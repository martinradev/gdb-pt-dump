import gdb
import sys
import argparse
import os

# A hack to import the other files without placing the files in the modules directory.
dirname = os.path.dirname(__file__)
dirname = os.path.expanduser(dirname)
dirname = os.path.abspath(dirname)

sys.path.append(dirname)

from pt_common import *
from pt_x86_64_parse import *
from pt_aarch64_parse import *

class VMPhysMem():
    def __init__(self, pid):
        self.pid = pid
        self.file = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
        self.mem_size = os.fstat(self.file).st_size

    def __close__(self):
        if self.file:
            os.close(self.file)

    def read(self, phys_addr, len):
        res = gdb.execute(f"monitor gpa2hva {hex(phys_addr)}", to_string = True)
        try:
            hva = int(res.split(" ")[-1], 16)
        except:
            raise OSError(f"Physical address ({hex(phys_addr)}, +{hex(len)}) is not accessible")
        return os.pread(self.file, len, hva)

class PageTableDump(gdb.Command):
    """
    GDB pt-dump: command for inspecting VM page tables.
    Arguments:
        -addr HEX_ADDR
            The GPA of the page table. If not used, the script will use the architectural
            register (e.g. cr3).
        -filter FILTER [FILTER ...]
            Specify filters for the recorded pages.
            x86_64 Supported filters:
                w: is writeable.
                x: is executable
                w|x: is writeable or executable
                ro: read-only
                u: user-space page
                s: supervisor page
                wb: write-back
                uc: uncacheable

             aarch64 Supported filters:
                w: is writeable.
                x: is executable
                w|x: is writeable or executable
                ro: read-only
                u: user-space page
                s: supervisor page

        -range START_ADDR END_ADDR
            Will filter-out virtual memory ranges which start at a position in [START_ADDR, END_ADDR]
        -has ADDR
            Will filter-out virtual memory ranges which contain ADDR
        -before ADDR
            Will filter-out virtual memory ranges which start before ADDR
        -after ADDR
            Will filter-out virtual memory ranges which start after ADDR
        -ss "STRING"
            Searches for the string STRING in the ranges after filtering
        -sb BYTESTRING
            Searches for the byte-string BYTESTRING in the ranges after filtering
        -s8 VALUE
            Searches for the value VALUE in the ranges after filtering
            VALUE should fit in 8 bytes.
        -s4 VALUE 
            Searches for the value VALUE in the ranges after filtering
            VALUE should fit in 4 bytes.
        -align ALIGNMENT [OFFSET]
            When searching, it will print out addresses which are aligned to ALIGNMENT.
            If offset is provided, then the check would be performed as (ADDR - OFFSET) % ALIGNMENT.
            It can be useful when searching for content in a particular SLAB.
        -kaslr
            Print KASLR-relevant information like the image offsets and phys map base.
        -save
            Cache the recorded page table for that address after traversing the hierachy.
            This will yield speed-up when printing the page table again.
        -list
            List the cached page tables.
        -clear
            Clear all saved page tables.
        -info
            Print arch register information.
        -o FILE_NAME
            Store the output from the current command to a file with name FILE_NAME.
            This may be useful when the a lot of data is produced, e.g. full page table.
        -find_alias
            Experimental feature and currently slow. Searches for aliases ranges in virtual memory.
            Ranges are aliased if they point to the the same physical memory. This can be useful if one
            is searching for R/RX memory which is writeable through some other address.
            Another interesting option is to find alias for memory mapped in user space and kernel space.
            TODO: This feature will be reworked for usability and performance in the near future.

    Example usage:
        `pt -save -filter s w|x wb`
            Traverse the current page table and then save it. When returning the result,
            filter the pages to be marked as supervisor, be writeable or executable, and marked as
            write-back.
        `pt -filter w x`
            Traverse the current page table and print out mappings which are both writeable and
            executable.
        `pt -addr 0x4000`
            Traverse the page table at guest physical address 0x4000. Don't save it.
        `pt -save -kaslr`
            Traverse page tables, save them and print kaslr information.
        `pt -ss "Linux 4."`
            Search for the string Linux.
        `pt -sb da87374107`
            Search for the byte-string da87374107.
        `pt -s8 0xaabbccdd`
            Search for the 8-byte-long value 0xaabbccdd.
        `pt -has 0xffffffffaaf629f7`
            Print information about the mapping which covers the address 0xffffffffaaf629f7.
    """
    def __init__(self):
        super(PageTableDump, self).__init__("pt", gdb.COMMAND_USER)
        self.init = False

    def lazy_init(self):
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("-addr", nargs=1)
        self.parser.add_argument("-save", action="store_true")
        self.parser.add_argument("-list", action="store_true")
        self.parser.add_argument("-clear", action="store_true")
        self.parser.add_argument("-ss", nargs='+', type=lambda s: str(s))
        self.parser.add_argument("-sb", nargs='+', type=lambda s: b"".join([int(s[u:u+2], 16).to_bytes(1, 'little') for u in range(0, len(s), 2)]))
        self.parser.add_argument("-s8", nargs='+', type=lambda s: int(s, 0))
        self.parser.add_argument("-s4", nargs='+', type=lambda s: int(s, 0))
        self.parser.add_argument("-range", nargs=2, type=lambda s: int(s, 0))
        self.parser.add_argument("-after", nargs=1, type=lambda s: int(s, 0))
        self.parser.add_argument("-before", nargs=1, type=lambda s: int(s, 0))
        self.parser.add_argument("-has", nargs=1, type=lambda s: int(s, 0))
        self.parser.add_argument("-align", nargs='+', type=lambda s: int(s, 0))
        self.parser.add_argument("-kaslr", action="store_true")
        self.parser.add_argument("-info", action="store_true")
        self.parser.add_argument("-filter", nargs="+")
        self.parser.add_argument("-o", nargs=1)
        self.parser.add_argument("-find_alias", action="store_true")
        self.cache = dict()

        # Get quick access to physical memory.
        proc = os.popen("pgrep qemu-system")
        pid = int(proc.read().strip(), 10)
        proc.close()

        self.phys_mem = VMPhysMem(pid)

        self.init = True

        self.backend = None
        arch = gdb.execute("show architecture", to_string = True)
        if "aarch64" in arch:
            self.backend = PT_Aarch64_Backend(self.phys_mem)
        elif "x86-64" in arch:
            self.backend = PT_x86_64_Backend(self.phys_mem)
        else:
            raise Exception(f"Unknown arch. Message: {arch}")

    def print_cache(self):
        print("Cache:")
        for address in self.cache:
            print(f"\t{hex(address)}")

    def handle_command(self, args):
        if args.list:
            self.print_cache()
            return

        if args.clear:
            self.cache = dict()
            return

        to_search = None
        to_search_num = 0x100000000
        if args.ss:
            to_search = args.ss[0].encode("ascii")
            if len(args.ss) > 1:
                to_search_num = int(args.ss[1], 0)
        if args.sb:
            to_search = args.sb[0]
            if len(args.sb) > 1:
                to_search_num = int.from_bytes(args.sb[1], 'little')
        elif args.s8:
            to_search = args.s8[0].to_bytes(8, 'little')
            if len(args.s8) > 1:
                to_search_num = int(args.s8[1], 0)
        elif args.s4:
            to_search = args.s4[0].to_bytes(4, 'little')
            if len(args.s4) > 1:
                to_search_num = int(args.s4[1], 0)

        requires_page_table_parsing = True
        if args.info:
            requires_page_table_parsing = False

        if requires_page_table_parsing:
            page_ranges = self.backend.parse_tables(self.cache, args)
            page_ranges = list(filter(self.parse_filter_args(args), page_ranges))

        if to_search:
            if page_ranges:
                aligned_to = args.align[0] if args.align else 1
                aligned_offset = args.align[1] if args.align and len(args.align) == 2 else 0
                search_results = search_memory(self.phys_mem, page_ranges, to_search, to_search_num, aligned_to, aligned_offset)
                for entry in search_results:
                    print("Found at " + hex(entry[0]) + " in " + str(entry[1]))
            else:
                print("Not found")
        elif args.kaslr:
            self.backend.print_kaslr_information(page_ranges)
        elif args.info:
            self.backend.print_stats()
        elif args.find_alias:
            find_aliases(page_ranges)
        else:
            self.backend.print_table(page_ranges)

    def invoke(self, arg, from_tty):
        if self.init == False:
            self.lazy_init()

        args = self.parser.parse_args(gdb.string_to_argv(arg))

        saved_stdout = None
        if args.o:
            saved_stdout = sys.stdout
            sys.stdout = open(args.o[0], "w+")

        try:
            self.handle_command(args)
        except Exception as e:
            print(f"Exception: {str(e)}")
        finally:
            if saved_stdout:
                sys.stdout.close()
                sys.stdout = saved_stdout

    def parse_filter_args(self, args):
        filters = []
        if args.range:
            filters.append(lambda page: page.va >= args.range[0] and page.va <= args.range[1])

        if args.has:
            filters.append(lambda page: args.has[0] >= page.va and args.has[0] < page.va + page.page_size)

        if args.after:
            filters.append(lambda page: args.after[0] <= page.va)

        if args.before:
            filters.append(lambda page: args.before[0] > page.va)

        if args.filter:
            # First, we have to determine if user/superuser filter flag was set
            # This is necessary at least for aarch64 where the AP bits provide many possibilities.

            has_superuser_filter = False
            has_user_filter = False
            for f in args.filter:
                if f == "s":
                    has_superuser_filter = True
                if f == "u":
                    has_user_filter = True
            if not has_superuser_filter and not has_user_filter:
                has_superuser_filter = True
                has_user_filter = True
            for f in args.filter:
                if f == "w":
                    filters.append(self.backend.get_filter_is_writeable(has_superuser_filter, has_user_filter))
                elif f == "_w":
                    filters.append(self.backend.get_filter_is_not_writeable(has_superuser_filter, has_user_filter))
                elif f == "x":
                    filters.append(self.backend.get_filter_is_executable(has_superuser_filter, has_user_filter))
                elif f == "_x":
                    filters.append(self.backend.get_filter_is_not_executable(has_superuser_filter, has_user_filter))
                elif f == "w|x" or f == "x|w":
                    filters.append(self.backend.get_filter_is_writeable_or_executable(has_superuser_filter, has_user_filter))
                elif f == "u" or f == "_s":
                    filters.append(self.backend.get_filter_is_user_page(has_superuser_filter, has_user_filter))
                elif f == "s" or f == "_u":
                    filters.append(self.backend.get_filter_is_superuser_page(has_superuser_filter, has_user_filter))
                elif f == "ro":
                    filters.append(self.backend.get_filter_is_read_only_page(has_superuser_filter, has_user_filter))
                elif f in ["wb", "_wb", "uc", "_uc"]:
                    filters.append(self.backend.get_filter_architecture_specific(f, has_superuser_filter, has_user_filter))
                else:
                    print(f"Unknown filter: {f}")
                    return

        return create_compound_filter(filters)

PageTableDump()
