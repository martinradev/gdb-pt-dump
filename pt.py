import gdb
import sys
import argparse
import os

# A hack to import the other files without placing the files in the modules directory.
dirname = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(1, dirname)
from pt_common import *
from pt_x86_64_definitions import *
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
            raise OSError("Physical address is not accessible")
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
        -ss STRING
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
        `pt -ss Linux`
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
        self.parser.add_argument("-filter", nargs="+")
        self.cache = dict()
        self.arch = None

        # Get quick access to physical memory.
        proc = os.popen("pgrep qemu-system")
        pid = int(proc.read().strip(), 10)
        proc.close()

        self.phys_mem = VMPhysMem(pid)

        self.init = True

    def print_cache(self):
        print("Cache:")
        for address in self.cache:
            print(f"\t{hex(address)}")

    def invoke(self, arg, from_tty):
        if self.init == False:
            self.lazy_init()

        args = self.parser.parse_args(arg.split())

        if args.list:
            self.print_cache()
            return

        if args.clear:
            self.cache = dict()
            return

        if self.arch == None:
            arch = gdb.execute("show architecture", to_string = True)
            if "aarch64" in arch:
                self.arch = SupportedArch.aarch64
            elif "x86-64" in arch:
                self.arch = SupportedArch.x86_64
            else:
                raise Exception(f"Unknown arch. Message: {arch}")

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

        should_print = to_search == None and not args.kaslr
        page_ranges = None

        if self.arch == SupportedArch.aarch64:
            page_ranges = parse_and_print_aarch64_table(self.cache, self.phys_mem, args, should_print)
        elif self.arch == SupportedArch.x86_64:
            page_ranges = parse_and_print_x86_64_table(self.cache, self.phys_mem, args, should_print)

        if to_search and page_ranges:
            aligned_to = args.align[0] if args.align else 1
            aligned_offset = args.align[1] if args.align and len(args.align) == 2 else 0
            search_results = search_memory(self.phys_mem, page_ranges, to_search, to_search_num, aligned_to, aligned_offset)
            for entry in search_results:
                print("Found " + hex(entry[0]) + " in " + str(entry[1]))

PageTableDump()
