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
        -ss STRING
            Searches for the string STRING in the ranges after filtering
        -s8 VALUE
            Searches for the value VALUE in the ranges after filtering
            VALUE should fit in 8 bytes.
        -s4 VALUE 
            Searches for the value VALUE in the ranges after filtering
            VALUE should fit in 4 bytes.
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
    """
    def __init__(self):
        super(PageTableDump, self).__init__("pt", gdb.COMMAND_USER)
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("-addr", nargs=1)
        self.parser.add_argument("-save", action="store_true")
        self.parser.add_argument("-list", action="store_true")
        self.parser.add_argument("-clear", action="store_true")
        self.parser.add_argument("-ss", nargs=1, type=lambda s: str(s))
        self.parser.add_argument("-s8", nargs=1, type=lambda s: int(s, 0))
        self.parser.add_argument("-s4", nargs=1, type=lambda s: int(s, 0))
        self.parser.add_argument("-range", nargs=2, type=lambda s: int(s, 0))
        self.parser.add_argument("-has", nargs=1, type=lambda s: int(s, 0))
        self.parser.add_argument("-filter", nargs="+")
        self.cache = dict()
        self.arch = None

    def print_cache(self):
        print("Cache:")
        for address in self.cache:
            print(f"\t{hex(address)}")
    
    def invoke(self, arg, from_tty):
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
        if args.ss:
            to_search = args.ss[0].encode("ascii")
        elif args.s8:
            to_search = args.s8[0].to_bytes(8, 'little')
        elif args.s4:
            to_search = args.s4[0].to_bytes(4, 'little')

        should_print = to_search == None
        page_ranges = None

        if self.arch == SupportedArch.aarch64:
            page_ranges = parse_and_print_aarch64_table(self.cache, args, should_print)
        elif self.arch == SupportedArch.x86_64:
            page_ranges = parse_and_print_x86_64_table(self.cache, args, should_print)

        if to_search and page_ranges:
            th = gdb.selected_inferior()
            for range in page_ranges:
                try:
                    data = th.read_memory(range.va, range.page_size).tobytes()
                    idx = 0
                    while True:
                        idx = data.find(to_search, idx)
                        if idx != -1:
                            print("Found " + hex(range.va + idx) + " in " + str(range))
                            idx = idx + 1
                        else:
                            break
                except gdb.MemoryError:
                    print(f"Fail: {hex(range.va)}")
                    pass

PageTableDump()
