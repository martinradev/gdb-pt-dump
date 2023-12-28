import sys
import argparse
import os
import subprocess
import tempfile
import string
import random
import traceback

from pt.pt_common import *

class PageTableDump():

    def __init__(self, machine_backend, arch_backend):
        self.machine_backend = machine_backend
        self.arch_backend = arch_backend

        self.parser = argparse.ArgumentParser()
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
        self.parser.add_argument("-kaslr_leaks", action="store_true")
        self.parser.add_argument("-info", action="store_true")
        self.parser.add_argument("-walk", nargs=1, type=lambda s: int(s, 0))
        self.parser.add_argument("-phys_verbose", action="store_true")
        self.parser.add_argument("-filter", nargs="+")
        self.parser.add_argument("-o", nargs=1)
        self.parser.add_argument("-find_alias", action="store_true")
        self.parser.add_argument("-force_traverse_all", action="store_true")

        if self.arch_backend.get_arch() == "x86_64" or self.arch_backend.get_arch() == "x86_32":
            self.parser.add_argument("-cr3", nargs=1)

        if self.arch_backend.get_arch() == "aarch64":
            self.parser.add_argument("-ttbr0_el1", nargs=1)
            self.parser.add_argument("-ttbr1_el1", nargs=1)

        if self.arch_backend.get_arch() == "riscv64":
            self.parser.add_argument("-satp", nargs=1)

        self.cache = dict()

    def print_cache(self):
        print("Cache:")
        for address in self.cache:
            print(f"\t{hex(address)}")

    def handle_command_wrapper(self, argv):
        args = None
        try:
            args = self.parser.parse_args(argv)
        except:
            return None

        saved_stdout = None
        if args.o:
            saved_stdout = sys.stdout
            sys.stdout = open(args.o[0], "w+")

        try:
            self.handle_command(args)
        except Exception as e:
            print(f"Exception: {str(e)}")
            print(f"Stack trace:\n{traceback.format_exc()}")
        finally:
            if saved_stdout:
                sys.stdout.close()
                sys.stdout = saved_stdout

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

        if args.walk:
            requires_page_table_parsing = False

        page_ranges = None
        page_ranges_filtered = None
        if requires_page_table_parsing:
            page_ranges = self.arch_backend.parse_tables(self.cache, args)
            compound_filter, (min_address, max_address) = self.parse_filter_args(args)
            page_ranges_filtered = list(filter(compound_filter, page_ranges))
            # Perform cut-off of start and end.
            # Only the first and last page entry need to be potentially modified because they were already filtered
            if len(page_ranges_filtered) >= 1:
                if min_address:
                    page_ranges_filtered[0].cut_after(min_address)
                if max_address:
                    page_ranges_filtered[-1].cut_before(max_address)


        if to_search:
            if page_ranges_filtered:
                aligned_to = args.align[0] if args.align else 1
                aligned_offset = args.align[1] if args.align and len(args.align) == 2 else 0
                search_results = search_memory(self.machine_backend, page_ranges_filtered, to_search, to_search_num, aligned_to, aligned_offset)
                for entry in search_results:
                    print("Found at " + hex(entry[0]) + " in " + entry[1].to_string(args.phys_verbose))
            else:
                print("Not found")
        elif args.walk:
            walk = self.arch_backend.walk(args.walk[0])
            print(walk)
        elif args.kaslr:
            self.arch_backend.print_kaslr_information(page_ranges)
        elif args.kaslr_leaks:
            def inner_find_leaks(x, off):
                top = (x >> (off * 8)).to_bytes(8 - off, 'little')
                num_entries = 10
                entries = search_memory(self.machine_backend, page_ranges_filtered, top, num_entries, 1, 0)
                if entries:
                    print(f"Search for {hex(x)}")
                    for entry in entries:
                        print("Found at " + hex(entry[0] - off) + " in " + entry[1].to_string(args.phys_verbose))
            leaks = self.arch_backend.print_kaslr_information(page_ranges, False)
            if leaks:
                inner_find_leaks(leaks[0], 3)
                inner_find_leaks(leaks[1], 5)
        elif args.info:
            self.arch_backend.print_stats()
        elif args.find_alias:
            find_aliases(page_ranges, args.phys_verbose)
        else:
            self.arch_backend.print_table(page_ranges_filtered, phys_verbose=args.phys_verbose) 

    def parse_filter_args(self, args):
        filters = []
        min_address = 0
        max_address = 2 ** 64
        if args.range:
            filters.append(lambda page: page.va >= args.range[0] and page.va <= args.range[1])
            min_address = max(args.range[0], min_address)
            max_address = min(args.range[1], max_address)

        if args.has:
            filters.append(lambda page: args.has[0] >= page.va and args.has[0] < page.va + page.page_size)

        if args.after:
            filters.append(lambda page: args.after[0] < page.va + page.page_size)
            min_address = max(args.after[0], min_address)
        else:
            min_address = None

        if args.before:
            filters.append(lambda page: args.before[0] > page.va)
            max_address = min(args.before[0], max_address)
        else:
            max_address = None

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
                    filters.append(self.arch_backend.get_filter_is_writeable(has_superuser_filter, has_user_filter))
                elif f == "_w":
                    filters.append(self.arch_backend.get_filter_is_not_writeable(has_superuser_filter, has_user_filter))
                elif f == "x":
                    filters.append(self.arch_backend.get_filter_is_executable(has_superuser_filter, has_user_filter))
                elif f == "_x":
                    filters.append(self.arch_backend.get_filter_is_not_executable(has_superuser_filter, has_user_filter))
                elif f == "w|x" or f == "x|w":
                    filters.append(self.arch_backend.get_filter_is_writeable_or_executable(has_superuser_filter, has_user_filter))
                elif f == "u":
                    filters.append(self.arch_backend.get_filter_is_user_page(has_superuser_filter, has_user_filter))
                elif f == "s":
                    filters.append(self.arch_backend.get_filter_is_superuser_page(has_superuser_filter, has_user_filter))
                elif f == "ro":
                    filters.append(self.arch_backend.get_filter_is_read_only_page(has_superuser_filter, has_user_filter))
                elif f in ["wb", "_wb", "uc", "_uc"]:
                    filters.append(self.arch_backend.get_filter_architecture_specific(f, has_superuser_filter, has_user_filter))
                else:
                    print(f"Unknown filter: {f}")
                    return

        return (create_compound_filter(filters), (min_address, max_address))

