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
            Supported filters:
            w: is writeable.
            x: is executable
            w|x: is writeable or executable
            ro: read-only
            u: user-space page
            s: supervisor page
            wb: write-back
            uc: uncacheable

            Additionally, you can invert some filters: _w, _x, _u, _s, _wb, _uc
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
        self.parser.add_argument("-filter", nargs="+")
        self.cache = dict()
        arch = gdb.execute("show architecture", to_string = True)
        if "aarch64" in arch:
            self.arch = SupportedArch.aarch64
        elif "x86-64" in arch:
            self.arch = SupportedArch.x86_64
        else:
            raise Exception(f"Unknown arch. Message: {arch}")

    def query(self, addr, query_from_cache = False):
        if query_from_cache == True and addr in self.cache:
            return self.cache[addr]

        pml4es = parse_pml4(addr)
        pdpes = parse_pml4es(pml4es)
        pdes, one_gig_pages = parse_pdpes(pdpes)
        ptes, two_mb_pages = parse_pdes(pdes)
        small_pages = []
        for pte in ptes:
            small_pages.append(create_page_from_pte(pte))
        page_ranges = optimize(one_gig_pages, two_mb_pages, small_pages, rwxs_semantically_similar)
        return page_ranges

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

        if self.arch == SupportedArch.aarch64:
            parse_and_print_aarch64_table(self.cache, None, args.save)
        elif self.arch == SupportedArch.x86_64:
            pt_addr = None
            if args.addr:
                pt_addr = int(args.addr[0], 16)
            else:
                pt_addr = int(gdb.parse_and_eval("$cr3").cast(gdb.lookup_type("long")))

            page_ranges = self.query(pt_addr, True)

            # Cache the page table if caching is set.
            # Caching happens before the filter is applied.
            if args.save:
                self.cache[pt_addr] = page_ranges

            if args.filter:
                filters = []
                for f in args.filter:
                    if f == "wx":
                        filters.append(lambda p: p.x and p.w)
                    elif f == "w":
                        filters.append(lambda p: p.w)
                    elif f == "_w":
                        filters.append(lambda p: not p.w)
                    elif f == "x":
                        filters.append(lambda p: p.x)
                    elif f == "_x":
                        filters.append(lambda p: not p.x)
                    elif f == "w|x" or f == "x|w":
                        filters.append(lambda p: p.x or p.w)
                    elif f == "u" or f == "_s":
                        filters.append(lambda p: not p.s)
                    elif f == "s" or f == "_u":
                        filters.append(lambda p: p.s)
                    elif f == "ro":
                        filters.append(lambda p: not p.x and not p.w)
                    elif f == "wb":
                        filters.append(lambda p: p.wb)
                    elif f == "_wb":
                        filters.append(lambda p: not p.wb)
                    elif f == "uc":
                        filters.append(lambda p: p.uc)
                    elif f == "_uc":
                        filters.append(lambda p: not p.uc)
                    else:
                        print(f"Unknown filter: {f}")
                        return

                def apply_filters(p):
                    res = True
                    for func in filters:
                        res = res and func(p)
                    return res
                page_ranges = list(filter(apply_filters, page_ranges))

            # Compute max len for these varying-len strings in order to print as tabular.
            max_va_len, max_page_size_len = compute_max_str_len(page_ranges)
            conf = PagePrintSettings(va_len = max_va_len, page_size_len = max_page_size_len)
            fmt = f"  {{:>{max_va_len}}} : {{:>{max_page_size_len}}}"
            varying_str = fmt.format("Address", "Length")
            print(bcolors.BLUE + varying_str + "   Kernel space         " + bcolors.ENDC)
            for page in page_ranges:
                prefix = ""
                if not page.s:
                    prefix = bcolors.CYAN + " " + bcolors.ENDC
                elif page.s:
                    prefix = bcolors.MAGENTA + " " + bcolors.ENDC

                if page.x and page.w:
                    print(prefix + bcolors.BLUE + " " + page_to_str(page, conf) + bcolors.ENDC)
                elif page.w and not page.x:
                    print(prefix + bcolors.GREEN + " " + page_to_str(page, conf) + bcolors.ENDC)
                elif page.x:
                    print(prefix + bcolors.RED + " " + page_to_str(page, conf) + bcolors.ENDC)
                else:
                    print(prefix + " " + page_to_str(page, conf))

PageTableDump()
