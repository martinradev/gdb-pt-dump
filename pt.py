import gdb
import sys
import copy
import argparse
import os

# A hack to import the other files without placing the files in the modules directory.
dirname = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(1, dirname)
from pt_common import *
from pt_x86_64_definitions import *
from pt_x86_64_parse import *

def rwxs_semantically_similar(p1: Page, p2: Page) -> bool:
    return p1.w == p2.w and p1.x == p2.x and p1.s == p2.s and p1.wb == p2.wb and p1.uc == p2.uc

def merge_cont_pages(pages):
    if len(pages) == 1:
        return pages

    # Here I am just going to abuse the Page structure to contain the range
    merged_pages = []
    cur_page = copy.copy(pages[0])
    for page in pages[1:]:
        if cur_page.va + cur_page.page_size == page.va and rwxs_semantically_similar(cur_page, page):
            cur_page.page_size = cur_page.page_size + page.page_size
        else:
            merged_pages.append(cur_page)
            cur_page = copy.copy(page)
    merged_pages.append(cur_page)
    return merged_pages 

def optimize(gig_pages, mb_pages, kb_pages):
    #opt_pages = merge_cont_pages(sorted(kb_pages, key = lambda p: p.va))
    # Let's not sort them since the kernel likely does the sensible thing
    # But still let's try to merge before sorting. This will often reduce the size by a lot.
    opt_kb_pages = merge_cont_pages(kb_pages)
    pages = sorted(gig_pages + mb_pages + opt_kb_pages, key = lambda p: p.va)
    opt = merge_cont_pages(pages)
    return opt

class PageTableDump(gdb.Command):
    def __init__(self):
        super(PageTableDump, self).__init__("pt", gdb.COMMAND_DATA)
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("-addr", nargs=1)
        self.parser.add_argument("-save", action="store_true")
        self.parser.add_argument("-list", action="store_true")
        self.parser.add_argument("-clear", action="store_true")
        self.parser.add_argument("-filter", nargs="+")
        #self.parser.add_argument("-filter_range", nargs=2, tpye=int)
        self.cache = dict()

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
        page_ranges = optimize(one_gig_pages, two_mb_pages, small_pages)
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
            page_ranges = filter(apply_filters, page_ranges)

        for page in page_ranges:
            prefix = ""
            if not page.s:
                prefix = bcolors.CYAN + " " + bcolors.ENDC
            elif page.s:
                prefix = bcolors.MAGENTA + " " + bcolors.ENDC
            if page.x and page.w:
                print(prefix + bcolors.BLUE + " " + str(page) + bcolors.ENDC)
            elif page.w and not page.x:
                print(prefix + bcolors.GREEN + " " + str(page) + bcolors.ENDC)
            elif page.x:
                print(prefix + bcolors.RED + " " + str(page) + bcolors.ENDC)
            else:
                print(prefix + " " + str(page))

PageTableDump()
