from pt_x86_64_definitions import *
from pt_common import *
from pt_arch_backend import PTArchBackend

def parse_pml4(phys_mem, addr):
    entries = []
    values = read_page(phys_mem, addr)
    for u, value in enumerate(values):
        if (value & 0x1) != 0: # Page must be present
            entry = PML4_Entry(value, u)
            entries.append(entry)
    return entries

def parse_pml4es(phys_mem, pml4es):
    entries = []
    for pml4e in pml4es:
        pdpe = parse_pdp(phys_mem, pml4e)
        entries.extend(pdpe)
    return entries

def parse_pdp(phys_mem, pml4e):
    entries = []
    values = read_page(phys_mem, pml4e.pdp)
    for u, value in enumerate(values):
        if (value & 0x1) != 0:
            entry = PDP_Entry(value, pml4e.virt_part, u)
            entries.append(entry)
    return entries

def parse_pdpes(phys_mem, pdpes):
    entries = []
    pages = []
    for pdpe in pdpes:
        if pdpe.one_gig == False:
            pdes = parse_pd(phys_mem, pdpe)
            entries.extend(pdes)
        else:
            page = create_page_from_pdpe(pdpe)
            one_gig_pages.append(page)
    return entries, pages

def parse_pd(phys_mem, pdpe):
    entries = []
    values = read_page(phys_mem, pdpe.pd)
    for u, value in enumerate(values):
        if (value & 0x1) != 0:
            entry = PD_Entry(value, pdpe.virt_part, u)
            entries.append(entry)
    return entries

def parse_pdes(phys_mem, pdes):
    entries = []
    pages = []
    for pde in pdes:
        if pde.two_mb == False:
            ptes = parse_pt(phys_mem, pde)
            entries.extend(ptes)
        else:
            page = create_page_from_pde(pde)
            pages.append(page)
    return entries, pages

def parse_pt(phys_mem, pde):
    entries = []
    values = read_page(phys_mem, pde.pt)
    for u, value in enumerate(values):
        if (value & 0x1) != 0:
            entry = PT_Entry(value, pde.virt_part, u)
            entries.append(entry)
    return entries

class PT_x86_64_Backend(PTArchBackend):

    def __init__(self, phys_mem):
        self.phys_mem = phys_mem

    def get_filter_is_writeable(self, has_superuser_filter, has_user_filter):
        return lambda p: p.w

    def get_filter_is_not_writeable(self, has_superuser_filter, has_user_filter):
        return lambda p: not p.w

    def get_filter_is_executable(self, has_superuser_filter, has_user_filter):
        return lambda p: p.x

    def get_filter_is_not_executable(self, has_superuser_filter, has_user_filter):
        return lambda p: not p.x

    def get_filter_is_writeable_or_executable(self, has_superuser_filter, has_user_filter):
        return lambda p: p.x or p.w

    def get_filter_is_user_page(self, has_superuser_filter, has_user_filter):
        return lambda p: not p.s

    def get_filter_is_superuser_page(self, has_superuser_filter, has_user_filter):
        return lambda p: p.s

    def get_filter_is_read_only_page(self, has_superuser_filter, has_user_filter):
        return lambda p: not p.x and not p.w

    def get_filter_architecture_specific(self, filter_name, has_superuser_filter, has_user_filter):
        if filter_name == "wb":
            return lambda p: p.wb
        elif filter_name == "_wb":
            return lambda p: not p.wb
        elif filter_name == "uc":
            return lambda p: p.uc
        elif filter_name == "_uc":
            return lambda p: not p.uc
        else:
            return None

    def parse_tables(self, cache, args):
        pt_addr = None
        if args.addr:
            pt_addr = int(args.addr[0], 16)
        else:
            pt_addr = int(gdb.parse_and_eval("$cr3").cast(gdb.lookup_type("long")))

        page_ranges = None
        if pt_addr in cache:
            page_ranges = cache[pt_addr]
        else:
            pml4es = parse_pml4(self.phys_mem, pt_addr)
            pdpes = parse_pml4es(self.phys_mem, pml4es)
            pdes, one_gig_pages = parse_pdpes(self.phys_mem, pdpes)
            ptes, two_mb_pages = parse_pdes(self.phys_mem, pdes)
            small_pages = []
            for pte in ptes:
                small_pages.append(create_page_from_pte(pte))
            page_ranges = optimize(one_gig_pages, two_mb_pages, small_pages, rwxs_semantically_similar)

        # Cache the page table if caching is set.
        # Caching happens before the filter is applied.
        if args.save:
            cache[pt_addr] = page_ranges

        return page_ranges

    def print_table(self, table):
        # Compute max len for these varying-len strings in order to print as tabular.
        max_va_len, max_page_size_len = compute_max_str_len(table)
        conf = PagePrintSettings(va_len = max_va_len, page_size_len = max_page_size_len)
        fmt = f"  {{:>{max_va_len}}} : {{:>{max_page_size_len}}}"
        varying_str = fmt.format("Address", "Length")
        print(bcolors.BLUE + varying_str + "   Permissions          " + bcolors.ENDC)
        for page in table:
            print(page_to_str(page, conf))

    def print_stats(self):
        print("Not implemented")

    def print_kaslr_information(self, table):
        potential_base_filter = lambda p: p.x and p.s and p.phys[0] % (2 * 1024 * 1024) == 0
        tmp = list(filter(potential_base_filter, table))
        th = gdb.selected_inferior()
        found_page = None

        for page in tmp:
            first_byte = th.read_memory(page.va, 1)
            if first_byte[0] == b'\x48':
                found_page = page
                break

        if found_page:
            print("Found virtual image base:")
            print("\tVirt: " + str(found_page))
            print("\tPhys: " + hex(found_page.phys[0]))
            first_bytes = th.read_memory(page.va, 32).tobytes()
            page_ranges_subset = filter(lambda page: not page.x and page.s and page.va % 2 * 1024 * 1024 == 0, table)
            search_res_iter = search_memory(self.phys_mem, page_ranges_subset, first_bytes, 1, 1, 0)
            if search_res_iter == None:
                print("Phys map was not found")
            else:
                search_res = next(search_res_iter)
                print("Found phys map base:")
                print("\tVirt: " + hex(search_res[0] - found_page.phys[0]) + " in " + str(search_res[1]))
        else:
            print("Failed to find KASLR info")

