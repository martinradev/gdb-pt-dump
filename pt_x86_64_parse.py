from pt_x86_64_definitions import *
import pt_x86_msr as x86_msr
from pt_common import *
from pt_constants import *
from pt_arch_backend import PTArchBackend

def parse_pml4(phys_mem, addr, force_traverse_all=False):
    entries = []
    values = split_range_into_int_values(read_page(phys_mem, addr), 8)
    pml4_cache = {}
    for u, value in enumerate(values):
        if (value & 0x1) != 0: # Page must be present
            if force_traverse_all or value not in pml4_cache:
                entry = PML4_Entry(value, u)
                entries.append(entry)
                pml4_cache[value] = entry
    return entries

def parse_pml4es(phys_mem, pml4es, force_traverse_all=False):
    entries = []
    for pml4e in pml4es:
        pdpe = parse_pdp(phys_mem, pml4e, force_traverse_all)
        entries.extend(pdpe)
    return entries

def parse_pdp(phys_mem, pml4e, force_traverse_all, size = 4096):
    entries = []
    values = split_range_into_int_values(phys_mem.read(pml4e.pdp, size), 8)
    pdp_cache = {}
    for u, value in enumerate(values):
        if (value & 0x1) != 0:
            if force_traverse_all or value not in pdp_cache:
                entry = PDP_Entry(value, pml4e.virt_part, u)
                entries.append(entry)
                pdp_cache[value] = entry
    return entries

def parse_pdpes(phys_mem, pdpes, force_traverse_all=False):
    entries = []
    pages = []
    for pdpe in pdpes:
        if pdpe.one_gig == False:
            pdes = parse_pd(phys_mem, pdpe, force_traverse_all)
            entries.extend(pdes)
        else:
            page = create_page_from_pdpe(pdpe)
            pages.append(page)
    return entries, pages

def parse_pd(phys_mem, pdpe, force_traverse_all):
    entries = []
    values = split_range_into_int_values(read_page(phys_mem, pdpe.pd), 8)
    pd_cache = {}
    for u, value in enumerate(values):
        if (value & 0x1) != 0:
            if force_traverse_all or value not in pd_cache:
                entry = PD_Entry(value, pdpe.virt_part, u)
                entries.append(entry)
                pd_cache[value] = entry
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
    values = split_range_into_int_values(read_page(phys_mem, pde.pt), 8)
    for u, value in enumerate(values):
        if (value & 0x1) != 0:
            entry = PT_Entry(value, pde.virt_part, u)
            entries.append(entry)
    return entries

class PT_x86_Common_Backend():
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
        print(x86_msr.pt_cr0.check())
        print(x86_msr.pt_cr4.check())

    def print_kaslr_information(self, table, should_print=True):
        potential_base_filter = lambda p: p.x and p.s and p.phys[0] % PT_SIZE_2MIB == 0
        tmp = list(filter(potential_base_filter, table))
        th = gdb.selected_inferior()
        found_page = None

        for page in tmp:
            first_byte = th.read_memory(page.va, 1)
            if first_byte[0] == b'\x48':
                found_page = page
                break

        stdout_output = ""
        kaslr_addresses = []
        if found_page:
            stdout_output += "Found virtual image base:\n"
            stdout_output += "\tVirt: " + str(found_page) + "\n"
            stdout_output += "\tPhys: " + hex(found_page.phys[0]) + "\n"
            kaslr_addresses.append(found_page.va)
            first_bytes = th.read_memory(page.va, 32).tobytes()
            page_ranges_subset = filter(lambda page: not page.x and page.s and page.va % PT_SIZE_2MIB == 0, table)
            search_res_iter = search_memory(self.phys_mem, page_ranges_subset, first_bytes, 1, 1, 0)
            if search_res_iter == None:
                print("Phys map was not found")
            else:
                search_res = next(search_res_iter)
                stdout_output += "Found phys map base:\n"
                phys_map_virt_base = search_res[0] - found_page.phys[0]
                stdout_output += "\tVirt: " + hex(phys_map_virt_base) + " in " + str(search_res[1]) + "\n"
                kaslr_addresses.append(phys_map_virt_base)
        else:
            stdout_output = "Failed to find KASLR info"
        if should_print:
            print(stdout_output)
        return kaslr_addresses


class PT_x86_64_Backend(PT_x86_Common_Backend, PTArchBackend):

    def __init__(self, phys_mem):
        self.phys_mem = phys_mem

    def parse_tables(self, cache, args):
        pt_addr = None
        if args.addr:
            pt_addr = int(args.addr[0], 16)
        else:
            pt_addr = int(gdb.parse_and_eval("$cr3").cast(gdb.lookup_type("long")))
            # TODO: Check if these attribute bits in the cr3 need to be respected.
            pt_addr = pt_addr & (~0xfff)

        page_ranges = None
        if pt_addr in cache:
            page_ranges = cache[pt_addr]
        else:
            pml4es = parse_pml4(self.phys_mem, pt_addr, args.force_traverse_all)
            pdpes = parse_pml4es(self.phys_mem, pml4es, args.force_traverse_all)
            pdes, one_gig_pages = parse_pdpes(self.phys_mem, pdpes, args.force_traverse_all)
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

class PT_x86_32_Backend(PT_x86_Common_Backend, PTArchBackend):

    def __init__(self, phys_mem):
        uses_pae = ((int(gdb.parse_and_eval("$cr4").cast(gdb.lookup_type("int"))) >> 5) & 0x1) == 0x1
        if not uses_pae:
            raise Exception("Current implementation only supports i386 with PAE")
        self.phys_mem = phys_mem
        return None

    def parse_tables(self, cache, args):
        pt_addr = None
        if args.addr:
            pt_addr = int(args.addr[0], 16)
        else:
            pt_addr = int(gdb.parse_and_eval("$cr3").cast(gdb.lookup_type("int")))
            # TODO: Check if these attribute bits in the cr3 need to be respected.
            pt_addr = pt_addr & (~0xfff)

        page_ranges = None
        if pt_addr in cache:
            page_ranges = cache[pt_addr]
        else:
            dummy_pml4 = PML4_Entry(pt_addr, 0)
            pdpes = parse_pdp(self.phys_mem, dummy_pml4, args.force_traverse_all, 4 * 8)
            pdes, one_gig_pages = parse_pdpes(self.phys_mem, pdpes, args.force_traverse_all)
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

