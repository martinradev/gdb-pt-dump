from pt.pt_x86_64_definitions import *
import pt.pt_x86_msr as x86_msr
from pt.pt_common import *
from pt.pt_constants import *
from pt.pt_arch_backend import PTArchBackend
from abc import ABC
from abc import abstractmethod

import math

def retrieve_pse():
    uses_pse = ((int(gdb.parse_and_eval("$cr4").cast(gdb.lookup_type("unsigned long"))) >> 4) & 0x1) == 0x1
    return uses_pse

def retrieve_pae():
    uses_pae = ((int(gdb.parse_and_eval("$cr4").cast(gdb.lookup_type("unsigned long"))) >> 5) & 0x1) == 0x1
    return uses_pae

def has_paging_enabled():
    uses_paging = ((int(gdb.parse_and_eval("$cr0").cast(gdb.lookup_type("unsigned long"))) >> 31) & 0x1) == 0x1
    return uses_paging

def parse_pml4(phys_mem, addr, force_traverse_all):
    entries = []
    entry_size = 8
    try:
        values = split_range_into_int_values(read_page(phys_mem, addr), entry_size)
    except:
        return entries
    pml4_cache = {}
    for u, value in enumerate(values):
        if (value & 0x1) != 0: # Page must be present
            if force_traverse_all or value not in pml4_cache:
                entry = PML4_Entry(value, u)
                entries.append(entry)
                pml4_cache[value] = entry
    return entries

def parse_pml4es(phys_mem, pml4es, force_traverse_all, entry_size):
    entries = []
    for pml4e in pml4es:
        pdpe = parse_pdp(phys_mem, pml4e, force_traverse_all, 4096, entry_size)
        entries.extend(pdpe)
    return entries

def parse_pdp(phys_mem, pml4e, force_traverse_all, size, entry_size):
    entries = []
    try:
        values = split_range_into_int_values(phys_mem.read(pml4e.pdp, size), entry_size)
    except:
        return entries
    pdp_cache = {}
    for u, value in enumerate(values):
        if (value & 0x1) != 0:
            if force_traverse_all or value not in pdp_cache:
                entry = PDP_Entry(value, pml4e.virt_part, u)
                entries.append(entry)
                pdp_cache[value] = entry
    return entries

def parse_pdpes(phys_mem, pdpes, force_traverse_all, entry_size, pde_shift):
    entries = []
    pages = []
    for pdpe in pdpes:
        if pdpe.large_page == False:
            pdes = parse_pd(phys_mem, pdpe, force_traverse_all, entry_size, pde_shift)
            entries.extend(pdes)
        else:
            page = create_page_from_pdpe(pdpe)
            pages.append(page)
    return entries, pages

def parse_pd(phys_mem, pdpe, force_traverse_all, entry_size, pde_shift):
    entries = []
    try:
        values = split_range_into_int_values(read_page(phys_mem, pdpe.pd), entry_size)
    except:
        return entries
    pd_cache = {}
    for u, value in enumerate(values):
        if (value & 0x1) != 0:
            if force_traverse_all or value not in pd_cache:
                entry = PD_Entry(value, pdpe.virt_part, u, pde_shift)
                entries.append(entry)
                pd_cache[value] = entry
    return entries

def parse_pdes(phys_mem, pdes, entry_size=8):
    entries = []
    pages = []
    for pde in pdes:
        if pde.big_page == False:
            ptes = parse_pt(phys_mem, pde, entry_size)
            entries.extend(ptes)
        else:
            page = create_page_from_pde(pde)
            pages.append(page)
    return entries, pages

def parse_pt(phys_mem, pde, entry_size=8):
    entries = []
    try:
        values = split_range_into_int_values(read_page(phys_mem, pde.pt), entry_size)
    except:
        return entries
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

    def print_table(self, table, phys_verbose):
        varying_str = None
        if phys_verbose:
            fmt = f"  {{:>{PrintConfig.va_len}}} : {{:>{PrintConfig.page_size_len}}} : {{:>{PrintConfig.phys_len}}} |"
            varying_str = fmt.format("Address", "Length", "Phys")
        else:
            fmt = f"  {{:>{PrintConfig.va_len}}} : {{:>{PrintConfig.page_size_len}}} |"
            varying_str = fmt.format("Address", "Length")
        print(bcolors.BLUE + varying_str + " Permissions          " + bcolors.ENDC)
        for page in table:
            print(page.to_string(phys_verbose))

    def print_stats(self):
        print(x86_msr.pt_cr0.check())
        print(x86_msr.pt_cr4.check())

    @abstractmethod
    def get_arch(self):
        raise NotImplementedError("")

    def walk(self, va):

        if has_paging_enabled() == False:
            raise Exception("Paging is not enabled")

        entry_size = self.get_entry_size()
        num_entries_per_page = int(4096 / entry_size)
        bits_per_level = int(math.log2(num_entries_per_page))

        pse = retrieve_pse()
        pse_ignore = self.get_arch() == "x86_64"

        pt_addr = int(gdb.parse_and_eval("$cr3").cast(gdb.lookup_type("unsigned long")))

        pt_walk = PageTableWalkInfo(va)
        pt_walk.add_register_stage("CR3", pt_addr)

        top_va = None
        stages = None
        if self.get_arch() == "x86_64":
            stages = ["PML4", "PDP", "PD", "PT"]
            top_va_bit = 47
        else:
            stages = ["PD", "PT"]
            top_va_bit = 31

        cur_phys_addr = pt_addr
        for (stage_index, stage_str) in enumerate(stages):
            page_pa = cur_phys_addr & ~0xFFF
            entry_index = extract(va, top_va_bit - bits_per_level + 1, top_va_bit)
            entry_page_pa = page_pa + entry_index * entry_size
            entry_value = int.from_bytes(self.phys_mem.read(entry_page_pa, entry_size), 'little')
            entry_value_pa_no_meta = extract_no_shift(entry_value, 12, 47)
            meta_bits = extract_no_shift(entry_value, 0, 11)

            pt_walk.add_stage(stage_str, entry_index, entry_value_pa_no_meta, meta_bits)

            if not is_present(entry_value):
                pt_walk.set_faulted()
                break

            if is_big_page(entry_value) and (pse or pse_ignore):
                break

            cur_phys_addr = entry_value
            top_va_bit = top_va_bit - bits_per_level

        return pt_walk

    def print_kaslr_information(self, table, should_print=True, phys_verbose=False):
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
            stdout_output += "\tVirt: " + found_page.to_string(phys_verbose) + "\n"
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
                phys_map_range = next(range for range in table if range.va >= phys_map_virt_base and phys_map_virt_base < range.va + range.page_size)
                stdout_output += "\tVirt: " + hex(phys_map_virt_base) + " in " + phys_map_range.to_string(phys_verbose) + "\n"
                kaslr_addresses.append(phys_map_virt_base)
        else:
            stdout_output = "Failed to find KASLR info"
        if should_print:
            print(stdout_output)
        return kaslr_addresses


class PT_x86_64_Backend(PT_x86_Common_Backend, PTArchBackend):

    def get_arch(self):
        return "x86_64"

    def get_pde_shift(self, pse, pae):
        # Size is always 2MiB
        return 21

    def __init__(self, phys_mem):
        self.phys_mem = phys_mem

    def get_entry_size(self):
        return 8

    def parse_tables(self, cache, args):
        # Check that paging is enabled, otherwise no point to continue.
        if has_paging_enabled() == False:
            raise Exception("Paging is not enabled")

        requires_physical_contiguity = args.phys_verbose
        pt_addr = None
        if args.cr3:
            pt_addr = int(args.cr3[0], 16)
        else:
            pt_addr = int(gdb.parse_and_eval("$cr3").cast(gdb.lookup_type("unsigned long")))
            # TODO: Check if these attribute bits in the cr3 need to be respected.
        pt_addr = pt_addr & (~0xfff)

        pde_shift = self.get_pde_shift(True, True)

        page_ranges = None
        if pt_addr in cache:
            page_ranges = cache[pt_addr]
        else:
            entry_size = self.get_entry_size()
            pml4es = parse_pml4(self.phys_mem, pt_addr, args.force_traverse_all)
            pdpes = parse_pml4es(self.phys_mem, pml4es, args.force_traverse_all, entry_size)
            pdes, large_pages = parse_pdpes(self.phys_mem, pdpes, args.force_traverse_all, entry_size, pde_shift)
            ptes, big_pages = parse_pdes(self.phys_mem, pdes)
            small_pages = []
            for pte in ptes:
                small_pages.append(create_page_from_pte(pte))
            page_ranges = optimize(large_pages, big_pages, small_pages, rwxs_semantically_similar, requires_physical_contiguity)

        # Cache the page table if caching is set.
        # Caching happens before the filter is applied.
        if args.save:
            cache[pt_addr] = page_ranges

        return page_ranges

class PT_x86_32_Backend(PT_x86_Common_Backend, PTArchBackend):

    def __init__(self, phys_mem):
        self.phys_mem = phys_mem
        return None

    def get_arch(self):
        return "x86_32"

    def get_pde_shift(self, pse, pae):
        if pse and pae:
            # PSE is ignored when PAE is available.
            return 21
        elif not pse and pae:
            # Only PAE. Page size is 2MiB
            return 21
        elif pse and not pae:
            # Only PSE. Page size is 4MiB.
            return 22
        elif not pse and not pae:
            # Default.
            # Manual suggests this shouldn't be possible because the page extension bit in the pde would be ignored.
            # Yet, QEMU doesn't respect this rule and here we are.
            return 21
        else:
            raise Exception("Unreachable")

    def get_entry_size(self):
        return 8 if pae else 4

    def parse_tables(self, cache, args):
        # Check that paging is enabled, otherwise no point to continue.
        if has_paging_enabled() == False:
            raise Exception("Paging is not enabled")

        pt_addr = None
        if args.cr3:
            pt_addr = int(args.cr3[0], 16)
        else:
            pt_addr = int(gdb.parse_and_eval("$cr3").cast(gdb.lookup_type("unsigned long")))
            # TODO: Check if these attribute bits in the cr3 need to be respected.
            pt_addr = pt_addr & (~0xfff)

        pse = retrieve_pse()
        pae = retrieve_pae()
        pde_shift = self.get_pde_shift(pse=pse, pae=pae)

        page_ranges = None
        if pt_addr in cache:
            page_ranges = cache[pt_addr]
        else:
            pdpes = None
            entry_size = self.get_entry_size()
            if pae:
                dummy_pml4 = PML4_Entry(pt_addr, 0)
                num_entries = 4
                pdpes = parse_pdp(self.phys_mem, dummy_pml4, args.force_traverse_all, num_entries * entry_size, entry_size)
            else:
                pdpes = [PDP_Entry(pt_addr, 0, 0)]

            pdes, large_pages = parse_pdpes(self.phys_mem, pdpes, args.force_traverse_all, entry_size, pde_shift)
            ptes, big_pages = parse_pdes(self.phys_mem, pdes, entry_size)
            small_pages = []
            for pte in ptes:
                small_pages.append(create_page_from_pte(pte))
            page_ranges = optimize(large_pages, big_pages, small_pages, rwxs_semantically_similar)

        # Cache the page table if caching is set.
        # Caching happens before the filter is applied.
        if args.save:
            cache[pt_addr] = page_ranges

        return page_ranges

