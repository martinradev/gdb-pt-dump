from pt.pt_x86_64_definitions import *
from pt.pt_x86_msr import *
from pt.pt_common import *
from pt.pt_constants import *
from pt.pt_arch_backend import PTArchBackend
from abc import ABC
from abc import abstractmethod

import math

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
        print(self.pt_cr0.check())
        print(self.pt_cr4.check())

    @abstractmethod
    def get_arch(self):
        raise NotImplementedError("")

    def walk(self, va):

        if self.has_paging_enabled() == False:
            raise Exception("Paging is not enabled")

        entry_size = self.get_entry_size()
        num_entries_per_page = int(4096 / entry_size)
        bits_per_level = int(math.log2(num_entries_per_page))

        pse = self.retrieve_pse()
        pse_ignore = self.get_arch() == "x86_64"

        pt_addr = self.machine.read_register("$cr3")

        pt_walk = PageTableWalkInfo(va)
        pt_walk.add_register_stage("CR3", pt_addr)

        top_va = None
        stages = None
        if self.is_long_mode_enabled():
            if self.has_level_5_paging_enabled():
                stages = ["PML5", "PML4", "PDP", "PD", "PT"]
                top_va_bit = 56
            else:
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
            entry_value = int.from_bytes(self.machine.read_physical_memory(entry_page_pa, entry_size), 'little')
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
        found_page = None

        for page in tmp:
            first_byte = self.machine.read_physical_memory(page.phys[0], 1)
            if first_byte[0] == 0x48:
                found_page = page
                break

        stdout_output = ""
        kaslr_addresses = []
        if found_page:
            stdout_output += "Found virtual image base:\n"
            stdout_output += "\tVirt: " + found_page.to_string(phys_verbose) + "\n"
            stdout_output += "\tPhys: " + hex(found_page.phys[0]) + "\n"
            kaslr_addresses.append(found_page.va)
            first_bytes = self.machine.read_physical_memory(page.phys[0], 32)
            page_ranges_subset = filter(lambda page: not page.x and page.s and page.va % PT_SIZE_2MIB == 0, table)
            search_res_iter = search_memory(self.machine, page_ranges_subset, first_bytes, 1, 1, 0)
            try:
                search_res = next(search_res_iter)
                stdout_output += "Found phys map base:\n"
                phys_map_virt_base = search_res[0] - found_page.phys[0]
                phys_map_range = next(range for range in table if range.va >= phys_map_virt_base and phys_map_virt_base < range.va + range.page_size)
                stdout_output += "\tVirt: " + hex(phys_map_virt_base) + " in " + phys_map_range.to_string(phys_verbose) + "\n"
                kaslr_addresses.append(phys_map_virt_base)
            except StopIteration:
                print("Phys map was not found")
        else:
            stdout_output = "Failed to find KASLR info"
        if should_print:
            print(stdout_output)
        return kaslr_addresses

    def retrieve_pse(self):
        return (self.machine.read_register("$cr4") >> 4) & 0x1 == 0x1

    def retrieve_pae(self):
        return (self.machine.read_register("$cr4") >> 5) & 0x1 == 0x1

    def has_paging_enabled(self):
        return (self.machine.read_register("$cr0") >> 31) & 0x1 == 0x1

    def has_level_5_paging_enabled(self):
        return (self.machine.read_register("$cr4") >> 12) & 0x1 == 0x1

    def parse_pml5(self, addr, force_traverse_all):
        entries = []
        entry_size = 8
        try:
            values = split_range_into_int_values(read_page(self.machine, addr), entry_size)
        except:
            return entries
        pml5_cache = {}
        for u, value in enumerate(values):
            if (value & 0x1) != 0: # Page must be present
                if force_traverse_all or value not in pml5_cache:
                    entry = PML5_Entry(value, u)
                    entries.append(entry)
                    pml5_cache[value] = entry
        return entries

    def parse_pml5es(self, pml5es, force_traverse_all, entry_size):
        entries = []
        for pml5e in pml5es:
            pdpe = self.parse_pml4(pml5e, force_traverse_all)
            entries.extend(pdpe)
        return entries

    def parse_pml4(self, pml5e, force_traverse_all):
        entries = []
        entry_size = 8
        try:
            values = split_range_into_int_values(read_page(self.machine, pml5e.pml4), entry_size)
        except:
            return entries
        pml4_cache = {}
        for u, value in enumerate(values):
            if (value & 0x1) != 0: # Page must be present
                if force_traverse_all or value not in pml4_cache:
                    entry = PML4_Entry(value, pml5e.virt_part, u)
                    entries.append(entry)
                    pml4_cache[value] = entry
        return entries

    def parse_pml4es(self, pml4es, force_traverse_all, entry_size):
        entries = []
        for pml4e in pml4es:
            pdpe = self.parse_pdp(pml4e, force_traverse_all, 4096, entry_size)
            entries.extend(pdpe)
        return entries

    def parse_pdp(self, pml4e, force_traverse_all, size, entry_size):
        entries = []
        try:
            values = split_range_into_int_values(self.machine.read_physical_memory(pml4e.pdp, size), entry_size)
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

    def parse_pdpes(self, pdpes, force_traverse_all, entry_size, pde_shift):
        entries = []
        pages = []
        for pdpe in pdpes:
            if pdpe.large_page == False:
                pdes = self.parse_pd(pdpe, force_traverse_all, entry_size, pde_shift)
                entries.extend(pdes)
            else:
                page = create_page_from_pdpe(pdpe)
                pages.append(page)
        return entries, pages

    def parse_pd(self, pdpe, force_traverse_all, entry_size, pde_shift):
        entries = []
        try:
            values = split_range_into_int_values(read_page(self.machine, pdpe.pd), entry_size)
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

    def parse_pdes(self, pdes, entry_size=8):
        entries = []
        pages = []
        for pde in pdes:
            if pde.big_page == False:
                ptes = self.parse_pt(pde, entry_size)
                entries.extend(ptes)
            else:
                page = create_page_from_pde(pde)
                pages.append(page)
        return entries, pages

    def parse_pt(self, pde, entry_size=8):
        entries = []
        try:
            values = split_range_into_int_values(read_page(self.machine, pde.pt), entry_size)
        except:
            return entries
        for u, value in enumerate(values):
            if (value & 0x1) != 0:
                entry = PT_Entry(value, pde.virt_part, u)
                entries.append(entry)
        return entries

class PT_x86_64_Backend(PT_x86_Common_Backend, PTArchBackend):

    def get_arch(self):
        return "x86_64"

    def __init__(self, machine):
        self.machine = machine
        self.init_registers()

    def init_registers(self):
        self.pt_cr0 = PT_CR0(self.machine)
        self.pt_cr4 = PT_CR4(self.machine)

    def is_long_mode_enabled(self):
        efer = self.machine.read_register("$efer")
        long_mode_enabled = bool((efer >> 8) & 0x1)
        return long_mode_enabled

    def get_entry_size(self):
        if self.is_long_mode_enabled():
            return 8
        else:
            pae = self.retrieve_pae()
            return 8 if pae else 4

    def get_pde_shift(self):
        if self.is_long_mode_enabled():
            return 21
        else:
            pse = self.retrieve_pse()
            pae = self.retrieve_pae()
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

    def parse_tables(self, cache, args):
        # Check that paging is enabled, otherwise no point to continue.
        if self.has_paging_enabled() == False:
            raise Exception("Paging is not enabled")

        # Check if long mode is enabled
        efer = self.machine.read_register("$efer")
        long_mode_enabled = bool((efer >> 8) & 0x1)

        requires_physical_contiguity = args.phys_verbose
        pt_addr = None
        if args.cr3:
            pt_addr = int(args.cr3[0], 16)
        else:
            pt_addr = self.machine.read_register("$cr3")
            # TODO: Check if these attribute bits in the cr3 need to be respected.
        pt_addr = pt_addr & (~0xfff)

        page_ranges = None

        if pt_addr in cache:
            page_ranges = cache[pt_addr]
        elif long_mode_enabled:
            pde_shift = self.get_pde_shift()
            entry_size = self.get_entry_size()
            pml4es = []
            if self.has_level_5_paging_enabled():
                pml5es = self.parse_pml5(pt_addr, args.force_traverse_all)
                pml4es = self.parse_pml5es(pml5es, args.force_traverse_all, entry_size)
            else:
                pml4es = self.parse_pml4(PML5_Entry(pt_addr, 0), args.force_traverse_all)

            pdpes = self.parse_pml4es(pml4es, args.force_traverse_all, entry_size)
            pdes, large_pages = self.parse_pdpes(pdpes, args.force_traverse_all, entry_size, pde_shift)
            ptes, big_pages = self.parse_pdes(pdes)
            small_pages = []
            for pte in ptes:
                small_pages.append(create_page_from_pte(pte))
            page_ranges = optimize(large_pages, big_pages, small_pages, rwxs_semantically_similar, requires_physical_contiguity)
        else:
            pae = self.retrieve_pae()
            pde_shift = self.get_pde_shift()
            entry_size = self.get_entry_size()

            pdpes = None
            if pae:
                dummy_pml4 = PML4_Entry(pt_addr, 0)
                num_entries = 4
                pdpes = parse_pdp(dummy_pml4, args.force_traverse_all, num_entries * entry_size, entry_size)
            else:
                pdpes = [PDP_Entry(pt_addr, 0, 0)]

            pdes, large_pages = self.parse_pdpes(pdpes, args.force_traverse_all, entry_size, pde_shift)
            ptes, big_pages = self.parse_pdes(pdes, entry_size)
            small_pages = []
            for pte in ptes:
                small_pages.append(create_page_from_pte(pte))
            page_ranges = optimize(large_pages, big_pages, small_pages, rwxs_semantically_similar, requires_physical_contiguity)

        # Cache the page table if caching is set.
        # Caching happens before the filter is applied.
        if args.save:
            cache[pt_addr] = page_ranges

        return page_ranges

