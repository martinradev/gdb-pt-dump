from pt.pt_common import *
from pt.pt_aarch64_definitions import *
from pt.pt_arch_backend import PTArchBackend
from pt.pt_constants import *
from pt.machine import *

import math

PT_AARCH64_4KB_PAGE  = PT_SIZE_4K
PT_AARCH64_16KB_PAGE = PT_SIZE_16K
PT_AARCH64_64KB_PAGE = PT_SIZE_64K

def is_user_readable(block):
    return block.permissions == 0b11 or block.permissions == 0b01

def is_kernel_readable(block):
    return True

def is_user_writeable(block):
    return block.permissions == 0b01

def is_kernel_writeable(block):
    return block.permissions == 0b01 or block.permissions == 0b00

def is_user_executable(block):
    return (not block.xn)

def is_kernel_executable(block):
    return not block.pxn

class Aarch64_Block(CommonPage):
    def __init__(self, va, phys, size, xn, pxn, permissions):
        self.va = va
        self.page_size = size
        self.xn = xn
        self.pxn = pxn
        self.permissions = permissions
        self.phys = [phys]
        self.sizes = [size]

    def to_string(self, phys_verbose):
        varying_str = None
        if phys_verbose:
            fmt = f"{{:>{PrintConfig.va_len}}} : {{:>{PrintConfig.page_size_len}}} : {{:>{PrintConfig.phys_len}}} "
            varying_str = fmt.format(hex(self.va), hex(self.page_size), hex(self.phys[0]))
        else:
            fmt = f"{{:>{PrintConfig.va_len}}} : {{:>{PrintConfig.page_size_len}}} "
            varying_str = fmt.format(hex(self.va), hex(self.page_size))

        uspace_writeable = is_user_writeable(self)
        kspace_writeable = is_kernel_writeable(self)
        uspace_readable = is_user_readable(self)
        kspace_readable = is_kernel_readable(self)
        uspace_executable = is_user_executable(self)
        kspace_executable = is_kernel_executable(self)
        delim = bcolors.YELLOW + " " + bcolors.ENDC
        uspace_color = select_color(uspace_writeable, uspace_executable, uspace_readable)
        uspace_str = uspace_color + f" R:{int(uspace_readable)} W:{int(uspace_writeable)} X:{int(uspace_executable)} " + bcolors.ENDC
        kspace_color = select_color(kspace_writeable, kspace_executable, kspace_readable)
        kspace_str = kspace_color + f" R:{int(kspace_readable)} W:{int(kspace_writeable)} X:{int(kspace_executable)}  " + bcolors.ENDC
        s = f"{varying_str}" + delim + uspace_str + delim + kspace_str
        return s

    def pwndbg_is_writeable(self):
        return is_user_writeable(self) or is_kernel_writeable(self)

    def pwndbg_is_executable(self):
        return is_user_executable(self) or is_kernel_executable(self)

class Aarch64_Table():
    def __init__(self, pa, va, pxn, xn, permissions):
        self.va = va
        self.pa = pa
        self.permissions = permissions
        self.pxn = pxn
        self.xn = xn

def aarch64_semantically_similar(p1: Aarch64_Block, p2: Aarch64_Block) -> bool:
    return p1.xn == p2.xn and p1.pxn == p2.pxn and p1.permissions == p2.permissions

class PT_Aarch64_Backend(PTArchBackend):
    def __init__(self, machine):
        self.machine = machine
        self.init_registers()

    def init_registers(self):
        self.pt_tcr = PT_TCR(self.machine)

    def print_stats(self):
        print(self.pt_tcr.check())

    def get_arch(self):
        return "aarch64"

    def walk(self, va):
        pt_walk = PageTableWalkInfo(va)

        # Use canonical form to determine which page table to use.
        top_bit_index = 63
        granule_size = None
        as_limit = None

        table_addr = None
        if va & (1 << top_bit_index) == 0:
            # top bit is not set, so this is a userspace address
            granule_size = self.determine_ttbr0_granule_size()
            as_limit = self.determine_ttbr0_address_space_limit()
            table_addr = extract_no_shift(self.get_ttbr0_el1(), 0, 47)
            pt_walk.add_register_stage("TTBR0_EL1", table_addr)
        else:
            granule_size = self.determine_ttbr1_granule_size()
            as_limit = self.determine_ttbr1_address_space_limit()
            table_addr = extract_no_shift(self.get_ttbr1_el1(), 0, 47)
            pt_walk.add_register_stage("TTBR1_EL1", table_addr)

        entry_size = 8
        bits_per_stage = int(math.log2(granule_size / entry_size))
        start_index = int(math.log2(granule_size))
        ranges = reversed([(base, base + bits_per_stage - 1) for base in range(start_index, as_limit, bits_per_stage)])

        for (index, r) in enumerate(ranges):
            page_pa = table_addr & ~0xfff
            entry_index = extract(va, r[0], r[1])
            entry_page_pa = page_pa + entry_index * entry_size
            entry_value = int.from_bytes(self.machine.read_physical_memory(entry_page_pa, entry_size), 'little')
            entry_value_pa = extract_no_shift(entry_value, 0, 47)
            entry_value_pa_no_meta = extract_no_shift(entry_value, 12, 47)
            meta_bits = extract_no_shift(entry_value, 0, 11)

            pt_walk.add_stage(f"Level{index}", entry_index, entry_value_pa_no_meta, meta_bits)

            bit1and2 = extract(entry_value, 0, 1)
            is_valid = bit1and2 != 0
            if not is_valid:
                pt_walk.set_faulted()
                break

            is_block = bit1and2 == 0x1
            if is_block:
                break
            table_addr = entry_value_pa

        return pt_walk

    def get_filter_is_writeable(self, has_superuser_filter, has_user_filter):
        if has_superuser_filter == True and has_user_filter == False:
            return lambda p: is_kernel_writeable(p)
        elif has_superuser_filter == False and has_user_filter == True:
            return lambda p: is_user_writeable(p)
        else:
            return lambda p: is_kernel_writeable(p) or is_user_writeable(p)

    def get_filter_is_not_writeable(self, has_superuser_filter, has_user_filter):
        if has_superuser_filter == True and has_user_filter == False:
            return lambda p: not is_kernel_writeable(p)
        elif has_superuser_filter == False and has_user_filter == True:
            return lambda p: not is_user_writeable(p)
        else:
            return lambda p: not is_kernel_writeable(p) and not is_user_writeable(p)

    def get_filter_is_executable(self, has_superuser_filter, has_user_filter):
        if has_superuser_filter == True and has_user_filter == False:
            return lambda p: is_kernel_executable(p)
        elif has_superuser_filter == False and has_user_filter == True:
            return lambda p: is_user_executable(p)
        else:
            return lambda p: is_user_executable(p) or is_kernel_executable(p)

    def get_filter_is_not_executable(self, has_superuser_filter, has_user_filter):
        if has_superuser_filter == True and has_user_filter == False:
            return lambda p: not is_kernel_executable(p)
        elif has_superuser_filter == False and has_user_filter == True:
            return lambda p: not is_user_executable(p)
        else:
            return lambda p: not is_user_executable(p) and not is_kernel_executable(p)

    def get_filter_is_writeable_or_executable(self, has_superuser_filter, has_user_filter):
        if has_superuser_filter == True and has_user_filter == False:
            return lambda p: is_kernel_writeable(p) or is_kernel_executable(p)
        elif has_superuser_filter == False and has_user_filter == True:
            return lambda p: is_user_writeable(p) or is_user_executable(p)
        else:
            return lambda p: is_kernel_writeable(p) or is_kernel_executable(p) or \
                                is_user_writeable(p) or is_user_executable(p)

    def get_filter_is_user_page(self, has_superuser_filter, has_user_filter):
        return lambda p: is_user_writeable(p) or is_user_readable(p) or is_user_executable(p)

    def get_filter_is_superuser_page(self, has_superuser_filter, has_user_filter):
        return lambda p: is_kernel_writeable(p) or is_kernel_readable(p) or is_kernel_executable(p)

    def get_filter_is_read_only_page(self, has_superuser_filter, has_user_filter):
        l_kernel = lambda p: (not is_kernel_writeable(p) and not is_kernel_executable(p)) and is_kernel_readable(p)
        l_user = lambda p: (not is_user_writeable(p) and not is_user_executable(p)) and is_user_readable(p)
        if has_superuser_filter == True and has_user_filter == False:
            return l_kernel
        elif has_superuser_filter == False and has_user_filter == True:
            return l_user
        else:
            return lambda p: l_user(p) or l_kernel(p)

    def get_filter_architecture_specific(self, filter_name, has_superuser_filter, has_user_filter):
        raise exception(f"Uknown filter {filter_name}")

    def get_ttbr0_el1(self):
        return self.machine.read_register("$TTBR0_EL1")

    def get_ttbr1_el1(self):
        return self.machine.read_register("$TTBR1_EL1")

    def determine_ttbr0_granule_size(self):
        tb0_granule_size = None
        tg0 = self.pt_tcr.TG0
        if tg0 == 0b00:
            tb0_granule_size = PT_AARCH64_4KB_PAGE
        elif tg0 == 0b01:
            tb0_granule_size = PT_AARCH64_64KB_PAGE
        elif tg0 == 0b10:
            tb0_granule_size = PT_AARCH64_16KB_PAGE
        else:
            raise Exception(f"Unknown TG0 value {tg0}")

        return tb0_granule_size

    def determine_ttbr1_granule_size(self):
        tb1_granule_size = None
        tg1 = self.pt_tcr.TG1
        if tg1 == 0b10:
            tb1_granule_size = PT_AARCH64_4KB_PAGE
        elif tg1 == 0b11:
            tb1_granule_size = PT_AARCH64_64KB_PAGE
        elif tg1 == 0b01:
            tb1_granule_size = PT_AARCH64_16KB_PAGE
        else:
            raise Exception(f"Unknown TG1 value {tg1}")

        return tb1_granule_size

    def determine_ttbr0_address_space_limit(self):
        return 64 - self.pt_tcr.T0SZ

    def determine_ttbr1_address_space_limit(self):
        return 64 - self.pt_tcr.T1SZ

    def aarch64_parse_entries(self, tbl, level_range, as_size, granule, is_last_level):
        # lvl starts from one to be in sync with the armv7 docs
        entries = []
        start_bit = int(math.log2(granule))

        try:
            entries = split_range_into_int_values(read_arbitrary_page(self.machine, tbl.pa, granule), 8)
        except Exception:
            pass

        tables = []
        blocks = []
        for i, pa in enumerate(entries):
            is_valid = bool(pa & 0x1)
            if is_valid:
                bit1 = extract(pa, 1, 1)
                bit1and2 = extract(pa, 0, 1)
                contiguous_bit = extract(pa, 52, 52)
                is_block_or_page = (bit1and2 == 1) or is_last_level
                is_table = (not is_block_or_page)
                address_contrib = (i << level_range[0])
                child_va = tbl.va | address_contrib
                if is_table:
                    next_level_address = extract_no_shift(pa, start_bit, 47)
                    permissions = extract(pa, 61, 62)
                    xn = (extract(pa, 60, 60) == 0x1) | tbl.xn
                    pxn = extract(pa, 59, 59) == 0x1 | tbl.pxn
                    tables.append(Aarch64_Table(next_level_address, child_va, pxn, xn, permissions))
                else:
                    xn = (extract(pa, 54, 54) == 0x1) | tbl.xn
                    pxn = (extract(pa, 53, 53) == 0x1) | tbl.pxn
                    phys_addr = extract_no_shift(pa, start_bit, 47)
                    permissions = extract(pa, 6, 7)
                    size = (1 << level_range[0])
                    blocks.append(Aarch64_Block(child_va, phys_addr, size, xn, pxn, permissions))

        return tables, blocks

    def arm_traverse_table(self, pt_addr, as_size, granule_size, leading_bit):
        num_entries_in_page = int(granule_size / 8)
        level_bit_coverage = int(math.log2(num_entries_in_page))
        low_bit_inclusive = int(math.log2(granule_size))
        top_bit_inclusive = as_size - 1

        table_ranges = list(reversed([(low, min(low + level_bit_coverage, top_bit_inclusive)) for low in range(low_bit_inclusive, top_bit_inclusive, level_bit_coverage)]))

        root = Aarch64_Table(pt_addr, 0, 0, 0, 0)
        tables = [root]
        all_blocks = []
        for (level, address_range) in enumerate(table_ranges):
            is_last_level = (level + 1) == len(table_ranges)
            new_tables = []
            for table in tables:
                cur_tables, cur_blocks = self.aarch64_parse_entries(table, address_range, as_size, granule_size, is_last_level)
                new_tables.extend(cur_tables)
                all_blocks.extend(cur_blocks)
            tables = new_tables

        if leading_bit == 1:
            for block in all_blocks:
                block.va = make_canonical(block.va | (1<<as_size), as_size+1)

        return all_blocks

    def parse_tables(self, cache, args):
        requires_physical_contiguity = args.phys_verbose
        tb0 = args.ttbr0_el1
        tb1 = args.ttbr1_el1

        if tb0:
            tb0 = int(tb0[0], 16)
        if tb1:
            tb1 = int(tb1[0], 16)

        # If neither is provided, just then query the actual translation table registers.
        if not tb0 and not tb1:
            tb0 = self.get_ttbr0_el1()
            tb1 = self.get_ttbr1_el1()

        all_blocks_0 = []
        all_blocks_1 = []
        if not args.ttbr0_el1:
            # Try to get the blocks from TTBR0 only if user has not specifically requested interpreting
            # the provided TTBR1.
            tb0 = extract_no_shift(tb0, 10, self.determine_ttbr0_address_space_limit() - 1)
            if tb0 in cache:
                all_blocks_0 = cache[tb0]
            else:
                tb0_granule_size = self.determine_ttbr0_granule_size()
                tb0_sz = self.determine_ttbr0_address_space_limit()
                all_blocks_0 = self.arm_traverse_table(tb0, tb0_sz, tb0_granule_size, 0)
                all_blocks_0 = optimize([], [], all_blocks_0, aarch64_semantically_similar, requires_physical_contiguity)

        if not args.ttbr1_el1:
            tb1 = extract_no_shift(tb1, 10, self.determine_ttbr1_address_space_limit() - 1)
            if tb1 in cache:
                all_blocks_1 = cache[tb1]
            else:
                tb1_granule_size = self.determine_ttbr1_granule_size()
                tb1_sz = self.determine_ttbr1_address_space_limit()
                all_blocks_1 = self.arm_traverse_table(tb1, tb1_sz, tb1_granule_size, 1)
                all_blocks_1 = optimize([], [], all_blocks_1, aarch64_semantically_similar, requires_physical_contiguity)

        # TODO: Consider the top-byte ignore rules
        # TODO: Consider EPDs

        if args.save:
            cache[tb0] = all_blocks_0
            cache[tb1] = all_blocks_1

        all_blocks = all_blocks_0 + all_blocks_1

        return all_blocks

    def print_kaslr_information(self, table, should_print = True, phys_verbose = False):
        potential_base_filter = lambda p: is_kernel_executable(p)
        tmp = list(filter(potential_base_filter, table))
        found_page = None
        kaslr_addresses = []
        stext_phys_base_addr = 0x40210000
        text_phys_base_addr = 0x40200000
        for page in tmp:
            if page.phys[0] == stext_phys_base_addr or page.phys[0] == text_phys_base_addr:
                found_page = page
                break
        if found_page:
            kaslr_addresses.append(found_page.va)
            if should_print:
                print("Found virtual image base:")
                print("\tVirt: " + found_page.to_string(phys_verbose))
                print("\tPhys: " + hex(found_page.phys[0]))
        else:
            if should_print:
                print("Failed to determine kaslr offsets")
        return kaslr_addresses

    def print_table(self, table, phys_verbose):
        varying_str = None
        if phys_verbose:
            fmt = f"{{:>{PrintConfig.va_len}}} : {{:>{PrintConfig.page_size_len}}} : {{:>{PrintConfig.phys_len}}} |"
            varying_str = fmt.format("Address", "Length", "Phys")
        else:
            fmt = f"{{:>{PrintConfig.va_len}}} : {{:>{PrintConfig.page_size_len}}} |"
            varying_str = fmt.format("Address", "Length")
        print(bcolors.BLUE + varying_str + " User space " + " | Kernel space " + bcolors.ENDC)
        for block in table:
            print(block.to_string(phys_verbose))

