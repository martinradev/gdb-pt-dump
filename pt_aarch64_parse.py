from pt_common import *
import pt_aarch64_definitions as a64_def
from pt_arch_backend import PTArchBackend
from pt_constants import *

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

class Aarch64_Block():
    def __init__(self, va, phys, size, xn, pxn, permissions):
        self.va = va
        self.page_size = size
        self.xn = xn
        self.pxn = pxn
        self.permissions = permissions
        self.phys = [phys]
        self.sizes = [size]

    def cut_before(self, va):
        print("cut_before is not implemented")

    def cut_after(self, va):
        print("cut_after is not implemented")

    def block_to_str(self, max_va_len, max_page_size_len):
        fmt = f"{{:>{max_va_len}}} : {{:>{max_page_size_len}}}"
        uspace_writeable = is_user_writeable(self)
        kspace_writeable = is_kernel_writeable(self)
        uspace_readable = is_user_readable(self)
        kspace_readable = is_kernel_readable(self)
        uspace_executable = is_user_executable(self)
        kspace_executable = is_kernel_executable(self)
        delim = bcolors.YELLOW + " " + bcolors.ENDC
        varying_str = fmt.format(hex(self.va), hex(self.page_size))
        uspace_color = select_color(uspace_writeable, uspace_executable, uspace_readable)
        uspace_str = uspace_color + f" R:{int(uspace_readable)} W:{int(uspace_writeable)} X:{int(uspace_executable)} " + bcolors.ENDC
        kspace_color = select_color(kspace_writeable, kspace_executable, kspace_readable)
        kspace_str = kspace_color + f" R:{int(kspace_readable)} W:{int(kspace_writeable)} X:{int(kspace_executable)} " + bcolors.ENDC
        s = f"{varying_str} " + delim + uspace_str + delim + kspace_str
        return s

    def read_memory(self, phys_mem):
        memory = b""
        for phys_range_start, phys_range_size in zip(self.phys, self.sizes):
            memory += phys_mem.read(phys_range_start, phys_range_size)
        return memory

    def __str__(self):
        return self.block_to_str(18, 8)

    def pwndbg_is_writeable(self):
        return is_user_writeable(self) or is_kernel_writeable(self)

    def pwndbg_is_executable(self):
        return is_user_executable(self) or is_kernel_executable(self)

class Aarch64_Table():
    def __init__(self, pa, va, lvl, pxn, xn, permissions):
        self.va = va
        self.pa = pa
        self.lvl = lvl
        self.permissions = permissions
        self.pxn = pxn
        self.xn = xn

def aarch64_semantically_similar(p1: Aarch64_Block, p2: Aarch64_Block) -> bool:
    return p1.xn == p2.xn and p1.pxn == p2.pxn and p1.permissions == p2.permissions

def aarch64_parse_entries(phys_mem, tbl, as_size, granule, lvl):
    # lvl starts from one to be in sync with the armv7 docs
    entries = None
    target_address_low = None
    last_level = None
    sizes = None
    index_ranges_per_lvl = []
    try:
        # `as_size == 25` implies 39-bit VAs, which only use 3-level page tables
        if granule == PT_AARCH64_4KB_PAGE and as_size == 39:
            entries = []
            try:
                entries = split_range_into_int_values(read_page(phys_mem, tbl.pa), 8)
            except:
                pass
            target_address_low = 12
            last_level = 3
            sizes = [PT_SIZE_1GIB, PT_SIZE_2MIB, PT_SIZE_4K]
            index_ranges_per_lvl = [(30, 38), (21, 29), (12, 20)]
        elif granule == PT_AARCH64_4KB_PAGE:
            entries = []
            try:
                entries = split_range_into_int_values(read_page(phys_mem, tbl.pa), 8)
            except:
                pass
            target_address_low = 12
            last_level = 4
            sizes = [PT_SIZE_512GIB, PT_SIZE_1GIB, PT_SIZE_2MIB, PT_SIZE_4K]
            index_ranges_per_lvl = [(39, 47), (30, 38), (21, 29), (12, 20)]
        elif granule == PT_AARCH64_64KB_PAGE:
            entries = []
            try:
                entries = split_range_into_int_values(read_64k_page(phys_mem, tbl.pa), 8)
            except:
                pass
            target_address_low = 16
            last_level = 3
            sizes = [PT_SIZE_4TB, PT_SIZE_512MIB, PT_SIZE_64K]
            index_ranges_per_lvl = [(42, 48), (29, 41), (16, 28)]
        elif granule == PT_AARCH64_16KB_PAGE:
            entries = []
            try:
                entries = split_range_into_int_values(read_16k_page(phys_mem, tbl.pa), 8)
            except:
                pass
            target_address_low = 14
            last_level = 4
            sizes = [PT_SIZE_128TB, PT_SIZE_64GIB, PT_SIZE_32MIB, PT_SIZE_16K]
            index_ranges_per_lvl = [(47, 47), (36, 46), (25, 35), (14, 24)]
        else:
            raise Exception(f"Unknown granule size: {granule}")
    except Exception as e:
        print(e)
        return [], []
    tables = []
    blocks = []
    for i, pa in enumerate(entries):
        is_valid = bool(pa & 0x1)
        if is_valid:
            bit1 = extract(pa, 1, 1)
            bit1and2 = extract(pa, 0, 1)
            if (lvl == 4 and bit1 == 0):
                continue
            # TODO: Write comment about contiguous bit
            contiguous_bit = extract(pa, 52, 52)
            is_block_or_page = (lvl < last_level and bit1and2 == 1) or lvl == last_level or contiguous_bit
            is_table = (not is_block_or_page)
            address_contrib = (i << (index_ranges_per_lvl[lvl-1][0]))
            child_va = tbl.va | address_contrib
            if is_table:
                next_level_address = extract_no_shift(pa, target_address_low, 47)
                permissions = extract(pa, 61, 62)
                xn = (extract(pa, 60, 60) == 0x1) | tbl.xn
                pxn = extract(pa, 59, 59) == 0x1 | tbl.pxn
                tables.append(Aarch64_Table(next_level_address, child_va, tbl.lvl + 1, pxn, xn, permissions))
            else:
                xn = (extract(pa, 54, 54) == 0x1) | tbl.xn
                pxn = (extract(pa, 53, 53) == 0x1) | tbl.pxn
                phys_addr = extract_no_shift(pa, target_address_low, 47)
                permissions = extract(pa, 6, 7)
                # TODO: handle 64k page size
                size = sizes[lvl - 1]
                blocks.append(Aarch64_Block(child_va, phys_addr, size, xn, pxn, permissions))
    return tables, blocks

def arm_traverse_table(phys_mem, pt_addr, as_size, granule_size, leading_bit):
    root = Aarch64_Table(pt_addr, 0, 1, 0, 0, 0)
    tables_lvl1, blocks_lvl1 = aarch64_parse_entries(phys_mem, root, as_size, granule_size, lvl=1)

    tables_lvl2 = []
    blocks_lvl2 = []
    for tmp_tb in tables_lvl1:
        tmp_tables, tmp_blocks = aarch64_parse_entries(phys_mem, tmp_tb, as_size, granule_size, lvl=2)
        tables_lvl2.extend(tmp_tables)
        blocks_lvl2.extend(tmp_blocks)

    tables_lvl3 = []
    blocks_lvl3 = []
    for tmp_tb in tables_lvl2:
        tmp_tables, tmp_blocks = aarch64_parse_entries(phys_mem, tmp_tb, as_size, granule_size, lvl=3)
        tables_lvl3.extend(tmp_tables)
        blocks_lvl3.extend(tmp_blocks)

    tables_lvl4 = []
    blocks_lvl4 = []
    if granule_size != 64 * 1024: # With 64 KiB granule, one level is ignored.
        for tmp_tb in tables_lvl3:
            tmp_tables, tmp_blocks = aarch64_parse_entries(phys_mem, tmp_tb, as_size, granule_size, lvl=4)
            tables_lvl4.extend(tmp_tables)
            blocks_lvl4.extend(tmp_blocks)

    all_blocks = blocks_lvl1 + blocks_lvl2 + blocks_lvl3 + blocks_lvl4

    if leading_bit == 1:
        for block in all_blocks:
            block.va = make_canonical(block.va | (1<<as_size), as_size+1)

    return all_blocks

def print_stats():
    print(a64_def.pt_tcr.check())

class PT_Aarch64_Backend(PTArchBackend):
    def __init__(self, phys_mem):
        self.phys_mem = phys_mem

    def get_arch(self):
        return "aarch64"

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

    def parse_tables(self, cache, args):
        tb0 = args.ttbr0_el1
        tb1 = args.ttbr1_el1

        if tb0:
            tb0 = int(tb0[0], 16)
        if tb1:
            tb1 = int(tb1[0], 16)

        # If neither is provided, just then query the actual translation table registers.
        if not tb0 and not tb1:
            tb0 = int(gdb.parse_and_eval("$TTBR0_EL1").cast(gdb.lookup_type("unsigned long")))
            tb1 = int(gdb.parse_and_eval("$TTBR1_EL1").cast(gdb.lookup_type("unsigned long")))

        all_blocks_0 = []
        all_blocks_1 = []
        if not args.ttbr1_el1:
            # Try to get the blocks from TTBR0 only if user has not specifically requested interpreting
            # the provided TTBR1.
            tb0 = extract_no_shift(tb0, 10, 47)
            if tb0 in cache:
                all_blocks_0 = cache[tb0]
            else:
                tb0_granule_size = None
                tg0 = a64_def.pt_tcr.TG0
                if tg0 == 0b00:
                    tb0_granule_size = PT_AARCH64_4KB_PAGE
                elif tg0 == 0b01:
                    tb0_granule_size = PT_AARCH64_64KB_PAGE
                elif tg0 == 0b10:
                    tb0_granule_size = PT_AARCH64_16KB_PAGE
                else:
                    raise Exception(f"Unknown TG0 value {tg0}")
                tb0_sz = 64 - a64_def.pt_tcr.T0SZ
                all_blocks_0 = arm_traverse_table(self.phys_mem, tb0, tb0_sz, tb0_granule_size, 0)
                all_blocks_0 = optimize([], [], all_blocks_0, aarch64_semantically_similar)

        if not args.ttbr0_el1:
            tb1 = extract_no_shift(tb1, 10, 47)
            if tb1 in cache:
                all_blocks_1 = cache[tb1]
            else:
                tb1_granule_size = None
                tg1 = a64_def.pt_tcr.TG1
                if tg1 == 0b10:
                    tb1_granule_size = PT_AARCH64_4KB_PAGE
                elif tg1 == 0b11:
                    tb1_granule_size = PT_AARCH64_64KB_PAGE
                elif tg1 == 0b01:
                    tb1_granule_size = PT_AARCH64_16KB_PAGE
                else:
                    raise Exception(f"Unknown TG1 value {tg1}")
                tb1_sz = 64 - a64_def.pt_tcr.T1SZ
                all_blocks_1 = arm_traverse_table(self.phys_mem, tb1, tb1_sz, tb1_granule_size, 1)
                all_blocks_1 = optimize([], [], all_blocks_1, aarch64_semantically_similar)

        # TODO: Consider the top-byte ignore rules
        # TODO: Consider EPDs

        if args.save:
            cache[tb0] = all_blocks_0
            cache[tb1] = all_blocks_1

        all_blocks = all_blocks_0 + all_blocks_1

        return all_blocks

    def print_kaslr_information(self, table, should_print = True):
        potential_base_filter = lambda p: is_kernel_executable(p)
        tmp = list(filter(potential_base_filter, table))
        th = gdb.selected_inferior()
        found_page = None
        kaslr_addresses = []
        for page in tmp:
            page_2mib_aligned_start = page.va if page.va % PT_SIZE_2MIB == 0 else (page.va & ~(PT_SIZE_2MIB - 1)) + PT_SIZE_2MIB
            for start_addr in range(page_2mib_aligned_start, page.va + page.page_size, PT_SIZE_2MIB):
                first_byte = th.read_memory(start_addr, 1)
                if first_byte[0] == b'\x4d':
                    found_page = page
                    break
        if found_page:
            kaslr_addresses.append(found_page.va)
            if should_print:
                print("Found virtual image base:")
                print("\tVirt: " + str(found_page))
                print("\tPhys: " + hex(found_page.phys[0]))
        else:
            if should_print:
                print("Failed to determine kaslr offsets")
        return kaslr_addresses

    def print_table(self, table):
        max_va_len, max_page_size_len = compute_max_str_len(table)
        fmt = f"{{:>{max_va_len}}} : {{:>{max_page_size_len}}}"
        varying_str = fmt.format("Address", "Length")
        print(bcolors.BLUE + varying_str + "  User space " + "   Kernel space " + bcolors.ENDC)
        for block in table:
            print(block.block_to_str(max_va_len, max_page_size_len))

    def print_stats(self):
        print_stats()
        return

