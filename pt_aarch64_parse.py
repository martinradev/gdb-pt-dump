from pt_common import *

PT_AARCH64_SMALL_PAGE = 4096
PT_AARCH64_BIG_PAGE   = 64 * 1024

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
    try:
        entries = read_page(phys_mem, tbl.pa) if granule == PT_AARCH64_SMALL_PAGE else read_64k_page(phys_mem, tbl.pa)
    except Exception as e:
        print(e)
        return [], []
    tables = []
    blocks = []
    for i, pa in enumerate(entries):
        is_valid = bool(pa & 0x1)
        if is_valid:
            bit1 = extract(pa, 1, 1)
            if (lvl == 4 and bit1 == 0):
                continue
            contiguous_bit = extract(pa, 52, 52)
            is_block_or_page = (lvl <= 3 and bit1 == 0) or lvl == 4 or contiguous_bit
            is_table = (not is_block_or_page)
            address_contrib = (i << (as_size - 9 * tbl.lvl))
            child_va = tbl.va | address_contrib
            if is_table:
                next_level_address = extract_no_shift(pa, 12, 47)
                permissions = extract(pa, 61, 62)
                xn = (extract(pa, 60, 60) == 0x1) | tbl.xn
                pxn = extract(pa, 59, 59) == 0x1 | tbl.pxn
                tables.append(Aarch64_Table(next_level_address, child_va, tbl.lvl + 1, pxn, xn, permissions))
            else:
                xn = (extract(pa, 54, 54) == 0x1) | tbl.xn
                pxn = (extract(pa, 53, 53) == 0x1) | tbl.pxn
                phys_addr = extract_no_shift(pa, 12, 47)
                permissions = extract(pa, 6, 7)
                # TODO: handle 64k page size
                size = 2 ** (as_size - lvl * 9)
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
    for tmp_tb in tables_lvl3:
        tmp_tables, tmp_blocks = aarch64_parse_entries(phys_mem, tmp_tb, as_size, granule_size, lvl=4)
        tables_lvl4.extend(tmp_tables)
        blocks_lvl4.extend(tmp_blocks)

    all_blocks = blocks_lvl1 + blocks_lvl2 + blocks_lvl3 + blocks_lvl4

    if leading_bit == 1:
        for block in all_blocks:
            block.va = block.va | (((1 << 64) - 1) ^ ((1 << as_size) - 1))

    return all_blocks

def parse_and_print_aarch64_table(cache, phys_mem, args, should_print = True):
    tb0 = int(gdb.parse_and_eval("$TTBR0_EL1").cast(gdb.lookup_type("long")))
    tb1 = int(gdb.parse_and_eval("$TTBR1_EL1").cast(gdb.lookup_type("long")))
    tcr = int(gdb.parse_and_eval("$TCR_EL1").cast(gdb.lookup_type("long")))

    physical_as = extract(tcr, 32, 34)
    if tb0 in cache:
        all_blocks_0 = cache[tb0]
    else:
        tb0 = extract_no_shift(tb0, 10, 47)
        tb0_granule_size = PT_AARCH64_SMALL_PAGE if extract(tcr, 14, 14) == 0 else PT_AARCH64_BIG_PAGE
        tb0_sz = 64 - extract(tcr, 0, 5)
        tb0_depth = int((tb0_sz - 12) / 9) # TODO: this assumes page is 4k
        all_blocks_0 = arm_traverse_table(phys_mem, tb0, tb0_sz, tb0_granule_size, 0)
        all_blocks_0 = optimize([], [], all_blocks_0, aarch64_semantically_similar)

    if tb1 in cache:
        all_blocks_1 = cache[tb1]
    else:
        tb1 = extract_no_shift(tb1, 10, 47)
        tb1_granule_size = PT_AARCH64_SMALL_PAGE if extract(tcr, 30, 30) == 0 else PT_AARCH64_BIG_PAGE
        tb1_sz = 64 - extract(tcr, 16, 21)
        tb1_depth = int((tb1_sz - 12) / 9) # TODO: this assumes the page is 4k
        all_blocks_1 = arm_traverse_table(phys_mem, tb1, tb1_sz, tb1_granule_size, 1)
        all_blocks_1 = optimize([], [], all_blocks_1, aarch64_semantically_similar)

    # TODO: Consider the top-byte ignore rules
    # TODO: Consider EPDs

    if args.save:
        cache[tb0] = all_blocks_0
        cache[tb1] = all_blocks_1

    # First go through the `u` and `s` filters
    filters = []
    if args.filter:
        include_user = True
        include_kernel = True
        for f in args.filter:
            if f == "u":
                include_user = True
                include_kernel = False
            elif f == "s":
                include_user = False
                include_kernel = True

        for f in args.filter:
            if f == "w":
                if include_kernel and not include_user:
                    filters.append(is_kernel_writeable)
                elif include_user and not include_kernel:
                    filters.append(is_user_writeable)
                elif include_user and include_kernel:
                    filters.append(lambda p: is_kernel_writeable(p) or is_user_writeable(p))
                else:
                    raise Exception(f"Unknown filter: {f}")
            elif f == "x":
                if include_kernel and not include_user:
                    filters.append(is_kernel_executable)
                elif include_user and not include_kernel:
                    filters.append(is_user_executable)
                elif include_user and include_kernel:
                    filters.append(lambda p: is_kernel_executable(p) or is_user_executable(p))
                else:
                    raise Exception(f"Unknown filter: {f}")
            elif f == "w|x" or f == "x|w":
                l_kernel = lambda p: is_kernel_writeable(p) or is_kernel_executable(p)
                l_user = lambda p: is_user_writeable(p) or is_user_executable(p)
                if include_kernel and not include_user:
                    filters.append(l_kernel)
                elif include_user and not include_kernel:
                    filters.append(l_user)
                elif include_user and include_kernel:
                    filters.append(lambda p: l_user(p) or l_kernel(p))
                else:
                    raise Exception(f"Unknown filter: {f}")
            elif f == "ro":
                l_kernel = lambda p: (not is_kernel_writeable(p) and not is_kernel_executable(p)) and is_kernel_readable(p)
                l_user = lambda p: (not is_user_writeable(p) and not is_user_executable(p)) and is_user_readable(p)
                if include_kernel and not include_user:
                    filters.append(l_kernel)
                elif include_user and not include_kernel:
                    filters.append(l_user)
                elif include_kernel and include_user:
                    filters.append(lambda p: l_user(p) or l_kernel(p))
                else:
                    raise Exception(f"Unknown filter: {f}")
            elif f == "u" or f == "s":
                continue
            else:
                print(f"Unknown filter: {f}")
                return

    all_blocks = all_blocks_0 + all_blocks_1
    all_blocks = list(filter(create_compound_filter(filters), all_blocks))

    if args.range:
        all_blocks = list(filter(lambda page: page.va >= args.range[0] and page.va <= args.range[1], all_blocks))

    if args.has:
        all_blocks = list(filter(lambda page: args.has[0] >= page.va and args.has[0] < page.va + page.page_size, all_blocks))

    if args.after:
        all_blocks = list(filter(lambda page: args.after[0] <= page.va, all_blocks))

    if args.before:
        all_blocks = list(filter(lambda page: args.before[0] > page.va, all_blocks))

    if args.kaslr:
        two_mib = 2 * 1024 * 1024
        potential_base_filter = lambda p: is_kernel_executable(p)
        tmp = list(filter(potential_base_filter, all_blocks))
        th = gdb.selected_inferior()
        found_page = None
        for page in tmp:
            page_2mib_aligned_start = page.va if page.va % two_mib == 0 else (page.va & ~(two_mib - 1)) + two_mib
            for start_addr in range(page_2mib_aligned_start, page.va + page.page_size, two_mib):
                first_byte = th.read_memory(start_addr, 1)
                if first_byte[0] == b'\x4d':
                    found_page = page
                    break
        if found_page:
            print("Found virtual image base:")
            print("\tVirt: " + str(found_page))
            print("\tPhys: " + hex(found_page.phys[0]))
        else:
            print("Failed to determine kaslr offsets")

    if should_print:
        max_va_len, max_page_size_len = compute_max_str_len(all_blocks)
        fmt = f"{{:>{max_va_len}}} : {{:>{max_page_size_len}}}"
        varying_str = fmt.format("Address", "Length")
        print(bcolors.BLUE + varying_str + "  User space " + "   Kernel space " + bcolors.ENDC)
        for block in all_blocks:
            print(block.block_to_str(max_va_len, max_page_size_len))

    return all_blocks

