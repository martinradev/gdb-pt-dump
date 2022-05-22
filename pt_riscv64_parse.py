from pt_common import *
from pt_arch_backend import PTArchBackend
from pt_constants import *

def get_address_space_size_from_mode(mode_value):
    if mode_value == 8:
        return 39
    elif mode_value == 9:
        return 48
    elif mode_value == 10:
        return 57
    elif mode_value == 11:
        return 64
    else:
        raise Exception(f"Unknown mode: {hex(mode_value)}")

class Riscv64_Page():
    def __init__(self, va, phys, size, readable, writeable, executable, user):
        self.va = va
        self.page_size = size
        self.r = readable
        self.w = writeable
        self.x = executable
        self.s = not user
        self.phys = [phys]
        self.sizes = [size]

    def __str__(self):
        conf = PagePrintSettings(va_len = 18, page_size_len = 8)
        return page_to_str(self, conf)

    def read_memory(self, phys_mem):
        memory = b""
        for phys_range_start, phys_range_size in zip(self.phys, self.sizes):
            memory += phys_mem.read(phys_range_start, phys_range_size)
        return memory

    def cut_before(self, va):
        print("cut_before not supported")

    def cut_after(self, va):
        print("cut_after not supported")

    def pwndbg_is_writeable(self):
        return self.w

    def pwndbg_is_executable(self):
        return self.x

def riscv64_semantically_similar(p1, p2) -> bool:
    return p1.x == p2.x and p1.w == p2.w and p1.r == p2.r and p1.s == p2.s

def parse_entries(phys_mem, table, as_size, lvl):
    dirs = []
    pages = []
    entries = []
    try:
        entries = split_range_into_int_values(read_page(phys_mem, table.phys[0]), 8)
    except:
        pass
    for i, pa in enumerate(entries):
        valid = extract(pa, 0, 0)
        if valid:
            is_leaf = (extract(pa, 1, 3) != 0)
            address_contrib = (i << (as_size - lvl * 9))
            child_va = table.va | address_contrib
            phys_addr = extract(pa, 10, 53) << 12
            if is_leaf:
                size = 1 << (as_size - lvl * 9)
                readable = extract(pa, 1, 1)
                writeable = extract(pa, 2, 2)
                executable = extract(pa, 3, 3)
                user_accessible = extract(pa, 4, 4)
                pages.append(Riscv64_Page(child_va, phys_addr, size, readable, writeable, executable, user_accessible))
            else:
                dirs.append(Riscv64_Page(child_va, phys_addr, None, None, None, None, None))
    return dirs, pages


def traverse_table(phys_mem, pt_addr, as_size):
    root = Riscv64_Page(0, pt_addr, 0, 0, 0, 0, 0)
    directories, leafs = parse_entries(phys_mem, root, as_size, lvl=1)

    lvl = 2
    while len(directories) != 0:
        directories_cur_lvl = []
        for tmp_tb in directories:
            tmp_dirs, tmp_leafs = parse_entries(phys_mem, tmp_tb, as_size, lvl=lvl)
            directories_cur_lvl.extend(tmp_dirs)
            leafs.extend(tmp_leafs)
        lvl = lvl + 1
        directories = directories_cur_lvl

    for leaf in leafs:
        leaf.va = make_canonical(leaf.va, as_size)

    return leafs

def print_stats():
    return

def page_to_str(page, conf: PagePrintSettings):
    prefix = ""
    if not page.s:
        prefix = bcolors.CYAN + " " + bcolors.ENDC
    elif page.s:
        prefix = bcolors.MAGENTA + " " + bcolors.ENDC

    fmt = f"{{:>{conf.va_len}}} : {{:>{conf.page_size_len}}}"
    varying_str = fmt.format(hex(page.va), hex(page.page_size))
    s = f"{varying_str} | W:{int(page.w)} X:{int(page.x)} R:{int(page.r)} S:{int(page.s)}"

    res = ""
    if page.x and page.w:
        res = prefix + bcolors.BLUE + " " + s + bcolors.ENDC
    elif page.w and not page.x:
        res = prefix + bcolors.GREEN + " " + s + bcolors.ENDC
    elif page.x:
        res = prefix + bcolors.RED + " " + s + bcolors.ENDC
    else:
        res = prefix + " " + s

    return res

class PT_RiscV64_Backend(PTArchBackend):
    def __init__(self, phys_mem):
        self.phys_mem = phys_mem

    def get_arch(self):
        return "riscv64"

    def get_filter_is_writeable(self, has_superuser_filter, has_user_filter):
        return lambda p: p.w

    def get_filter_is_not_writeable(self, has_superuser_filter, has_user_filter):
        return lambda p: not p.w

    def get_filter_is_executable(self, has_superuser_filter, has_user_filter):
        return lambda p: p.x

    def get_filter_is_not_executable(self, has_superuser_filter, has_user_filter):
        return lambda p: not p.x

    def get_filter_is_writeable_or_executable(self, has_superuser_filter, has_user_filter):
        return lambda p: p.w or p.x

    def get_filter_is_user_page(self, has_superuser_filter, has_user_filter):
        return lambda p: not p.s

    def get_filter_is_superuser_page(self, has_superuser_filter, has_user_filter):
        return lambda p: p.s

    def get_filter_is_read_only_page(self, has_superuser_filter, has_user_filter):
        return lambda p: p.r and not p.w and not p.x

    def get_filter_architecture_specific(self, filter_name, has_superuser_filter, has_user_filter):
        raise exception(f"Uknown filter {filter_name}")

    def parse_tables(self, cache, args):
        satp = args.satp

        if satp:
            satp = int(satp[0], 16)
        else:
            satp = int(gdb.parse_and_eval("$satp").cast(gdb.lookup_type("unsigned long")))

        all_blocks = None

        if satp in cache:
            all_blocks = cache[satp]
        else:
            mode_value = extract(satp, 60, 63)
            as_size = get_address_space_size_from_mode(mode_value)
            pt_base = extract(satp, 0, 43) << 12
            all_blocks = traverse_table(self.phys_mem, pt_base, as_size)
            all_blocks = optimize([], [], all_blocks, riscv64_semantically_similar)

        if args.save:
            cache[satp] = all_blocks

        return all_blocks

    def print_kaslr_information(self, table):
        return None

    def print_table(self, table):
        max_va_len, max_page_size_len = compute_max_str_len(table)
        conf = PagePrintSettings(va_len = max_va_len, page_size_len = max_page_size_len)
        fmt = f"  {{:>{max_va_len}}} : {{:>{max_page_size_len}}}"
        varying_str = fmt.format("Address", "Length")
        print(bcolors.BLUE + varying_str + "   Permissions    " + bcolors.ENDC)
        for page in table:
            print(page_to_str(page, conf))
        return None

    def print_stats(self):
        print_stats()
        return

