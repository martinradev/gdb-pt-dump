from pt.pt_common import *
from pt.pt_arch_backend import PTArchBackend
from pt.pt_constants import *

import math

class Riscv64_Page(CommonPage):
    def __init__(self, va, phys, size, readable, writeable, executable, user):
        self.va = va
        self.page_size = size
        self.r = readable
        self.w = writeable
        self.x = executable
        self.s = not user
        self.phys = [phys]
        self.sizes = [size]

    def pwndbg_is_writeable(self):
        return self.w

    def pwndbg_is_executable(self):
        return self.x

    def to_string(self, phys_verbose):
        prefix = ""
        if not self.s:
            prefix = bcolors.CYAN + " " + bcolors.ENDC
        elif self.s:
            prefix = bcolors.MAGENTA + " " + bcolors.ENDC

        varying_str = None
        if phys_verbose:
            fmt = f"{{:>{PrintConfig.va_len}}} : {{:>{PrintConfig.page_size_len}}} : {{:>{PrintConfig.phys_len}}}"
            varying_str = fmt.format(hex(self.va), hex(self.page_size), hex(self.phys[-1]))
        else:
            fmt = f"{{:>{PrintConfig.va_len}}} : {{:>{PrintConfig.page_size_len}}}"
            varying_str = fmt.format(hex(self.va), hex(self.page_size))
        s = f"{varying_str} | W:{int(self.w)} X:{int(self.x)} R:{int(self.r)} S:{int(self.s)}"

        res = ""
        if self.x and self.w:
            res = prefix + bcolors.BLUE + " " + s + bcolors.ENDC
        elif self.w and not self.x:
            res = prefix + bcolors.GREEN + " " + s + bcolors.ENDC
        elif self.x:
            res = prefix + bcolors.RED + " " + s + bcolors.ENDC
        else:
            res = prefix + " " + s

        return res

class PT_RiscV64_Backend(PTArchBackend):
    def __init__(self, machine):
        self.machine = machine

    def get_arch(self):
        return "riscv64"

    def riscv64_semantically_similar(p1, p2) -> bool:
        return p1.x == p2.x and p1.w == p2.w and p1.r == p2.r and p1.s == p2.s

    def parse_entries(self, table, as_size, lvl):
        dirs = []
        pages = []
        entries = []
        try:
            entries = split_range_into_int_values(read_page(self.machine, table.phys[0]), 8)
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

    def traverse_table(self, pt_addr, as_size):
        root = Riscv64_Page(0, pt_addr, 0, 0, 0, 0, 0)
        directories, leafs = self.parse_entries(root, as_size, lvl=1)

        lvl = 2
        while len(directories) != 0:
            directories_cur_lvl = []
            for tmp_tb in directories:
                tmp_dirs, tmp_leafs = self.parse_entries(tmp_tb, as_size, lvl=lvl)
                directories_cur_lvl.extend(tmp_dirs)
                leafs.extend(tmp_leafs)
            lvl = lvl + 1
            directories = directories_cur_lvl

        for leaf in leafs:
            leaf.va = make_canonical(leaf.va, as_size)

        return leafs

    def print_stats(self):
        raise Exception("Unimplemented")

    def get_address_space_size_from_mode(self, mode_value):
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

    def walk(self, va):
        entry_size = 8
        num_entries_per_page = int(4096 / entry_size)
        bits_per_level = int(math.log2(num_entries_per_page))

        satp = self.machine.read_register("$satp")
        pt_addr = extract(satp, 0, 43) << 12
        mode_value = extract(satp, 60, 63)
        as_size = get_address_space_size_from_mode(mode_value)

        pt_walk = PageTableWalkInfo(va)
        pt_walk.add_register_stage("satp", pt_addr)

        iter = 0
        while True:
            top_bit = as_size - 1 - iter * bits_per_level
            low_bit = top_bit - bits_per_level + 1
            entry_index = extract(va, low_bit, top_bit)
            entry_page_pa = pt_addr + entry_index * entry_size
            entry_value = int.from_bytes(self.machine.read_physical_memory(entry_page_pa, entry_size), 'little')
            entry_value_pa_no_meta = (extract(entry_value, 10, 53)) << 12
            meta_bits = extract_no_shift(entry_value, 0, 9)
            pt_walk.add_stage(f"Level{iter}", entry_index, entry_value_pa_no_meta, meta_bits)

            if extract(meta_bits, 0, 0) == 0:
                # Not present
                pt_walk.set_faulted()

            is_leaf = (extract(meta_bits, 1, 3) != 0)
            if is_leaf:
                break

            pt_addr = entry_value_pa_no_meta
            iter += 1

        return pt_walk

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
        requires_physical_contiguity = args.phys_verbose

        if satp:
            satp = int(satp[0], 16)
        else:
            satp = self.machine.read_register("$satp")

        all_blocks = None

        if satp in cache:
            all_blocks = cache[satp]
        else:
            mode_value = extract(satp, 60, 63)
            as_size = self.get_address_space_size_from_mode(mode_value)
            pt_base = extract(satp, 0, 43) << 12
            all_blocks = self.traverse_table(pt_base, as_size)
            all_blocks = optimize([], [], all_blocks, PT_RiscV64_Backend.riscv64_semantically_similar, requires_physical_contiguity)

        if args.save:
            cache[satp] = all_blocks

        return all_blocks

    def print_kaslr_information(self, table, should_print = True, phys_verbose = False):
        return None

    def print_table(self, table, phys_verbose):
        varying_str = None
        if phys_verbose:
            fmt = f"  {{:>{PrintConfig.va_len}}} : {{:>{PrintConfig.page_size_len}}} : {{:>{PrintConfig.phys_len}}}"
            varying_str = fmt.format("Address", "Length", "Phys")
        else:
            fmt = f"  {{:>{PrintConfig.va_len}}} : {{:>{PrintConfig.page_size_len}}}"
            varying_str = fmt.format("Address", "Length")
        print(bcolors.BLUE + varying_str + "   Permissions    " + bcolors.ENDC)
        for page in table:
            print(page.to_string(phys_verbose))
        return None

