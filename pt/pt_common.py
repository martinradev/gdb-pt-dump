from collections import namedtuple
import copy

class bcolors:
    RED     = '\033[41m'
    BLUE    = '\033[44m'
    GREEN   = '\033[42m'
    CYAN    = '\033[106m'
    MAGENTA = '\033[45m'
    BLACK   = '\033[40m'
    YELLOW  = '\033[103m'
    LGREY   = '\033[47m'
    ENDC    = '\033[0m'

def extract(value, s, e):
    return extract_no_shift(value, s, e) >> s

def extract_no_shift(value, s, e):
    mask = ((1<<(e + 1))-1) & ~((1<<s) - 1)
    return (value & mask)

def split_range_into_int_values(memory, value_size):
    values = []
    for u in range(0, len(memory), value_size):
        values.append(int.from_bytes(memory[u:u+value_size], 'little'))
    return values

def read_arbitrary_page(machine, addr, page_size):
    return machine.read_physical_memory(addr, page_size)

def read_page(machine, addr):
    return read_arbitrary_page(machine, addr, 4096)

def read_16k_page(machine, addr):
    return read_arbitrary_page(machine, addr, 16 * 1024)

def read_64k_page(machine, addr):
    return read_arbitrary_page(machine, addr, 64 * 1024)

def make_canonical(va, top_bit_pos = 48):
    shift = top_bit_pos - 1
    bit = (va >> shift) & 0x1
    mask = ((((2**64)-1) >> shift) * bit) << shift
    return va | mask

PagePrintSettings = namedtuple('PagePrintSettings', ['va_len', 'page_size_len', 'phys_len'])
PrintConfig = PagePrintSettings(va_len = 18, page_size_len = 14, phys_len = 12)

class CommonPage():

    def cut_after(self, cut_addr):
        i = 0
        off = 0
        while i < len(self.phys):
            if cut_addr < self.va + off + self.sizes[i]:
                break
            off += self.sizes[i]
            i += 1
        if i > 0:
            self.phys = self.phys[i:]
            self.sizes = self.sizes[i:]
        delta = 0
        if len(self.phys) >= 1 and cut_addr >= self.va:
            delta = cut_addr - (self.va + off)
            self.sizes[0] = self.sizes[0] - delta
            self.phys[0] = self.phys[0] + delta
        self.page_size = self.page_size - delta - off
        self.va = max(self.va, cut_addr)

    def cut_before(self, cut_addr):
        i = len(self.phys) - 1
        off = 0
        while i >= 0:
            if self.va < cut_addr:
                break
            off += self.sizes[i]
            i -= 1
        if i > 0:
            self.phys = self.phys[:i]
            self.sizes = self.sizes[:i]
        delta = 0
        if len(self.phys) >= 1:
            delta = max(0, (self.va + self.page_size - off) - cut_addr)
            self.sizes[-1] = self.sizes[-1] - delta
        self.page_size = min(self.page_size, cut_addr - self.va)

    def read_memory(self, machine):
        memory = b""
        for phys_range_start, phys_range_size in zip(self.phys, self.sizes):
            memory += machine.read_physical_memory(phys_range_start, phys_range_size)
        return memory

class Page(CommonPage):
    def __init__(self):
        self.va = None
        self.page_size = None
        self.w = None
        self.x = None
        self.s = None
        self.wb = None
        self.uc = None
        self.phys = None
        self.sizes = None

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
            varying_str = fmt.format(hex(self.va), hex(self.page_size), hex(self.phys[0]))
        else:
            fmt = f"{{:>{PrintConfig.va_len}}} : {{:>{PrintConfig.page_size_len}}}"
            varying_str = fmt.format(hex(self.va), hex(self.page_size))

        s = f"{varying_str} | W:{int(self.w)} X:{int(self.x)} S:{int(self.s)} UC:{int(self.uc)} WB:{int(self.wb)}"

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

def merge_cont_pages(pages, func_semantic_sim, require_physical_contiguity):
    if len(pages) <= 1:
        return pages

    # Here I am just going to abuse the Page structure to contain the range
    merged_pages = []
    cur_page = copy.copy(pages[0])
    for page in pages[1:]:

        merge_pages = True
        if not (cur_page.va + cur_page.page_size == page.va and func_semantic_sim(cur_page, page)):
            merge_pages = False

        if require_physical_contiguity and not (cur_page.phys[-1] + cur_page.sizes[-1] == page.phys[0]):
            merge_pages = False

        if merge_pages:
            cur_page.page_size = cur_page.page_size + page.page_size
            if cur_page.phys[-1] + cur_page.sizes[-1] == page.phys[0]:
                # Depending on the flag require_physical_contiguity, the extended ranges may or may not be physically contiguous
                assert(len(page.phys) == 1)
                assert(len(page.sizes) == 1)
                cur_page.sizes[-1] = cur_page.sizes[-1] + page.page_size
            else:
                # If not, then add a new entry
                cur_page.phys.extend(page.phys)
                cur_page.sizes.extend(page.sizes)
        else:
            merged_pages.append(cur_page)
            cur_page = copy.copy(page)
    merged_pages.append(cur_page)
    return merged_pages 

def optimize(gig_pages, mb_pages, kb_pages, func_semantic_sim, require_physical_contiguity):
    pages = sorted(gig_pages + mb_pages + kb_pages, key = lambda p: p.va)
    opt = merge_cont_pages(pages, func_semantic_sim, require_physical_contiguity)
    return opt

def select_color(w, x, r):
    if x and w:
        return bcolors.BLUE
    if x:
        return bcolors.RED
    if w:
        return bcolors.GREEN
    if r:
        return bcolors.LGREY
    return bcolors.BLACK

def create_compound_filter(filters):
    def apply_filters(p):
        res = True
        for func in filters:
            res = res and func(p)
        return res
    return apply_filters

def search_memory(machine, page_ranges, to_search, to_search_num, aligned_to, aligned_offset):
    done_searching = False
    for range in page_ranges:
        if done_searching:
            break

        data = None
        try:
            data = range.read_memory(machine)
        except OSError:
            pass

        if data is not None:
            idx = 0
            while True:
                idx = data.find(to_search, idx)
                if idx != -1:
                    if (idx - aligned_offset) % aligned_to == 0:
                        yield (range.va + idx, range)
                        to_search_num = to_search_num - 1
                        if to_search_num == 0:
                            done_searching = True
                            break
                    idx = idx + 1
                else:
                    break
    return None

def find_aliases(virtual_page_ranges, phys_verobse):
    # First collect the physical ranges, aka inverse virtual map
    phys_ranges = []
    i = 0
    for range in virtual_page_ranges:
        virtual_page_range_base = range.va
        off = 0
        for phys_range, phys_range_size in zip(range.phys, range.sizes):
            phys_ranges.append((phys_range, phys_range + phys_range_size, virtual_page_range_base + off))
            off = off + phys_range_size

    # Sort the physical ranges
    phys_ranges = sorted(phys_ranges, key=lambda key: key[0])

    # TODO
    # We could use bisect here to speed-up
    # The first loop can be simplified
    # The object copy is a hack
    # The check for previous occ is not elegant
    overlaps_dict = {}
    for range in virtual_page_ranges:
        base_va = range.va
        off = 0
        for phys_range, phys_range_size in zip(range.phys, range.sizes):
            phys_range_end = phys_range + phys_range_size
            for saved_range in phys_ranges:
                if saved_range[0] > phys_range_end:
                    break
                beg = max(phys_range, saved_range[0]) 
                end = min(phys_range_end, saved_range[1]) 
                va = base_va + off + (beg - phys_range)
                if beg < end and va != saved_range[2]:
                    key = (beg, end)
                    # Make copy and clean-up
                    range_copy = copy.copy(range)
                    range_copy.phys = None
                    range_copy.size = None
                    range_copy.va = va
                    range_copy.page_size = end - beg
                    if key in overlaps_dict:
                        found = False
                        for tmp in overlaps_dict[key]:
                            if tmp.va == va:
                                found = True
                                break
                        if not found:
                            overlaps_dict[key].append(range_copy)
                    else:
                        overlaps_dict[key] = [range_copy]
            off = off + phys_range_size

    # Print the found aliases
    for key in overlaps_dict.keys():
        overlaps = overlaps_dict[key]
        if len(overlaps) > 1:
            print(f"Phys: {hex(key[0])} - {hex(key[1])}")
            overlap_len = key[1] - key[0]
            for overlap in overlaps:
                print(" " * 4 + overlap.to_string(phys_verbose))
            print("")

class PageTableWalkInfo():

    def __init__(self, va):
        self.va = va
        self.faulted = False
        self.stages = []

    def add_register_stage(self, register_name, register_value):
        self.base_register = (register_name, register_value)

    def add_stage(self, stage_str, table_index, entry_value_without_meta, meta_bits):
        self.stages.append((stage_str, table_index, entry_value_without_meta, meta_bits))

    def set_faulted(self):
        self.faulted = True

    def __str__(self):
        s = ""

        s += f"Page table walk for VA = {hex(self.va)}\n"
        s += "-" * 43 + "\n"

        s += f"{self.base_register[0]} = {hex(self.base_register[1])}\n"

        for (stage_index, stage_entry) in enumerate(self.stages):
            stage_str, table_index, entry_value_without_meta, meta_bits = stage_entry
            stage_index = stage_index + 1
            mapping_string = " " * stage_index * 2 + f"{stage_str}[{table_index}] = {hex(entry_value_without_meta)}"
            flags_string = f"Flags 0x{meta_bits:03x}"
            s += mapping_string.ljust(34) + "| " + flags_string + "\n"

        if self.faulted:
            s += "\n!!! Last stage faulted !!!\n"

        return s
