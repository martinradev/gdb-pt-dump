import gdb
from collections import namedtuple
import copy

class bcolors:
    RED     = '\033[41m'
    BLUE    = '\033[44m'
    GREEN   = '\033[42m'
    CYAN    = '\033[106m'
    MAGENTA = '\033[105m'
    BLACK   = '\033[40m'
    YELLOW  = '\033[103m'
    LGREY   = '\033[47m'
    ENDC    = '\033[0m'

class SupportedArch:
    aarch64 = 1,
    x86_64 = 2,

def extract(value, s, e):
    return extract_no_shift(value, s, e) >> s

def extract_no_shift(value, s, e):
    mask = ((1<<(e + 1))-1) & ~((1<<s) - 1)
    return (value & mask)

def read_n_pa64(phys_memory, addr, n):
    mem = phys_memory.read(addr, n * 8)
    values = []
    for u in range(0, len(mem), 8):
        values.append(int.from_bytes(mem[u:u+8], 'little'))
    return values

def read_arbitrary_page(phys_memory, addr, page_size):
    n = int(page_size / 8)
    return read_n_pa64(phys_memory, addr, n)

def read_page(phys_memory, addr):
    return read_arbitrary_page(phys_memory, addr, 4096)

def read_64k_page(phys_memory, addr):
    return read_arbitrary_page(phys_memory, addr, 64 * 1024)

def make_canonical(va, top_bit_pos = 47):
    bit = (va >> top_bit_pos) & 0x1
    mask = ((((2**64)-1) >> top_bit_pos) * bit) << top_bit_pos
    return va | mask

PagePrintSettings = namedtuple('PagePrintSettings', ['va_len', 'page_size_len'])

class Page():
    def __init__(self):
        self.va = None
        self.pa = None
        self.page_size = None
        self.w = None
        self.x = None
        self.s = None
        self.wb = None
        self.uc = None
        self.phys = None
        self.sizes = None

    def __str__(self):
        conf = PagePrintSettings(va_len = 18, page_size_len = 8)
        return page_to_str(self, conf)

    def read_memory(self, phys_mem):
        memory = b""
        for phys_range_start, phys_range_size in zip(self.phys, self.sizes):
            memory += phys_mem.read(phys_range_start, phys_range_size)
        return memory

class GenericPageRangeNoAttr():
    def __init__(self, va, size):
        self.va = va
        self.size = size

def page_to_str(page: Page, conf: PagePrintSettings):
    prefix = ""
    if not page.s:
        prefix = bcolors.CYAN + " " + bcolors.ENDC
    elif page.s:
        prefix = bcolors.MAGENTA + " " + bcolors.ENDC

    fmt = f"{{:>{conf.va_len}}} : {{:>{conf.page_size_len}}}"
    varying_str = fmt.format(hex(page.va), hex(page.page_size))
    s = f"{varying_str} | W:{int(page.w)} X:{int(page.x)} S:{int(page.s)} UC:{int(page.uc)} WB:{int(page.wb)}"

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

def merge_cont_pages(pages, func_semantic_sim):
    if len(pages) <= 1:
        return pages

    # Here I am just going to abuse the Page structure to contain the range
    merged_pages = []
    cur_page = copy.copy(pages[0])
    for page in pages[1:]:
        if cur_page.va + cur_page.page_size == page.va and func_semantic_sim(cur_page, page):
            cur_page.page_size = cur_page.page_size + page.page_size
            if cur_page.phys[-1] + cur_page.sizes[-1] == page.phys[0]:
                # Simply extend phys as well if they are physicall contiguous
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

def optimize(gig_pages, mb_pages, kb_pages, func_semantic_sim):
    pages = sorted(gig_pages + mb_pages + kb_pages, key = lambda p: p.va)
    opt = merge_cont_pages(pages, func_semantic_sim)
    return opt

def compute_max_str_len(pages):
    max_page_size_len = 0
    max_va_len = 0
    for page in pages:
        max_va_len = max(max_va_len, len(hex(page.va)))
        max_page_size_len = max(max_page_size_len, len(hex(page.page_size)))
    return max_va_len, max_page_size_len

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

def search_memory(phys_mem, page_ranges, to_search, to_search_num, aligned_to, aligned_offset):
    th = gdb.selected_inferior()
    done_searching = False
    for range in page_ranges:
        if done_searching:
            break
        try:
            data = range.read_memory(phys_mem)
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
        except (gdb.MemoryError, OSError):
            pass
    return None

