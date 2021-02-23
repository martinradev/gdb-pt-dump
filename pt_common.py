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

def read_pa64(addr):
    res = gdb.execute(f"monitor xp /xg {hex(addr)}", to_string = True)
    i = res.find(" ")
    value = int(res[i+1:], 16)
    return value

def read_n_pa64(addr, n):
    res = gdb.execute(f"monitor xp /{n}xg {hex(addr)}", to_string = True)
    lines = res.split("\n")
    values = []
    for line in lines[:-1]:
        tokens = line.split(" ")
        values.append(int(tokens[1], 16))
        values.append(int(tokens[2], 16))
    return values

def read_arbitrary_page(addr, page_size):
    n = int(page_size / 8)
    return read_n_pa64(addr, n)

def read_page(addr):
    return read_arbitrary_page(addr, 4096)

def read_64k_page(addr):
    return read_arbitrary_page(addr, 64 * 1024)

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

    def __str__(self):
        conf = PagePrintSettings(va_len = 18, page_size_len = 8)
        return page_to_str(self, conf)

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
    if len(pages) == 1:
        return pages

    # Here I am just going to abuse the Page structure to contain the range
    merged_pages = []
    cur_page = copy.copy(pages[0])
    for page in pages[1:]:
        if cur_page.va + cur_page.page_size == page.va and func_semantic_sim(cur_page, page):
            cur_page.page_size = cur_page.page_size + page.page_size
        else:
            merged_pages.append(cur_page)
            cur_page = copy.copy(page)
    merged_pages.append(cur_page)
    return merged_pages 

def optimize(gig_pages, mb_pages, kb_pages, func_semantic_sim):
    #opt_pages = merge_cont_pages(sorted(kb_pages, key = lambda p: p.va))
    # Let's not sort them since the kernel likely does the sensible thing
    # But still let's try to merge before sorting. This will often reduce the size by a lot.
    opt_kb_pages = merge_cont_pages(kb_pages, func_semantic_sim)
    pages = sorted(gig_pages + mb_pages + opt_kb_pages, key = lambda p: p.va)
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

