import gdb
from collections import namedtuple

class bcolors:
    RED     = '\033[41m'
    BLUE    = '\033[44m'
    GREEN   = '\033[42m'
    CYAN    = '\033[106m'
    MAGENTA = '\033[105m'
    ENDC    = '\033[0m'

def read_pa64(addr):
    res = gdb.execute(f"monitor xp /xg {hex(addr)}", to_string = True)
    i = res.find(" ")
    value = int(res[i+1:], 16)
    return value

def read_page(addr):
    res = gdb.execute(f"monitor xp /512xg {hex(addr)}", to_string = True)
    lines = res.split("\n")
    values = []
    for line in lines[:-1]:
        tokens = line.split(" ")
        values.append(int(tokens[1], 16))
        values.append(int(tokens[2], 16))
    return values

def make_canonical(va):
    bit = (va >> 47) & 0x1
    mask = ((((2**64)-1) >> 47) * bit) << 47
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

def page_to_str(page: Page, conf: PagePrintSettings):
    fmt = f"{{:>{conf.va_len}}} : {{:>{conf.page_size_len}}}"
    varying_str = fmt.format(hex(page.va), hex(page.page_size))
    s = f"{varying_str} | W:{int(page.w)} X:{int(page.x)} S:{int(page.s)} UC:{int(page.uc)} WB:{int(page.wb)}"
    return s
