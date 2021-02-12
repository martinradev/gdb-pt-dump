import gdb

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
        s = f"{hex(self.va)} + {hex(self.page_size)} | W:{int(self.w)} X:{int(self.x)} S:{int(self.s)} UC:{int(self.uc)} WB:{int(self.wb)}"
        return s


