import gdb
from collections import namedtuple
from pt_common import *

PT_Register_Range = namedtuple('PT_Register_Range', ['name', 'low', 'high', 'func'])

class PT_Register_State:
    def __init__(self, short_name, name, kv):
        self.short_name = short_name
        self.name = name
        self.kv = kv

    def __str__(self):
        s = ""
        total = 148
        s += bcolors.BLUE + f"{self.short_name} ({self.name}):".ljust(total) +  bcolors.ENDC  + "\n"
        delim = "|"
        for key in self.kv:
            value, low, high, res  = self.kv[key]
            s += f"    {key}".ljust(10) + " (" + f"{low}".rjust(2) + ":" + f"{high}".rjust(2) + ") = " + hex(res).rjust(4) + " " + delim + f" {value} ".ljust(128) + "\n"
        s += "-" * total + "\n"
        return s

    def get_value(self, key):
        return self.kv[key][3]

class PT_Decipher_Meaning_Match:
    def __init__(self, kv):
        self.kv = kv

    def __call__(self, key):
        return self.kv[key]

PT_Decipher_Meaning_Passthrough = lambda x: x

class PT_Register:
    def __init__(self, register, name):
        self.register = register
        self.name = name
        self.ranges_dict = {}

    def add_range(self, name, low, high, decipher_meaning):
        self.ranges_dict[name] = PT_Register_Range(name = name, low = low, high = high, func = decipher_meaning)

    def check(self):
        reg_value = int(gdb.parse_and_eval(f"${self.register}").cast(gdb.lookup_type("unsigned long")))
        kv = dict()
        for key in self.ranges_dict:
            r = self.ranges_dict[key]
            res = extract(reg_value, r.low, r.high)
            kv[r.name] = (r.func(res), r.low, r.high, res)
        return PT_Register_State(self.register, self.name, kv)

    def __getattr__(self, attr):
        return self.check().get_value(str(attr))

