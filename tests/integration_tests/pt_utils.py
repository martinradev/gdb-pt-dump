
from abc import ABC, abstractmethod
import re

class MetaFlags(ABC):
    def __init__(self):
        pass

    @abstractmethod
    def executable(self):
        raise Exception("Unimplemented")

    @abstractmethod
    def writeable(self):
        raise Exception("Unimplemented")

    @abstractmethod
    def user_accessible(self):
        raise Exception("Unimplemented")

    @abstractmethod
    def user_writeable(self):
        raise Exception("Unimplemented")

    @abstractmethod
    def user_executable(self):
        raise Exception("Unimplemented")

    @abstractmethod
    def super_accessible(self):
        raise Exception("Unimplemented")

    @abstractmethod
    def super_writeable(self):
        raise Exception("Unimplemented")

    @abstractmethod
    def super_executable(self):
        raise Exception("Unimplemented")


class MetaFlagsX86(MetaFlags):
    def __init__(self, w, x, s, uc, wb):
        super().__init__()
        self.w = w
        self.x = x
        self.s = s
        self.uc = uc
        self.wb = wb

    def __eq__(self, other):
        fields = ["w", "x", "s", "uc", "wb"]
        return all(getattr(self, attr) == getattr(other, attr) for attr in fields)

    def executable(self):
        return self.x

    def writeable(self):
        return self.w

    def user_accessible(self):
        return not self.s

    def user_writeable(self):
        return self.user_accessible() and self.w

    def user_executable(self):
        return self.user_accessible() and self.w

    def super_accessible(self):
        return self.s

    def super_writeable(self):
        return self.super_accessible() and self.w

    def super_executable(self):
        return self.super_accessible() and self.x

class MetaFlagsArm64(MetaFlags):
    def __init__(self, ur, uw, ux, sr, sw, sx):
        super().__init__()
        self.ur = ur
        self.uw = uw
        self.ux = ux
        self.sr = sr
        self.sw = sw
        self.sx = sx

    def __eq__(self, other):
        fields = ["ur", "uw", "ux", "sr", "sw", "sx"]
        return all(getattr(self, attr) == getattr(other, attr) for attr in fields)

    def executable(self):
        return self.ux or self.sx

    def writeable(self):
        return self.uw or self.sw

    def user_accessible(self):
        return any([self.ur, self.uw, self.ux])

    def user_writeable(self):
        return self.uw

    def user_executable(self):
        return self.ux

    def super_accessible(self):
        return any([self.sr, self.sw, self.sx])

    def super_writeable(self):
        return self.sw

    def super_executable(self):
        return self.sx

class MetaFlagsRiscv(MetaFlags):
    def __init__(self, r, w, x, s):
        super().__init__()
        self.r = r
        self.w = w
        self.x = x
        self.s = s

    def __eq__(self, other):
        fields = ["r", "w", "x", "s"]
        return all(getattr(self, attr) == getattr(other, attr) for attr in fields)

    def executable(self):
        return self.x

    def writeable(self):
        return self.w

    def user_accessible(self):
        return any([self.r, self.w, self.x]) and not self.s

    def user_writeable(self):
        return self.w and not self.s

    def user_executable(self):
        return self.w and not self.s

    def super_accessible(self):
        return any([self.r, self.w, self.x]) and self.s

    def super_writeable(self):
        return self.w and self.s

    def super_executable(self):
        return self.x and self.s

class VirtRange():
    def __init__(self, va_start, length, flags):
        self.va_start = va_start
        self.length = length
        self.flags = flags

    def __eq__(self, other):
        fields = ["va_start", "length", "flags"]
        return all(getattr(self, attr) == getattr(other, attr) for attr in fields)

class Occurrence():
    def __init__(self, occ_va, virt_range):
        self.occ_va = occ_va
        self.virt_range = virt_range

def ansi_escape(line):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', line)

def _parse_va_range_x86(line):
    pattern = r"\s*([0-9a-fA-Fx]+)\s*:\s*([0-9a-fA-Fx]+)\s*\|\s*W:(\d+)\s*X:(\d+)\s*S:(\d+)\s*UC:(\d+)\s*WB:(\d+)"
    line = ansi_escape(line)
    match = re.match(pattern, line)
    if match:
        range_va, range_size, flag_w, flag_x, flag_s, flag_uc, flag_wb = match.groups()
        flags = MetaFlagsX86(w=bool(int(flag_w)), x=bool(int(flag_x)), s=bool(int(flag_s)), uc=bool(int(flag_uc)), wb=bool(int(flag_wb)))
        virt_range = VirtRange(int(range_va, 16), int(range_size, 16), flags)
        return virt_range
    return None

def _parse_va_range_arm_64(line):
    pattern = r"\s*([0-9a-fA-Fx]+)\s*:\s*([0-9a-fA-Fx]+)\s*\|\s*W:(\d+)\s*X:(\d+)\s*S:(\d+)\s*UC:(\d+)\s*WB:(\d+)"
    pattern = r"\s*([0-9a-fA-Fx]+)\s*:\s*([0-9a-fA-Fx]+)\s*R:(\d+)\s+W:(\d+)\s+X:(\d+)\s+R:(\d+)\s+W:(\d+)\s+X:(\d+)"
    line = ansi_escape(line)
    match = re.match(pattern, line)
    if match:
        range_va, range_size, flag_user_r, flag_user_w, flag_user_x, flag_super_r, flag_super_w, flag_super_x = match.groups()
        flags = MetaFlagsArm64( \
                               ur=bool(int(flag_user_r)), uw=bool(int(flag_user_w)), ux=bool(int(flag_user_x)), \
                               sr=bool(int(flag_super_r)), sw=bool(int(flag_super_w)), sx=bool(int(flag_super_x)))
        virt_range = VirtRange(int(range_va, 16), int(range_size, 16), flags)
        return virt_range
    return None

def _parse_va_range_riscv(line):
    pattern = r"\s*([0-9a-fA-Fx]+)\s*:\s*([0-9a-fA-Fx]+)\s*\|\s*W:(\d+)\s*X:(\d+)\s*R:(\d+)\s*S:(\d+)"
    line = ansi_escape(line)
    match = re.match(pattern, line)
    if match:
        range_va, range_size, flag_w, flag_x, flag_r, flag_s = match.groups()
        flags = MetaFlagsRiscv(w=bool(int(flag_w)), x=bool(int(flag_x)), s=bool(int(flag_s)), r=bool(int(flag_r)))
        virt_range = VirtRange(int(range_va, 16), int(range_size, 16), flags)
        return virt_range
    return None

def parse_va_ranges(arch, command_output):
    func = None
    if arch == "x86_64":
        func = _parse_va_range_x86
    elif arch == "arm_64":
        func = _parse_va_range_arm_64
    elif arch == "riscv":
        func = _parse_va_range_riscv
    else:
        raise Exception("Unknown architecture")

    lines = command_output.split("\n")
    ranges = []
    for line in lines:
        range_info = func(line)
        if range_info:
            ranges.append(range_info)
    return ranges

def _parse_occurrences_x86(command_output):
    occ_lines = command_output.split("\n")
    pattern = r"Found at (\w+) in\s+(\w+)\s+:\s+(\w+)\s+\|\s+W:(\d+)\s+X:(\d+)\s+S:(\d+)\s+UC:(\d+)\s+WB:(\d+)"
    occs = []
    for line in occ_lines:
        line = ansi_escape(line)
        match = re.match(pattern, line)
        if match:
            found_at, range_va, range_size, flag_w, flag_x, flag_s, flag_uc, flag_wb = match.groups()
            flags = MetaFlagsX86(w=bool(int(flag_w)), x=bool(int(flag_x)), s=bool(int(flag_s)), uc=bool(int(flag_uc)), wb=bool(int(flag_wb)))
            virt_range = VirtRange(int(range_va, 16), int(range_size, 16), flags)
            occ = Occurrence(int(found_at, 16), virt_range)
            occs.append(occ)
    return occs

def _parse_occurrences_arm_64(command_output):
    occ_lines = command_output.split("\n")
    pattern = r"Found at (\w+) in\s+(\w+)\s+:\s+(\w+)\s+R:(\d+)\s+W:(\d+)\s+X:(\d+)\s+R:(\d+)\s+W:(\d+)\s+X:(\d+)"
    occs = []
    for line in occ_lines:
        line = ansi_escape(line)
        match = re.match(pattern, line)
        if match:
            found_at, range_va, range_size, flag_user_r, flag_user_w, flag_user_x, flag_super_r, flag_super_w, flag_super_x = match.groups()
            flags = MetaFlagsArm64( \
                                   ur=bool(int(flag_user_r)), uw=bool(int(flag_user_w)), ux=bool(int(flag_user_x)), \
                                   sr=bool(int(flag_super_r)), sw=bool(int(flag_super_w)), sx=bool(int(flag_super_x)))
            virt_range = VirtRange(int(range_va, 16), int(range_size, 16), flags)
            occ = Occurrence(int(found_at, 16), virt_range)
            occs.append(occ)
    return occs

def _parse_occurrences_riscv(command_output):
    occ_lines = command_output.split("\n")
    pattern = r"Found at (\w+) in\s+(\w+)\s+:\s+(\w+)\s+\|\s+W:(\d+)\s+X:(\d+)\s+R:(\d+)\s+S:(\d+)"
    occs = []
    for line in occ_lines:
        line = ansi_escape(line)
        match = re.match(pattern, line)
        if match:
            found_at, range_va, range_size, flag_w, flag_x, flag_r, flag_s = match.groups()
            flags = MetaFlagsRiscv(w=bool(int(flag_w)), x=bool(int(flag_x)), s=bool(int(flag_s)), r=bool(int(flag_r)))
            virt_range = VirtRange(int(range_va, 16), int(range_size, 16), flags)
            occ = Occurrence(int(found_at, 16), virt_range)
            occs.append(occ)
    return occs

def parse_occurrences(arch, command_output):
    if arch == "x86_64":
        return _parse_occurrences_x86(command_output)
    elif arch == "arm_64":
        return _parse_occurrences_arm_64(command_output)
    elif arch == "riscv":
        return _parse_occurrences_riscv(command_output)
    else:
        raise Exception("Unknown architecture")
