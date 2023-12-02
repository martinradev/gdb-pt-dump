#!/usr/bin/env python3

import subprocess
import socket
import os
import time
import copy
import re
import json
import tempfile

_DEFAULT_QEMU_MONITOR_PORT=55555
_DEFAULT_QEMU_GDB_PORT=1234

# TODO: add images to github and write a downloader script
class ImageContainer:
    def __init__(self):
        self.images_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "images")

    def get_linux_x86_64(self):
        return os.path.join(self.images_dir, "linux_x86_64")

class VM:
    def __init__(self):
        self.vm_proc = None

    def __del__(self):
        self.stop()

    def start(self, cmd):
        self.vm_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def wait_for_shell(self, shell_symbol="~"):
        line = b""
        while True:
            b = self.vm_proc.stdout.read(1)
            if b == b"":
                continue
            line += b
            if b == b"\n":
                match = re.search(b'Boot took (.*) seconds', line)
                if match:
                    return
                line = b""

    def stop(self):
        if self.vm_proc:
            self.vm_proc.kill()
            self.vm_proc = None

    def is_alive(self):
        if not self.vm_proc:
            return False
        return self.vm_proc.poll() == None

class VM_X86_64(VM):
    def __init__(self, image_dir):
        super().__init__()
        self.image_dir = image_dir

    def start(self, memory_mib=64, kvm=False, smep=True, smap=True, kaslr=True, svm=False, num_cores=1):
        cmd = []
        cmd.extend(["qemu-system-x86_64"])

        cpu_options = []
        if kvm:
            cpu_options.append("kvm64")
        else:
            cpu_options.append("qemu64")

        if smep:
            cpu_options.append("+smep")
        else:
            cpu_options.append("-smep")

        if smap:
            cpu_options.append("+smap")
        else:
            cpu_options.append("-smap")

        if svm:
            cpu_options.append("+svm")

        cmd.extend(["-cpu", ",".join(cpu_options)])

        kernel_image = os.path.join(self.image_dir, "kernel.img")
        cmd.extend(["-kernel", kernel_image])

        initrd_image = os.path.join(self.image_dir, "initrd.img")
        cmd.extend(["-initrd", initrd_image])

        cmd.extend(["-m", str(memory_mib)])

        boot_string = "console=ttyS0 oops=panic ip=dhcp root=/dev/ram rdinit=/init quiet"
        if kaslr:
            boot_string += " kaslr"
        else:
            boot_string += " nokaslr"

        cmd.extend(["-append", boot_string])

        cmd.extend(["-qmp", f"tcp:localhost:{_DEFAULT_QEMU_MONITOR_PORT},server,nowait"])

        cmd.extend(["-nographic", "-snapshot", "-no-reboot"])

        cmd.extend(["-smp", str(num_cores)])

        cmd.extend(["-s"])

        super().start(cmd)

class QemuMonitorExecutor:

    def __init__(self, qemu_server_port):
        self.qemu_server_port = qemu_server_port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect(("localhost", qemu_server_port))

        _header = self.read_line()
        self.socket.sendall(b'{ "execute": "qmp_capabilities" }\n')
        self.read_line()

    def __del__(self):
        if self.socket:
            self.socket.shutdown(socket.SHUT_WR)
            self.socket.close()

    def _read_memory(self, addr, len, is_virt):
        exec = ""
        if is_virt:
            exec = "memsave"
        else:
            exec = "pmemsave"
        filename = "/tmp/tmp.bin"
        if os.path.isfile(filename):
            os.remove(filename)

        # The QMP memsave and pmemsave require signed integers for the address and length.
        # Thus, using cannonical addresses requires translating them to a signed integer.

        if (addr & (1 << 63)) != 0:
            addr = addr - (1 << 64)

        cmd = json.dumps({"execute": exec,"arguments":{"val":addr, "size":len, "filename": filename}})
        self.socket.sendall(cmd.encode("utf-8") + b"\n")
        res = json.loads(self.read_line())
        if "error" in res:
            print(res, cmd)
            return None
        assert("return" in res)
        data = b""
        with open(filename, "rb") as f:
            data = f.read()
        os.remove(filename)
        return data

    def pause(self):
        cmd = json.dumps({"execute": "stop"})
        self.socket.sendall(cmd.encode("utf-8") + b"\n")
        res = json.loads(self.read_line())
        assert("error" not in res)
        line = self.read_line()
        assert("error" not in line)

    def resume(self):
        cmd = json.dumps({"execute": "cont"})
        self.socket.sendall(cmd.encode("utf-8") + b"\n")
        res = json.loads(self.read_line())
        assert("return" in res)

    def read_virt_memory(self, addr, len):
        return self._read_memory(addr, len, True)

    def read_phys_memory(self, addr, len):
        return self._read_memory(addr, len, False)

    def run_cmd(self, monitor_cmd):
        self.socket.sendall(monitor_cmd.encode("utf-8") + b"\n")

    def read_line(self):
        line = b""
        while True:
            b = self.socket.recv(1)
            if b != b"":
                line += b
            if b == b"\n":
                break
        return line.decode("utf-8")

class GdbCommandExecutor:

    class Result:
        def __init__(self, output, elapsed):
            self.output = output
            self.elapsed = elapsed

    def __init__(self, gdb_server_port):
        self.gdb_server_port = gdb_server_port

    def run_cmd(self, pt_cmd):
        cmd = []
        cmd.extend(["gdb"])
        cmd.extend(["-q"])
        cmd.extend(["-ex", f"target remote :{self.gdb_server_port}"])
        cmd.extend(["-ex", pt_cmd])
        cmd.extend(["-ex", "quit"])
        t1 = time.time()
        result = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode("utf-8")
        t2 = time.time()
        if "error" in result.lower() or "exception" in result.lower():
            raise Exception(f"Executuing command failed: '{result}'")
        elapsed = t2 - t1
        return GdbCommandExecutor.Result(result, elapsed)

class MetaFlags():
    def __init__(self):
        pass

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

def test_pt_smoke():
    vm = VM_X86_64(ImageContainer().get_linux_x86_64())
    vm.start()
    vm.wait_for_shell()
    gdb = GdbCommandExecutor(_DEFAULT_QEMU_GDB_PORT)
    res = gdb.run_cmd("pt")

def test_pt_filter_smoke():
    vm = VM_X86_64(ImageContainer().get_linux_x86_64())
    vm.start()
    vm.wait_for_shell()
    gdb = GdbCommandExecutor(_DEFAULT_QEMU_GDB_PORT)
    gdb.run_cmd("pt")
    gdb.run_cmd("pt -filter x")
    gdb.run_cmd("pt -filter w")
    gdb.run_cmd("pt -filter ro")
    gdb.run_cmd("pt -filter w|x")
    gdb.run_cmd("pt -filter u")
    gdb.run_cmd("pt -filter s")
    gdb.run_cmd("pt -filter w x")

def test_pt_kaslr_smoke():
    vm = VM_X86_64(ImageContainer().get_linux_x86_64())
    vm.start()
    vm.wait_for_shell()
    gdb = GdbCommandExecutor(_DEFAULT_QEMU_GDB_PORT)
    res = gdb.run_cmd("pt -kaslr")

def ansi_escape(line):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', line)

def parse_va_range_x86(line):
    pattern = r"\s*([0-9a-fA-Fx]+)\s*:\s*([0-9a-fA-Fx]+)\s*\|\s*W:(\d+)\s*X:(\d+)\s*S:(\d+)\s*UC:(\d+)\s*WB:(\d+)"
    line = ansi_escape(line)
    match = re.match(pattern, line)
    if match:
        range_va, range_size, flag_w, flag_x, flag_s, flag_uc, flag_wb = match.groups()
        flags = MetaFlagsX86(w=bool(int(flag_w)), x=bool(int(flag_x)), s=bool(int(flag_s)), uc=bool(int(flag_uc)), wb=bool(int(flag_wb)))
        virt_range = VirtRange(int(range_va, 16), int(range_size, 16), flags)
        return virt_range
    return None

def parse_va_ranges(command_output):
    lines = command_output.split("\n")
    ranges = []
    for line in lines:
        range_info = parse_va_range_x86(line)
        if range_info:
            ranges.append(range_info)
    return ranges

def parse_occurrences_x86(command_output):
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

def verify_all_search_occurrences(monitor, occs, mem_len, checker):
    for occ in occs:
        memory = monitor.read_virt_memory(occ.occ_va, mem_len)
        assert(checker(occ, memory))

def _test_pt_search(search_command, mem_len, checker):
    vm = VM_X86_64(ImageContainer().get_linux_x86_64())
    vm.start()
    vm.wait_for_shell()
    gdb = GdbCommandExecutor(_DEFAULT_QEMU_GDB_PORT)

    res = gdb.run_cmd(search_command)

    monitor = QemuMonitorExecutor(_DEFAULT_QEMU_MONITOR_PORT)
    monitor.pause()

    occs = parse_occurrences_x86(res.output)
    assert(len(occs) > 0)

    verify_all_search_occurrences(monitor, occs, mem_len, checker)

def test_pt_search_string():
    checker = lambda _, mem: mem == b"Linux"
    _test_pt_search("pt -ss Linux", 5, checker)

def test_pt_search_s4():
    checker = lambda _, mem: mem == b"\x41\x41\x41\x41"
    _test_pt_search("pt -s4 0x41414141", 4, checker)

def test_pt_search_s8():
    checker = lambda _, mem: mem == b"\xfe\xff\xff\xff\xff\xff\xff\xff"
    _test_pt_search("pt -s8 0xfffffffffffffffe", 8, checker)

def test_pt_range_exists():
    vm = VM_X86_64(ImageContainer().get_linux_x86_64())
    vm.start()
    vm.wait_for_shell()
    gdb = GdbCommandExecutor(_DEFAULT_QEMU_GDB_PORT)

    res = gdb.run_cmd(f"pt")
    monitor = QemuMonitorExecutor(_DEFAULT_QEMU_MONITOR_PORT)
    monitor.pause()

    ranges = parse_va_ranges(res.output)
    assert(len(ranges) > 0)
    for r in ranges:
        data = monitor.read_virt_memory(r.va_start, 4)
        assert(len(data) == 4)

        data = monitor.read_virt_memory(r.va_start + int(r.length / 2), 4)
        assert(len(data) == 4)

        data = monitor.read_virt_memory(r.va_start + r.length - 4, 4)
        assert(len(data) == 4)

def _test_pt_filter_common_x86(executions):
    vm = VM_X86_64(ImageContainer().get_linux_x86_64())
    vm.start()
    vm.wait_for_shell()
    gdb = GdbCommandExecutor(_DEFAULT_QEMU_GDB_PORT)
    monitor = QemuMonitorExecutor(_DEFAULT_QEMU_MONITOR_PORT)

    for (_cmd, _check) in executions:
        print(f"Running {_cmd}")
        res = gdb.run_cmd(_cmd)
        monitor.pause()

        ranges = parse_va_ranges(res.output)
        assert(len(ranges) > 0)
        for r in ranges:
            assert(_check(r))

def test_pt_filter_executable_x86():
    executions = [("pt -filter x", lambda r: r.flags.x == True), ("pt -filter _x", lambda r: r.flags.x == False)]
    _test_pt_filter_common_x86(executions)

def test_pt_filter_writeable_x86():
    executions = [("pt -filter w", lambda r: r.flags.w == True), ("pt -filter _w", lambda r: r.flags.w == False)]
    _test_pt_filter_common_x86(executions)

def test_pt_filter_read_only_x86():
    executions = [("pt -filter ro", lambda r: r.flags.x == False and r.flags.w == False)]
    _test_pt_filter_common_x86(executions)

def test_pt_filter_user_accessible_x86():
    executions = [("pt -filter u", lambda r: r.flags.s == False), ("pt -filter _u", lambda r: r.flags.s == True)]
    _test_pt_filter_common_x86(executions)

def test_pt_filter_kernel_only_accessible_x86():
    executions = [("pt -filter s", lambda r: r.flags.s == True), ("pt -filter _s", lambda r: r.flags.s == False)]
    _test_pt_filter_common_x86(executions)

def test_pt_filter_multiple_filters_x86():
    executions = [ \
                  ("pt -filter x u", lambda r: r.flags.x == True and r.flags.s == False), \
                  ("pt -filter w s", lambda r: r.flags.w == True and r.flags.s == True), \
                  ("pt -filter x s", lambda r: r.flags.x == True and r.flags.s == True), \
                 ]
    _test_pt_filter_common_x86(executions)

def test_pt_filter_and_search_x86():
    checker = lambda occ, data: occ.virt_range.flags.w == True and data == b"Linux"
    _test_pt_search("pt -ss Linux -filter w", 5, checker)

    checker = lambda occ, data: occ.virt_range.flags.w == False and occ.virt_range.flags.x == False and data == b"Linux"
    _test_pt_search("pt -ss Linux -filter ro", 5, checker)

def test_pt_range_command():
    vm = VM_X86_64(ImageContainer().get_linux_x86_64())
    vm.start()
    vm.wait_for_shell()
    gdb = GdbCommandExecutor(_DEFAULT_QEMU_GDB_PORT)
    monitor = QemuMonitorExecutor(_DEFAULT_QEMU_MONITOR_PORT)

    res = gdb.run_cmd("pt")
    ranges = parse_va_ranges(res.output)
    assert(len(ranges) > 10)

    r0, r1, r2, r3 = ranges[0:4]

    # cover first range only
    res = gdb.run_cmd(f"pt -range {r0.va_start} {r0.va_start + r0.length}")
    subranges = parse_va_ranges(res.output)
    assert(len(subranges) == 1)
    assert(subranges[0] == r0)

    # cover first range partially
    res = gdb.run_cmd(f"pt -range {r0.va_start + 0x1} {r0.va_start + r0.length}")
    subranges = parse_va_ranges(res.output)
    assert(len(subranges) == 0)

    # cover range 2 partially
    res = gdb.run_cmd(f"pt -range {r0.va_start + 0x1} {r1.va_start}")
    subranges = parse_va_ranges(res.output)
    assert(len(subranges) == 1)
    assert(subranges[0] == r1)

    # cover ranges 0, 1, 2
    res = gdb.run_cmd(f"pt -range {r0.va_start} {r2.va_start}")
    subranges = parse_va_ranges(res.output)
    assert(len(subranges) == 3)
    assert(subranges[0] == r0)
    assert(subranges[1] == r1)
    assert(subranges[2] == r2)

    # cover ranges 1, 2, 3
    res = gdb.run_cmd(f"pt -range {r1.va_start} {r3.va_start}")
    subranges = parse_va_ranges(res.output)
    assert(len(subranges) == 3)
    assert(subranges[0] == r1)
    assert(subranges[1] == r2)
    assert(subranges[2] == r3)

    # end before start
    res = gdb.run_cmd(f"pt -range 0x40000 0x30000")
    subranges = parse_va_ranges(res.output)
    assert(len(subranges) == 0)

def test_pt_has_command():
    vm = VM_X86_64(ImageContainer().get_linux_x86_64())
    vm.start()
    vm.wait_for_shell()
    gdb = GdbCommandExecutor(_DEFAULT_QEMU_GDB_PORT)
    monitor = QemuMonitorExecutor(_DEFAULT_QEMU_MONITOR_PORT)

    res = gdb.run_cmd("pt")
    ranges = parse_va_ranges(res.output)
    assert(len(ranges) > 10)

    r0, r1, r2, r3 = ranges[0:4]

    res = gdb.run_cmd(f"pt -has {r0.va_start}")
    subranges = parse_va_ranges(res.output)
    assert(len(subranges) == 1)
    assert(subranges[0] == r0)

    res = gdb.run_cmd(f"pt -has {r0.va_start + 1}")
    subranges = parse_va_ranges(res.output)
    assert(len(subranges) == 1)
    assert(subranges[0] == r0)

    res = gdb.run_cmd(f"pt -has {r0.va_start + r0.length - 1}")
    subranges = parse_va_ranges(res.output)
    assert(len(subranges) == 1)
    assert(subranges[0] == r0)

    res = gdb.run_cmd(f"pt -has {r1.va_start}")
    subranges = parse_va_ranges(res.output)
    assert(len(subranges) == 1)
    assert(subranges[0] == r1)

    res = gdb.run_cmd(f"pt -has {ranges[-1].va_start + ranges[-1].length - 1}")
    subranges = parse_va_ranges(res.output)
    assert(len(subranges) == 1)
    assert(subranges[0] == ranges[-1])

    res = gdb.run_cmd(f"pt -has {ranges[-1].va_start + ranges[-1].length}")
    subranges = parse_va_ranges(res.output)
    assert(len(subranges) == 0)

def test_pt_before_command():
    vm = VM_X86_64(ImageContainer().get_linux_x86_64())
    vm.start()
    vm.wait_for_shell()

    gdb = GdbCommandExecutor(_DEFAULT_QEMU_GDB_PORT)
    monitor = QemuMonitorExecutor(_DEFAULT_QEMU_MONITOR_PORT)

    res = gdb.run_cmd("pt")
    ranges = parse_va_ranges(res.output)
    assert(len(ranges) > 10)

    r0, r1, r2, r3 = ranges[0:4]

    res = gdb.run_cmd(f"pt -before {r0.va_start}")
    subranges = parse_va_ranges(res.output)
    assert(len(subranges) == 0)

    res = gdb.run_cmd(f"pt -before {r0.va_start + r0.length}")
    subranges = parse_va_ranges(res.output)
    assert(len(subranges) == 1)
    assert(subranges[0] == r0)

    res = gdb.run_cmd(f"pt -before {r0.va_start + 0x100}")
    subranges = parse_va_ranges(res.output)
    assert(len(subranges) == 1)
    r_tmp = copy.deepcopy(r0)
    r_tmp.length = 0x100
    assert(subranges[0] == r_tmp)

    res = gdb.run_cmd(f"pt -before {r2.va_start + r2.length}")
    subranges = parse_va_ranges(res.output)
    assert(len(subranges) == 3)
    assert(subranges[0] == r0)
    assert(subranges[1] == r1)
    assert(subranges[2] == r2)

    res = gdb.run_cmd(f"pt -before {r3.va_start + r3.length - 0x100}")
    subranges = parse_va_ranges(res.output)
    assert(len(subranges) == 4)
    assert(subranges[0] == r0)
    assert(subranges[1] == r1)
    assert(subranges[2] == r2)
    r_tmp = copy.deepcopy(r3)
    r_tmp.length = r3.length - 0x100
    assert(subranges[3] == r_tmp)

    res = gdb.run_cmd(f"pt -before {ranges[-1].va_start + ranges[-1].length}")
    subranges = parse_va_ranges(res.output)
    assert(subranges == ranges)

def test_pt_after_command():
    vm = VM_X86_64(ImageContainer().get_linux_x86_64())
    vm.start()
    vm.wait_for_shell()

    gdb = GdbCommandExecutor(_DEFAULT_QEMU_GDB_PORT)
    monitor = QemuMonitorExecutor(_DEFAULT_QEMU_MONITOR_PORT)

    res = gdb.run_cmd("pt")
    ranges = parse_va_ranges(res.output)
    assert(len(ranges) > 10)

    res = gdb.run_cmd(f"pt -after {ranges[-1].va_start}")
    subranges = parse_va_ranges(res.output)
    assert(subranges == [ranges[-1]])

    res = gdb.run_cmd(f"pt -after {ranges[-1].va_start + ranges[-1].length}")
    subranges = parse_va_ranges(res.output)
    assert(subranges == [])

    res = gdb.run_cmd(f"pt -after {ranges[-1].va_start + 0x100}")
    subranges = parse_va_ranges(res.output)
    r_tmp = copy.deepcopy(ranges[-1])
    r_tmp.va_start += 0x100
    r_tmp.length = ranges[-1].length - 0x100
    assert(subranges == [r_tmp])

    res = gdb.run_cmd(f"pt -after {ranges[0].va_start}")
    subranges = parse_va_ranges(res.output)
    assert(subranges == ranges)

def test_pt_before_after_combination():
    vm = VM_X86_64(ImageContainer().get_linux_x86_64())
    vm.start()
    vm.wait_for_shell()

    gdb = GdbCommandExecutor(_DEFAULT_QEMU_GDB_PORT)
    monitor = QemuMonitorExecutor(_DEFAULT_QEMU_MONITOR_PORT)

    res = gdb.run_cmd("pt")
    ranges = parse_va_ranges(res.output)
    assert(len(ranges) > 10)

    res = gdb.run_cmd(f"pt -after {ranges[0].va_start} -before {ranges[-1].va_start + ranges[-1].length}")
    subranges = parse_va_ranges(res.output)
    assert(subranges == ranges)

    res = gdb.run_cmd(f"pt -after {ranges[1].va_start} -before {ranges[-1].va_start}")
    subranges = parse_va_ranges(res.output)
    assert(subranges == ranges[1:-1])

    res = gdb.run_cmd(f"pt -after {ranges[2].va_start} -before {ranges[3].va_start}")
    subranges = parse_va_ranges(res.output)
    assert(subranges == [ranges[2]])

    res = gdb.run_cmd(f"pt -after {ranges[2].va_start} -before {ranges[3].va_start + ranges[3].length}")
    subranges = parse_va_ranges(res.output)
    assert(subranges == ranges[2:4])

    res = gdb.run_cmd(f"pt -after {ranges[2].va_start + 0x200} -before {ranges[4].va_start + 0x300}")
    subranges = parse_va_ranges(res.output)

    r2_tmp = copy.deepcopy(ranges[2])
    r2_tmp.va_start += 0x200
    r2_tmp.length = r2_tmp.length - 0x200
    r4_tmp = copy.deepcopy(ranges[4])
    r4_tmp.length = 0x300
    assert(subranges == [r2_tmp, ranges[3], r4_tmp])

def test_pt_kaslr_x86():
    virt_pattern = re.compile(r'Virt:\s+([0-9a-fA-Fx]+)')
    phys_pattern = re.compile(r'Phys:\s+([0-9a-fA-Fx]+)')

    vm = VM_X86_64(ImageContainer().get_linux_x86_64())
    vm.start(kaslr=False)
    vm.wait_for_shell()

    gdb = GdbCommandExecutor(_DEFAULT_QEMU_GDB_PORT)

    res = gdb.run_cmd("pt -kaslr")
    output = ansi_escape(res.output)
    virt_matches = virt_pattern.findall(output)
    phys_matches = phys_pattern.findall(output)

    assert(int(virt_matches[0], 16) == 0xffffffff81000000)
    assert(int(phys_matches[0], 16) == 0x1000000)
    assert(int(virt_matches[1], 16) == 0xffff888000000000)

    del gdb
    vm.stop()

    for u in range(4):
        vm.start(kaslr=True)
        vm.wait_for_shell()
        gdb = GdbCommandExecutor(_DEFAULT_QEMU_GDB_PORT)
        res = gdb.run_cmd("pt -kaslr")
        output = ansi_escape(res.output)
        virt_matches = virt_pattern.findall(output)
        phys_matches = phys_pattern.findall(output)
        assert(int(virt_matches[0], 16) != 0)
        assert(int(phys_matches[0], 16) != 0)
        assert(int(virt_matches[1], 16) != 0)

        del gdb
        vm.stop()

if __name__ == "__main__":
    print("This code should be invoked via 'pytest':", file=sys.stderr)
    print("")
    print("    pytest run_integration_tests.py")
    print("")
