import os
import sys
import subprocess
import re
import time
import socket
import tempfile
import shutil
import shlex
from abc import ABC, abstractmethod

class SocketAllocator:
    def __init__(self):
        self._socket_dir = tempfile.mkdtemp()

    def __del__(self):
        #self.cleanup_all_sockets()
        pass

    def cleanup_all_sockets(self):
        shutil.rmtree(self._socket_dir)

    def alloc_monitor_socket(self):
        return self._alloc_socket("monitor")

    def alloc_gdb_socket(self):
        return self._alloc_socket("gdb")

    def _alloc_socket(self, type_name):
        return tempfile.mkstemp(prefix="{}_".format(type_name), dir=self._socket_dir)[1]

GlobalSocketAllocator = SocketAllocator()

# TODO: add images to github and write a downloader script
class ImageContainer:
    def __init__(self):
        self.images_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_images")

    def get_linux_image(self, image_name):
        return os.path.join(self.images_dir, image_name)

    def get_linux_x86_64(self):
        return os.path.join(self.images_dir, "linux_x86_64")

    def get_linux_riscv(self):
        return os.path.join(self.images_dir, "linux_riscv")

    def get_kolibri_x86_32(self):
        return os.path.join(self.images_dir, "kolibri_x86_32")

    def get_linux_arm_64(self):
        return os.path.join(self.images_dir, "linux_arm_64")

    def get_custom_kernels_x86_64(self):
        return os.path.join(self.images_dir, "custom_kernels", "x86_64")

    def get_custom_kernels_arm_64(self):
        return os.path.join(self.images_dir, "custom_kernels", "arm_64")

    def get_custom_kernels_golden_images(self, arch_name):
        if arch_name == "x86_64":
            return os.path.join(self.images_dir, "custom_kernels_golden_images", "x86_64")
        elif arch_name == "arm_64":
            return os.path.join(self.images_dir, "custom_kernels_golden_images", "arm_64")
        else:
            raise Exception(f"Unknown arch {arch_name}")

class VM(ABC):
    def __init__(self, arch):
        self.vm_proc = None
        self.arch = arch
        self.qemu_monitor_path = GlobalSocketAllocator.alloc_monitor_socket()
        self.print_uart = bool(os.getenv("GDB_PT_DUMP_TESTS_PRINT_UART"))
        self.qemu_gdb_path = GlobalSocketAllocator.alloc_gdb_socket()

    def start(self, cmd):
        if bool(os.getenv("GDB_PT_DUMP_TESTS_PRINT_VM_LAUNCH_CMD")):
            print(f"Executing command: {' '.join(shlex.quote(arg) for arg in cmd)}")
        self.vm_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def get_arch(self):
        return self.arch

    @abstractmethod
    def get_default_base_image_kaddr(self):
        raise Exception("Not implemented")

    @abstractmethod
    def get_default_base_image_paddr(self):
        raise Exception("Not implemented")

    @abstractmethod
    def get_default_physmap_kaddr(self):
        raise Exception("Not implemented")

    @abstractmethod
    def get_fixed_known_address(self):
        raise Exception("Not implemented")

    def get_qemu_monitor_path(self):
        return self.qemu_monitor_path

    def get_qemu_gdb_path(self):
        return self.qemu_gdb_path

    def wait_for_string_on_line(self, string):
        line = b""
        while True:
            b = self.vm_proc.stdout.read(1)
            if b == b"":
                continue
            if self.print_uart:
                sys.stdout.write(b.decode("utf-8"))
            line += b
            if b == b"\n":
                if line[:-1] == string:
                    return
                line = b""

    def wait_for_shell(self, shell_symbol="~"):
        line = b""
        while True:
            b = self.vm_proc.stdout.read(1)
            if b == b"":
                continue
            if self.print_uart:
                sys.stdout.write(b.decode("utf-8"))
            line += b
            if b == b"\n":
                match = re.search(b'Boot took (.*) seconds', line)
                if match:
                    return
                line = b""

    def stop(self):
        if self.vm_proc:
            self.vm_proc.kill()
            self.vm_proc.wait()
            self.vm_proc = None

    def is_alive(self):
        if not self.vm_proc:
            return False
        return self.vm_proc.poll() == None

class VM_X86_64(VM):
    def __init__(self, image_dir, fda_name=None):
        super().__init__(arch="x86_64")
        self.image_dir = image_dir
        self.fda_name = fda_name

    def start(self, memory_mib=256, kvm=False, smep=True, smap=True, kaslr=True, svm=False, la57=False, num_cores=1):
        cmd = []
        cmd.extend(["qemu-system-x86_64"])

        cpu_options = []
        if kvm:
            cpu_options.append("kvm64")
        else:
            if la57:
                cpu_options.append("qemu64,+la57")
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

        if self.fda_name == None:
            kernel_image = os.path.join(self.image_dir, "kernel.img")
            cmd.extend(["-kernel", kernel_image])

            initrd_image = os.path.join(self.image_dir, "initrd.img")
            cmd.extend(["-initrd", initrd_image])

            boot_string = "console=ttyS0 oops=panic ip=dhcp root=/dev/ram rdinit=/init quiet"
            if kaslr:
                boot_string += " kaslr"
            else:
                boot_string += " nokaslr"

            cmd.extend(["-append", boot_string])
        else:
            # This path is taken for the custom images
            cmd.extend(["-fda", os.path.join(self.image_dir, self.fda_name)])

        cmd.extend(["-m", str(memory_mib)])

        cmd.extend(["-monitor", f"unix:{self.get_qemu_monitor_path()},server,nowait"])

        cmd.extend(["-gdb", f"unix:{self.get_qemu_gdb_path()},server,nowait"])

        cmd.extend(["-nographic", "-snapshot", "-no-reboot"])

        cmd.extend(["-smp", str(num_cores)])

        super().start(cmd)

    def get_default_base_image_kaddr(self):
        return [0xffffffff81000000]

    def get_default_base_image_paddr(self):
        return [0x1000000]

    def get_default_physmap_kaddr(self):
        return 0xffff888000000000

    def get_fixed_known_address(self):
        return 0xffffffff81000000

class VM_X86_32(VM):
    def __init__(self, image_dir, fda_name=None):
        super().__init__(arch="x86_32")
        self.image_dir = image_dir
        self.fda_name = fda_name

    def start(self, memory_mib=256, num_cores=1):
        cmd = []
        cmd.extend(["qemu-system-i386"])

        if self.fda_name == None:
            kernel_image = os.path.join(self.image_dir, "kernel.img")
            cmd.extend(["-kernel", kernel_image])

            initrd_image = os.path.join(self.image_dir, "initrd.img")
            cmd.extend(["-initrd", initrd_image])

            boot_string = "console=ttyS0 oops=panic ip=dhcp root=/dev/ram rdinit=/init quiet"
            if kaslr:
                boot_string += " kaslr"
            else:
                boot_string += " nokaslr"

            cmd.extend(["-append", boot_string])
        else:
            # This path is taken for the custom images
            cmd.extend(["-fda", os.path.join(self.image_dir, self.fda_name)])

        cmd.extend(["-m", str(memory_mib)])

        cmd.extend(["-monitor", f"unix:{self.get_qemu_monitor_path()},server,nowait"])

        cmd.extend(["-gdb", f"unix:{self.get_qemu_gdb_path()},server,nowait"])

        cmd.extend(["-nographic", "-snapshot", "-no-reboot"])

        cmd.extend(["-smp", str(num_cores)])

        super().start(cmd)

    def get_default_base_image_kaddr(self):
        raise Exception("Unimplemented")

    def get_default_base_image_paddr(self):
        raise Exception("Unimplemented")

    def get_default_physmap_kaddr(self):
        raise Exception("Unimplemented")

    def get_fixed_known_address(self):
        raise Exception("Unimplemented")

class VM_Arm_64(VM):
    def __init__(self, image_dir, bios_name=None, has_kernel=True):
        super().__init__(arch="arm_64")
        self.image_dir = image_dir
        self.bios_name = bios_name
        self.has_kernel = has_kernel

    def start(self, memory_mib=256, kaslr=True,  num_cores=1):
        cmd = []
        cmd.extend(["qemu-system-aarch64"])

        cpu_options = []
        cpu_options.append("cortex-a57")
        cmd.extend(["-cpu", ",".join(cpu_options)])

        cmd.extend(["-machine", "virt"])

        if self.bios_name:
            cmd.extend(["-bios", os.path.join(self.image_dir, self.bios_name)])

        if self.has_kernel:
            kernel_image = os.path.join(self.image_dir, "kernel.img")
            cmd.extend(["-kernel", kernel_image])

            initrd_image = os.path.join(self.image_dir, "initrd.img")
            cmd.extend(["-initrd", initrd_image])

            boot_string = "root=/dev/ram rdinit=/init"
            if kaslr:
                boot_string += " kaslr"
            else:
                boot_string += " nokaslr"

            cmd.extend(["-append", boot_string])

        cmd.extend(["-m", str(memory_mib)])

        cmd.extend(["-monitor", f"unix:{self.get_qemu_monitor_path()},server,nowait"])

        cmd.extend(["-gdb", f"unix:{self.get_qemu_gdb_path()},server,nowait"])

        cmd.extend(["-nographic", "-snapshot", "-no-reboot"])

        cmd.extend(["-smp", str(num_cores)])

        super().start(cmd)

    # TODO
    # The addresses are not correct when LA57 is enabled
    def get_default_base_image_kaddr(self):
        return [0xffff800010000000, 0xffffffc008010000, 0xfffffe0008010000]

    def get_default_base_image_paddr(self):
        return [0x40200000, 0x40210000]

    def get_default_physmap_kaddr(self):
        raise Exception("Unknown")

    def get_fixed_known_address(self):
        return 0xfffffffe00000000

class VM_Riscv(VM):
    def __init__(self, image_dir):
        super().__init__(arch="riscv")
        self.image_dir = image_dir

    def start(self, memory_mib=64, kvm=False, kaslr=True, num_cores=1):
        cmd = []
        cmd.extend(["qemu-system-riscv64"])

        cpu_options = []
        if kvm:
            cpu_options.append("kvm64")
        else:
            cpu_options.append("qemu64")

        cmd.extend(["-cpu", "rv64"])

        kernel_image = os.path.join(self.image_dir, "kernel.img")
        cmd.extend(["-kernel", kernel_image])

        initrd_image = os.path.join(self.image_dir, "initrd.img")
        cmd.extend(["-initrd", initrd_image])

        cmd.extend(["-machine", "virt"])

        boot_string = "root=/dev/ram rdinit=/init console=ttyS0 "
        if kaslr:
            boot_string += " kaslr"
        else:
            boot_string += " nokaslr"

        cmd.extend(["-append", boot_string])

        cmd.extend(["-m", str(memory_mib)])

        cmd.extend(["-monitor", f"unix:{self.get_qemu_monitor_path()},server,nowait"])

        cmd.extend(["-gdb", f"unix:{self.get_qemu_gdb_path()},server,nowait"])

        cmd.extend(["-nographic", "-snapshot", "-no-reboot"])

        cmd.extend(["-smp", str(num_cores)])

        super().start(cmd)

    def get_default_base_image_kaddr(self):
        raise Exception("Unimplemented")

    def get_default_base_image_paddr(self):
        raise Exception("Unimplemented")

    def get_default_physmap_kaddr(self):
        raise Exception("Unimplemented")

    def get_fixed_known_address(self):
        raise Exception("Unimplemented")

class FlatViewRange:

    def __init__(self, range_start, range_end, range_type):
        self.range_start = range_start
        self.range_end = range_end
        self.range_type = range_type

    def is_memory_backed(self):
        return self.range_type in ["ram"]

    def is_rom(self):
        return self.range_type in ["rom"]

    def is_io(self):
        return self.range_type in ["i/o"]

    def __str__(self):
        return f"VA_start: {hex(self.range_start)}, VA_end: {hex(self.range_end)}, Type: {self.range_type}"

class VmFlatView:

    def __init__(self, tree_data):
        self._tree_data = tree_data
        self._ranges = []

        pattern = "^([0-9a-f]{16})-([0-9a-f]{16}) \\(prio \d, (.+)\\): (.+)$"
        res = ""
        for line in tree_data.split("\n"):
            line = line.strip()
            matching = re.match(pattern, line)
            if matching:
                memory_type = matching.group(3)
                if memory_type in ["ram", "rom"]:
                    range_start = int(matching.group(1), 16)
                    range_end = int(matching.group(2), 16) + 1
                    self._ranges.append(FlatViewRange(range_start, range_end, memory_type))

    def find_range(self, pa):
        for r in self._ranges:
            if pa >= r.range_start and pa < r.range_end:
                return r
        return None

    def find_prev_range(self, pa):
        prev = None
        for r in self._ranges:
            if r.range_end <= pa:
                prev = r
        return prev

class QemuMonitorExecutor:

    def __init__(self, vm):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.connect(vm.get_qemu_monitor_path())
        self._read_until("(qemu)")

    def stop(self):
        if self.socket:
            self.socket.shutdown(socket.SHUT_WR)
            self.socket.close()

    def _read_until(self, until):
        buf = ""
        while True:
            b = self.socket.recv(1)
            if b != b'':
                buf += b.decode()
            if buf.endswith(until):
                break
        return buf

    def _send_command(self, command):
        self.socket.send(command.encode() + b"\n")
        res = self._read_until("(qemu)")[:-7]
        res = res[res.find("\n"):]
        return res

    def get_memory_flat_view(self):
        tree = self._send_command("info mtree -f")
        return VmFlatView(tree)

    def gva2gpa(self, addr):
        res = self._send_command(f"gva2gpa {hex(addr)}").strip()
        matching = re.match("gpa: (.+)", res)
        if matching == None:
            return None
        res = matching.group(1)
        gpa_addr = int(res, 16)
        return gpa_addr

    def read_virt_memory(self, addr, len):
        data = self._read_memory(addr, len, True)
        return data

    def _read_memory(self, addr, len, is_virt):
        exec = ""
        if is_virt:
            exec = "memsave"
        else:
            exec = "pmemsave"
        filename = tempfile.mktemp()
        if os.path.isfile(filename):
            os.remove(filename)

        self._send_command(f"{exec} {addr} {len} \"{filename}\"")

        data = b""
        for u in range(3):
            try:
                with open(filename, "rb") as f:
                    data = f.read()
                    break
            except:
                time.sleep(0.1)
        os.remove(filename)
        return data

    def pause(self):
        self._send_command("stop")

    def resume(self):
        self._send_command("cont")

class GdbCommandExecutor:

    class Result:
        def __init__(self, output, elapsed):
            self.output = output
            self.elapsed = elapsed

    def __init__(self, vm):
        self.gdb_server_path = vm.get_qemu_gdb_path()
        self.use_multiarch = vm.get_arch() != "x86_64"
        self.script_root_pt = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../", "../", "pt.py"))

        # Start a GDB process immediately so that
        self._start_gdb_process()

    def __del__(self):
        self.stop()

    def stop(self):
        if self._subproc:
            self._subproc.kill()
            self._subproc.wait()
            self._subproc = None

    def _start_gdb_process(self):
        cmd = []
        if self.use_multiarch:
            cmd.extend(["gdb-multiarch"])
        else:
            cmd.extend(["gdb"])

        cmd.extend(["-n"])
        cmd.extend(["-q"])
        cmd.extend(["-ex", "set confirm off"])
        cmd.extend(["-ex", "set pagination off"])
        cmd.extend(["-ex", "source {}".format(self.script_root_pt)])
        cmd.extend(["-ex", f"target remote {self.gdb_server_path}"])

        self._subproc = subprocess.Popen(cmd, stderr=subprocess.STDOUT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=0)

    def _read_until(self, until_str):
        buf = ""
        while True:
            b = self._subproc.stdout.read(1)
            if b != "":
                buf += b
            if buf.endswith(until_str):
                break
        return buf

    def run_cmd(self, pt_cmd):
        if not self._subproc:
            self._start_gdb_process()

        t1 = time.time()
        self._read_until("(gdb)")
        self._subproc.stdin.write(pt_cmd + "\n")
        self._subproc.stdin.write("p \"(DONE)\"\n")
        res = self._read_until("(DONE)")
        res = res[:res.rfind("\n")]
        t2 = time.time()

        if "error" in res.lower() or "exception" in res.lower():
            raise Exception(f"Executuing command failed: '{res}'")
        elapsed = t2 - t1
        return GdbCommandExecutor.Result(res, elapsed)

def create_linux_vm(arch_name, image_name = None):
    if arch_name == "x86_64":
        image = ImageContainer().get_linux_image(image_name) if image_name is not None else ImageContainer().get_linux_x86_64()
        return VM_X86_64(image)
    elif arch_name == "arm_64":
        image = ImageContainer().get_linux_image(image_name) if image_name is not None else ImageContainer().get_linux_arm_64()
        return VM_Arm_64(image)
    elif arch_name == "riscv":
        image = ImageContainer().get_linux_image(image_name) if image_name is not None else ImageContainer().get_linux_riscv()
        return VM_Riscv(image)
    else:
        raise Exception(f"Unknown arch {arch_name}")

def create_custom_vm(arch_name, image_name):
    if arch_name == "x86_64":
        return VM_X86_64(image_dir = ImageContainer().get_custom_kernels_x86_64(), fda_name = image_name)
    elif arch_name == "arm_64":
        return VM_Arm_64(image_dir = ImageContainer().get_custom_kernels_arm_64(), bios_name = image_name, has_kernel = False)
    else:
        raise Exception(f"Unknown arch {arch_name}")

def get_x86_64_binary_names():
    image_folder = ImageContainer().get_custom_kernels_x86_64()
    files = [file for file in os.listdir(image_folder) if file.endswith(".bin")]
    return files

def get_arm_64_binary_names():
    image_folder = ImageContainer().get_custom_kernels_arm_64()
    files = [file for file in os.listdir(image_folder) if file.endswith(".bin")]
    # Filter out 16k granule
    files = [file for file in files if "16k" not in file]
    return files

def check_va_exists(monitor, flatview, va):
    data = monitor.read_virt_memory(va, 4)
    if len(data) == 4:
        # This is the common case that the memory is accessible
        return True

    pa = monitor.gva2gpa(va)
    if pa == None:
        print("Qemu failed to translate the GVA altogether")
        print("This probably means that the page-table parsing or range merging is incorrect")
        return False

    r = flatview.find_range(pa)
    if r == None:
        if prev_range := flatview.find_prev_range(va):
            if prev_range.is_io() or prev_range.is_rom():
                page_aligned_pa = pa & 0xFF_FF_FF_FF_FF_FF_F0_00
                if page_aligned_pa < prev_range.range_end:
                    return True
        print(f"Failed to find the PA ({hex(pa)}) in the collected flatview ranges")
        print("This can mean the whole page is part of IO/ROM and only part of the address is accessible")
        return False

    if r.is_io():
        # If it's not IO, it should be either RAM or ROM.
        assert(r.is_memory_backed())

        # IO may only implement part of the physical memory range to be accessible, so accesses will fail
        # even if technically the physical page exists.
        return True

    # Anything else that's not handled is a failure to access memory
    return False

def check_if_belongs_to_io_or_rom(monitor, flatview, va):
    pa = monitor.gva2gpa(va)
    if pa == None:
        print("Qemu failed to translate the GVA altogether")
        print("This probably means that the page-table parsing or range merging is incorrect")
        return False

    if pa == None:
        print("Qemu failed to translate the GVA altogether")
        print("This probably means that the page-table parsing or range merging is incorrect")
        return False

    r = flatview.find_range(pa)
    if r != None:
        return r.is_io() or r.is_rom()

    return False

