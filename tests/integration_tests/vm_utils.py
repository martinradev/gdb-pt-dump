import os
import sys
import subprocess
import re
import time
import socket
import json
from abc import ABC, abstractmethod

_DEFAULT_QEMU_MONITOR_PORT=55555

# TODO: add images to github and write a downloader script
class ImageContainer:
    def __init__(self):
        self.images_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "images")

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
    def __init__(self, arch, qemu_monitor_port):
        self.vm_proc = None
        self.arch = arch
        self.qemu_monitor_port = qemu_monitor_port
        self.print_uart = bool(os.getenv("GDB_PT_DUMP_TESTS_PRINT_UART"))

    def start(self, cmd):
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

    def get_gdb_server_port(self):
        default_qemu_gdb_port = 1234
        return default_qemu_gdb_port

    def get_qemu_monitor_port(self):
        return self.qemu_monitor_port

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
            self.vm_proc = None

    def is_alive(self):
        if not self.vm_proc:
            return False
        return self.vm_proc.poll() == None

class VM_X86_64(VM):
    def __init__(self, image_dir, fda_name=None):
        super().__init__(arch="x86_64", qemu_monitor_port=_DEFAULT_QEMU_MONITOR_PORT)
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

        cmd.extend(["-qmp", f"tcp:localhost:{self.get_qemu_monitor_port()},server,nowait"])

        cmd.extend(["-nographic", "-snapshot", "-no-reboot"])

        cmd.extend(["-smp", str(num_cores)])

        cmd.extend(["-s"])

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
        super().__init__(arch="x86_32", qemu_monitor_port=_DEFAULT_QEMU_MONITOR_PORT)
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

        cmd.extend(["-qmp", f"tcp:localhost:{self.get_qemu_monitor_port()},server,nowait"])

        cmd.extend(["-nographic", "-snapshot", "-no-reboot"])

        cmd.extend(["-smp", str(num_cores)])

        cmd.extend(["-s"])

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
        super().__init__(arch="arm_64", qemu_monitor_port=_DEFAULT_QEMU_MONITOR_PORT)
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

        cmd.extend(["-qmp", f"tcp:localhost:{self.get_qemu_monitor_port()},server,nowait"])

        cmd.extend(["-nographic", "-snapshot", "-no-reboot"])

        cmd.extend(["-smp", str(num_cores)])

        cmd.extend(["-s"])

        super().start(cmd)

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
        super().__init__(arch="riscv", qemu_monitor_port=_DEFAULT_QEMU_MONITOR_PORT)
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

        cmd.extend(["-qmp", f"tcp:localhost:{self.get_qemu_monitor_port()},server,nowait"])

        cmd.extend(["-nographic", "-snapshot", "-no-reboot"])

        cmd.extend(["-smp", str(num_cores)])

        cmd.extend(["-s"])

        super().start(cmd)

    def get_default_base_image_kaddr(self):
        raise Exception("Unimplemented")

    def get_default_base_image_paddr(self):
        raise Exception("Unimplemented")

    def get_default_physmap_kaddr(self):
        raise Exception("Unimplemented")

    def get_fixed_known_address(self):
        raise Exception("Unimplemented")

class QemuMonitorExecutor:

    def __init__(self, vm):
        self.qemu_monitor_port = vm.get_qemu_monitor_port()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect(("localhost", vm.get_qemu_monitor_port()))

        _header = self.read_line()
        self.socket.sendall(b'{ "execute": "qmp_capabilities" }\n')
        self.read_line()

    def stop(self):
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
        while True:
            res = json.loads(self.read_line())
            if "error" in res:
                print(res, cmd)
                return None
            if "event" in res:
                continue
            assert("return" in res)
            break
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
        data = self._read_memory(addr, len, True)
        return data

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

    def __init__(self, vm):
        self.gdb_server_port = vm.get_gdb_server_port() 
        self.use_multiarch = vm.get_arch() != "x86_64"
        self.script_root_pt = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../", "../", "pt.py"))

    def run_cmd(self, pt_cmd):
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

