#!/usr/bin/env python3

from pt.machine import *
from pt.pt import *
from pt.pt_x86_64_parse import *
from pt.pt_aarch64_parse import *
from pt.pt_riscv64_parse import *

from bcc import BPF
import fcntl
import ctypes
import threading
import time

import sys

def read_address_from_kallsyms(searched_symb_name):
    f = open("/proc/kallsyms", "r")
    data = f.read()
    f.close()
    for line in data.split("\n"):
        symb_addr, symb_type, symb_name = line.split(" ")
        if searched_symb_name == symb_name:
            return int(symb_addr, 16)
    return None

read_memory_bpf_program_src = open("pt_host/pt_host.bcc", "r").read()
page_offset_base = read_address_from_kallsyms("page_offset_base")
read_memory_bpf_program_src = read_memory_bpf_program_src.replace("$PAGE_OFFSET_BASE", hex(page_offset_base))
read_memory_program = BPF(text=read_memory_bpf_program_src)

def dummy_thread(event):
    while not event.is_set():
        time.sleep(0.01)

def read_cr3(pid):
    bpf_program = open("pt_host/pt_host_read_cr3.bcc", "r").read()
    bpf_program = bpf_program.replace("$PID", pid)
    page_offset_base = read_address_from_kallsyms("page_offset_base")
    bpf_program = bpf_program.replace("$PAGE_OFFSET_BASE", hex(page_offset_base))
    bpf = BPF(text=bpf_program)
    bpf.attach_kprobe(event="finish_task_switch.isra.0", fn_name="read_cr3")
    event = threading.Event()
    th = threading.Thread(target=dummy_thread, args=(event,))
    th.start()
    cr3 = None
    while cr3 == None or cr3 == 0:
        (_, _, _, _, _, msg_b) = bpf.trace_fields()
        msg = msg_b.decode('utf8')
        if msg != "Done":
            continue
        cr3 = bpf["out_cr3"][0].value
        if cr3 == 0:
            continue
    event.set()
    th.join()
    return cr3

class HostMachine(Machine):

    def __init__(self):
        pass

    def __close__(self):
        pass

    def read_virtual_memory(self, virtual_address, length):
        raise Exception("Unimplemented")

    def read_physical_memory(self, physical_address, length):
        block_size = 0x1000
        data = b""
        for block_off in range(0, length, block_size):
            block_len = min(block_size, length - block_off)
            data += read_phys_memory(physical_address + block_off, block_len)
        return data

    def read_register(self, register_name):
        value = None
        if register_name == "$cr3":
            #value = read_cr3(str(os.getpid()))
            value = read_cr3(str(os.getpid()))
        elif register_name == "$cr4":
            value = (1 << 4) | (1 << 5) | (1 << 20) | (1 << 21)
        elif register_name == "$cr0":
            value = (1 << 0) | (1 << 16) | (1 << 31)
        elif register_name == "$efer":
            value = (1 << 8)
        else:
            raise Exception("Unimplemented register: " + register_name)
        return value

    def __init__(self):
        pass

class HostFrontend():
    def __init__(self):

        # Create machine backend
        machine_backend = HostMachine()

        # Create arch backend
        arch_backend = PT_x86_64_Backend(machine_backend)

        # Bring-up pt_dump
        self.pt = PageTableDump(machine_backend, arch_backend)

    def invoke(self, arg):
        self.pt.handle_command_wrapper(arg)

class Page(ctypes.Structure):
    _fields_ = [('data', ctypes.c_char * 4096)]

_attached = False

def read_phys_memory(addr, len):
    pid = os.getpid()

    global _attached
    if not _attached:
        read_memory_program.get_table("in_pid")[ctypes.c_uint32(0)] = ctypes.c_uint32(pid)
        read_memory_program.attach_kprobe(event=read_memory_program.get_syscall_fnname("ioctl"), fn_name="read_memory")
        _attached = True

    read_memory_program.get_table("in_phys_addr")[ctypes.c_uint32(0)] = ctypes.c_uint64(addr)
    read_memory_program.get_table("in_phys_len")[ctypes.c_uint32(0)] = ctypes.c_uint32(len)
    try:
        fcntl.ioctl(0, 0xFEFEFEFE)
    except:
        pass
    (_, _, _, _, _, msg_b) = read_memory_program.trace_fields()
    msg = msg_b.decode('utf8')
    assert(msg == "Done")
    data = bytearray(read_memory_program["out_block"][0].data)
    return data[:len]

def main():
    frontend = HostFrontend()
    frontend.invoke(sys.argv[1:])

if __name__ == "__main__":
    main()

