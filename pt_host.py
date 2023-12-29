#!/usr/bin/env python3

from pt.machine import *
from pt.pt import *
from pt.pt_x86_64_parse import *

from bcc import BPF
import ctypes

import sys

def read_address_from_kallsyms(searched_symb_name):
    """
    Returns the VA of a given kernel symbol.
    """
    f = open("/proc/kallsyms", "r")
    data = f.read()
    f.close()
    for line in data.split("\n"):
        symb_addr, symb_type, symb_name = line.split(" ")
        if searched_symb_name == symb_name:
            return int(symb_addr, 16)
    return None

syscall = ctypes.CDLL(None).syscall
read_memory_program = None
read_cr3_program = None

def init_global_state(target_pid):
    global read_memory_program
    global read_cr3_program

    page_offset_base = read_address_from_kallsyms("page_offset_base")

    with open("pt_host/pt_host_read_physmem.bcc", "r") as read_memory_bpf_program_src_file:
        read_memory_bpf_program_src = read_memory_bpf_program_src_file.read()
        read_memory_bpf_program_src = read_memory_bpf_program_src.replace("$PAGE_OFFSET_BASE", hex(page_offset_base))
        read_memory_program = BPF(text=read_memory_bpf_program_src)

    with open("pt_host/pt_host_read_cr3.bcc", "r") as read_cr3_program_src_file:
        read_cr3_program_src = read_cr3_program_src_file.read()
        read_cr3_program_src = read_cr3_program_src.replace("$TARGET_PID", str(target_pid))
        read_cr3_program_src = read_cr3_program_src.replace("$PT_HOST_PID", str(os.getpid()))
        read_cr3_program_src = read_cr3_program_src.replace("$PAGE_OFFSET_BASE", hex(page_offset_base))
        read_cr3_program = BPF(text=read_cr3_program_src)

def read_cr3(target_pid):
    """
    Retrieves the value of the CR3 register for a given PID.

    The CR3 value is retrieved from mm_struct::pgd.
    """
    cr3 = None

    # Invoke 'pidfd_open' which will cause 'pidfd_create' to be called.
    pidfd = os.pidfd_open(int(target_pid))
    os.close(pidfd)

    # The trace must have been triggered
    (_, _, _, _, _, msg_b) = read_cr3_program.trace_fields()
    msg = msg_b.decode('utf8')
    assert(msg == "Done")

    # Read back the CR3 value for the target process.
    cr3 = read_cr3_program["out_cr3"][0].value
    return cr3

class HostMachine(Machine):
    """
    Implementation of the pt-dump 'Machine' interface.
    """

    def __init__(self, target_pid):
        self.target_pid = target_pid

    def __del__(self):
        pass

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
            value = read_cr3(self.target_pid)
        elif register_name == "$cr4":
            value = (1 << 4) | (1 << 5) | (1 << 20) | (1 << 21)
        elif register_name == "$cr0":
            value = (1 << 0) | (1 << 16) | (1 << 31)
        elif register_name == "$efer":
            value = (1 << 8)
        else:
            raise Exception("Unimplemented register: " + register_name)
        return value

class HostFrontend():
    """
    Combines the machine, arch and pt_dump implementations.
    """

    def __init__(self, target_pid):

        # Create machine backend
        machine_backend = HostMachine(target_pid)

        # Create arch backend
        arch_backend = PT_x86_64_Backend(machine_backend)

        # Bring-up pt_dump
        self.pt = PageTableDump(machine_backend, arch_backend, needs_pid = True)

    def invoke(self, arg):
        self.pt.handle_command_wrapper(arg)

class Page(ctypes.Structure):
    """
    Data structure for holding one 4K page.
    """
    _fields_ = [('data', ctypes.c_char * 4096)]

_attached = False

def read_phys_memory(addr, len):
    """
    Reads 'len' bytes from the physical address in 'addr'
    """

    assert(len <= 0x1000)

    pid = os.getpid()

    # Attach once dynamically
    global _attached
    if not _attached:
        read_memory_program.get_table("in_pid")[ctypes.c_uint32(0)] = ctypes.c_uint32(pid)
        read_memory_program.attach_kprobe(event=read_memory_program.get_syscall_fnname("madvise"), fn_name="syscall__madvise")
        _attached = True

    read_memory_program.get_table("in_phys_addr")[ctypes.c_uint32(0)] = ctypes.c_uint64(addr)
    read_memory_program.get_table("in_phys_len")[ctypes.c_uint32(0)] = ctypes.c_uint32(len)

    # Use madvise as a driver to trigger the point for reading physical memory
    try:
        madvise_syscall = 28
        syscall(madvise_syscall, 0x1337, 0x1337)
    except Exception as e:
        print(e)
        pass

    # Sanity check that execution of the point finished successfully
    (_, _, _, _, _, msg_b) = read_memory_program.trace_fields()
    msg = msg_b.decode('utf8')
    assert(msg == "Done")

    # Read back the physical memory from the shared array.
    data = bytearray(read_memory_program["out_block"][0].data)
    return data[:len]

def main():

    # This is a necessary hack to WAR the disparity of argument handling in pt_host and pt_dump
    # pt_host needs to take a mandatory "-pid" argument, while "pt_dump" does not need it.
    # pt_host does not know of the arguments handled by pt_dump.
    #
    # The hack is to do the pid arg parsing here once to get the pid, but then still add
    # pid to argparse in pt_dump.
    pid_index = None
    for (index, arg_value) in enumerate(sys.argv):
        if arg_value == "-pid" and (index + 1) < len(sys.argv):
            pid_index = index
            break
    pid = None
    if pid_index == None:
        pid = -1
    else:
        pid = int(sys.argv[pid_index + 1])

    # Initialize state
    init_global_state(target_pid=pid)
    frontend = HostFrontend(target_pid=pid)

    # Invoke pt_dump
    frontend.invoke(sys.argv[1:])

if __name__ == "__main__":
    main()

