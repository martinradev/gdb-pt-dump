from pt.machine import *
from pt.pt import *
from pt.pt_x86_64_parse import *
from pt.pt_aarch64_parse import *
from pt.pt_riscv64_parse import *

import gdb
import os
import subprocess

class QemuGdbMachine(Machine):

    def __init__(self):
        self.pid = QemuGdbMachine.get_qemu_pid()
        self.file = os.open(f"/proc/{self.pid}/mem", os.O_RDONLY)

    def __del__(self):
        if self.file:
            os.close(self.file)

    def read_physical_memory(self, physical_address, length):
        res = gdb.execute(f"monitor gpa2hva {hex(physical_address)}", to_string = True)

        # It's not possible to pread large sizes, so let's break the request
        # into a few smaller ones.
        max_block_size = 1024 * 1024 * 256
        try:
            hva = int(res.split(" ")[-1], 16)
            data = b""
            for offset in range(0, length, max_block_size):
                length_to_read = min(length - offset, max_block_size)
                block = os.pread(self.file, length_to_read, hva + offset)
                data += block
            return data
        except Exception as e:
            msg = f"Physical address ({hex(physical_address)}, +{hex(length)}) is not accessible. Reason: {e}. gpa2hva result: {res}"
            raise OSError(msg)

    def search_pids_for_file(pids, filename):
        for pid in pids:
            fd_dir = f"/proc/{pid}/fd"

            try:
                for fd in os.listdir(fd_dir):
                    if os.readlink(f"{fd_dir}/{fd}") == filename:
                        return pid
            except FileNotFoundError:
                # Either the process has gone or fds are changing, not our pid
                pass
            except PermissionError:
                # Evade processes owned by other users
                pass

        return None

    @staticmethod
    def get_qemu_pid():
        out = subprocess.check_output(["pgrep", "qemu-system"], encoding="utf8")
        pids = out.strip().split('\n')

        if len(pids) == 1:
            return int(pids[0], 10)

        # We add a chardev file backend (we dont add a fronted, so it doesn't affect
        # the guest). We can then look through proc to find which process has the file
        # open. This approach is agnostic to namespaces (pid, network and mount).
        chardev_id = "gdb-pt-dump" + '-' + ''.join(random.choices(string.ascii_letters, k=16))
        with tempfile.NamedTemporaryFile() as t:
            gdb.execute(f"monitor chardev-add file,id={chardev_id},path={t.name}")
            ret = QemuGdbMachine.search_pids_for_file(pids, t.name)
            gdb.execute(f"monitor chardev-remove {chardev_id}")

        if not ret:
            raise Exception("Could not find qemu pid")

        return int(ret, 10)

    def read_register(self, register_name):
        return int(gdb.parse_and_eval(register_name).cast(gdb.lookup_type("unsigned long")))

class PageTableDumpGdbFrontend(gdb.Command):
    """
    GDB pt-dump: command for inspecting VM page tables.
    Arguments:
        -filter FILTER [FILTER ...]
            Specify filters for the recorded pages.
            x86_64 Supported filters:
                w: is writeable.
                x: is executable
                w|x: is writeable or executable
                ro: read-only
                u: user-space page
                s: supervisor page
                wb: write-back
                uc: uncacheable

             aarch64- and riscv64-supported filters:
                w: is writeable.
                x: is executable
                w|x: is writeable or executable
                ro: read-only
                u: user-space page
                s: supervisor page

        -range START_ADDR END_ADDR
            Will filter-out virtual memory ranges which start at a position in [START_ADDR, END_ADDR]
        -has ADDR
            Will filter-out virtual memory ranges which contain ADDR
        -before ADDR
            Will select virtual memory ranges which start <ADDR
        -after ADDR
            Will select virtual memory ranges which start >=ADDR
        -ss "STRING"
            Searches for the string STRING in the ranges after filtering
        -sb BYTESTRING
            Searches for the byte-string BYTESTRING in the ranges after filtering
        -s8 VALUE
            Searches for the value VALUE in the ranges after filtering
            VALUE should fit in 8 bytes.
        -s4 VALUE
            Searches for the value VALUE in the ranges after filtering
            VALUE should fit in 4 bytes.
        -align ALIGNMENT [OFFSET]
            When searching, it will print out addresses which are aligned to ALIGNMENT.
            If offset is provided, then the check would be performed as (ADDR - OFFSET) % ALIGNMENT.
            It can be useful when searching for content in a particular SLAB.
        -kaslr
            Print KASLR-relevant information like the image offsets and phys map base.
        -kaslr_leaks
            Searchers for values which disclose KASLR offsets.
        -save
            Cache the recorded page table for that address after traversing the hierachy.
            This will yield speed-up when printing the page table again.
        -list
            List the cached page tables.
        -clear
            Clear all saved page tables.
        -info
            Print arch register information.
        -o FILE_NAME
            Store the output from the current command to a file with name FILE_NAME.
            This may be useful when the a lot of data is produced, e.g. full page table.
        -find_alias
            Experimental feature and currently slow. Searches for aliases ranges in virtual memory.
            Ranges are aliased if they point to the the same physical memory. This can be useful if one
            is searching for R/RX memory which is writeable through some other address.
            Another interesting option is to find alias for memory mapped in user space and kernel space.
            TODO: This feature will be reworked for usability and performance in the near future.
        -force_traverse_all
            Forces the traversal of any page table entry (pml4, pdp, ...) even if a duplicate entry has
            already been trarversed. Using this option bypasses an optimization which discards already
            traversed duplicate entries. Expect that using this option would render pt unusable for
            windows VMs.
        -phys_verbose
            Prints the start physical address for the printed virtual ranges. This argument further
            restricts the merging of virtual ranges by requiring that merged ranges need to also be
            physically contiguous. Using this range leads to more verbose output.

    Architecture-specific arguments:
        - X86-32 / X86-64
            `-cr3 HEX_ADDR`
                The GPA of the page table. If not used, the script will use the architectural
                register (e.g. cr3).

        - aarch64
            `-ttbr0_el1 HEX_ADDR`
                The GPA of the TTBR0_EL1 register.
            `-ttbr1_el1 HEX_ADDR`
                The GPA of the TTBR1_EL1 register.

        - riscv64
            `-satp HEX_ADDR`
                The GPA of the SATP register.

    Example usage:
        `pt -save -filter s w|x wb`
            Traverse the current page table and then save it. When returning the result,
            filter the pages to be marked as supervisor, be writeable or executable, and marked as
            write-back.
        `pt -filter w x`
            Traverse the current page table and print out mappings which are both writeable and
            executable.
        `pt -cr3 0x4000`
            Traverse the page table at guest physical address 0x4000. Don't save it.
        `pt -save -kaslr`
            Traverse page tables, save them and print kaslr information.
        `pt -ss "Linux 4."`
            Search for the string Linux.
        `pt -sb da87374107`
            Search for the byte-string da87374107.
        `pt -s8 0xaabbccdd`
            Search for the 8-byte-long value 0xaabbccdd.
        `pt -has 0xffffffffaaf629f7`
            Print information about the mapping which covers the address 0xffffffffaaf629f7.
    """

    def __init__(self):
        super(PageTableDumpGdbFrontend, self).__init__("pt", gdb.COMMAND_USER)
        self.pid = -1
        self.pt = None

    def lazy_init(self):

        # Create machine backend
        machine_backend = QemuGdbMachine()

        # Create arch backend
        arch = gdb.execute("show architecture", to_string = True)
        arch_backend = None
        if "aarch64" in arch:
            arch_backend = PT_Aarch64_Backend(machine_backend)
        elif "x86" in arch or "x64" in arch:
            arch_backend = PT_x86_64_Backend(machine_backend)
        elif "riscv:rv64" in arch:
            arch_backend = PT_RiscV64_Backend(machine_backend)
        else:
            raise Exception(f"Unknown arch. Message: {arch}")

        # Bring-up pt_dump
        self.pt = PageTableDump(machine_backend, arch_backend)

    def invoke(self, arg, from_tty):
        try:
            curr_pid = QemuGdbMachine.get_qemu_pid()
            if curr_pid != self.pid:
                self.lazy_init()
        except Exception as e:
            print("Cannot get qemu-system pid", e)
            return

        argv = gdb.string_to_argv(arg)
        self.pt.handle_command_wrapper(argv)
