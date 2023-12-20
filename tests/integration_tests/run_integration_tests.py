#!/usr/bin/env pytest

import os
import copy
import re
import pytest
import sys

from vm_utils import *
from pt_utils import *

def verify_all_search_occurrences(monitor, occs, mem_len, checker):
    for occ in occs:
        memory = monitor.read_virt_memory(occ.occ_va, mem_len)
        assert(checker(occ, memory))

def get_all_arch():
    return ["x86_64", "arm_64"]

@pytest.mark.parametrize("arch_name", get_all_arch())
def test_pt_smoke(arch_name):
    vm = create_linux_vm(arch_name)
    vm.start()
    vm.wait_for_shell()
    gdb = GdbCommandExecutor(vm)
    res = gdb.run_cmd("pt")

@pytest.mark.parametrize("arch_name", get_all_arch())
def test_pt_filter_smoke(arch_name):
    vm = create_linux_vm(arch_name)
    vm.start()
    vm.wait_for_shell()
    gdb = GdbCommandExecutor(vm)
    gdb.run_cmd("pt")
    gdb.run_cmd("pt -filter x")
    gdb.run_cmd("pt -filter w")
    gdb.run_cmd("pt -filter ro")
    gdb.run_cmd("pt -filter w|x")
    gdb.run_cmd("pt -filter u")
    gdb.run_cmd("pt -filter s")
    gdb.run_cmd("pt -filter w x")

@pytest.mark.parametrize("arch_name", get_all_arch())
def test_pt_kaslr_smoke(arch_name):
    vm = create_linux_vm(arch_name)
    vm.start()
    vm.wait_for_shell()
    gdb = GdbCommandExecutor(vm)
    res = gdb.run_cmd("pt -kaslr")

def _test_pt_search(arch_name, search_command, mem_len, checker):
    vm = create_linux_vm(arch_name)
    vm.start()
    vm.wait_for_shell()
    gdb = GdbCommandExecutor(vm)

    res = gdb.run_cmd(search_command)

    monitor = QemuMonitorExecutor(vm)
    monitor.pause()

    occs = parse_occurrences(arch_name, res.output)
    assert(len(occs) > 0)

    verify_all_search_occurrences(monitor, occs, mem_len, checker)

@pytest.mark.parametrize("arch_name", get_all_arch())
def test_pt_search_string(arch_name):
    checker = lambda _, mem: mem == b"Linux"
    _test_pt_search(arch_name, "pt -ss Linux", 5, checker)

@pytest.mark.parametrize("arch_name", get_all_arch())
def test_pt_search_s4(arch_name):
    checker = lambda _, mem: mem == b"\x41\x41\x41\x41"
    _test_pt_search(arch_name, "pt -s4 0x41414141", 4, checker)

@pytest.mark.parametrize("arch_name", get_all_arch())
def test_pt_search_s8(arch_name):
    checker = lambda _, mem: mem == b"\xfe\xff\xff\xff\xff\xff\xff\xff"
    _test_pt_search(arch_name, "pt -s8 0xfffffffffffffffe", 8, checker)

@pytest.mark.parametrize("arch_name", get_all_arch())
def test_pt_range_exists(arch_name):
    vm = create_linux_vm(arch_name)
    vm.start()
    vm.wait_for_shell()
    gdb = GdbCommandExecutor(vm)

    res = gdb.run_cmd(f"pt")
    monitor = QemuMonitorExecutor(vm)
    monitor.pause()

    ranges = parse_va_ranges(arch_name, res.output)
    assert(len(ranges) > 0)
    for r in ranges:
        # BUG: for some reason qemu does
        if r.va_start == 0xffff800010010000 or r.va_start == 0xffff800010030000:
            print(f"Skip reading {hex(r.va_start)} due to a weird qemu bug")
            continue

        addr = r.va_start
        data = monitor.read_virt_memory(addr, 4)
        assert(len(data) == 4)

        addr = r.va_start + int(r.length / 2)
        data = monitor.read_virt_memory(addr, 4)
        assert(len(data) == 4)

        addr = r.va_start + r.length - 4
        data = monitor.read_virt_memory(addr, 4)
        assert(len(data) == 4)

def _test_pt_filter_common(arch_name, executions):
    vm = create_linux_vm(arch_name)
    vm.start()
    vm.wait_for_shell()
    gdb = GdbCommandExecutor(vm)
    monitor = QemuMonitorExecutor(vm)

    for (_cmd, _check) in executions:
        print(f"Running {_cmd}")
        res = gdb.run_cmd(_cmd)
        monitor.pause()

        ranges = parse_va_ranges(arch_name, res.output)
        assert(len(ranges) > 0)
        for r in ranges:
            assert(_check(r))

@pytest.mark.parametrize("arch_name", get_all_arch())
def test_pt_filter_executable(arch_name):
    executions = [("pt -filter x", lambda r: r.flags.executable()), ("pt -filter _x", lambda r: not r.flags.executable())]
    _test_pt_filter_common(arch_name, executions)

@pytest.mark.parametrize("arch_name", get_all_arch())
def test_pt_filter_writeable(arch_name):
    executions = [("pt -filter w", lambda r: r.flags.writeable()), ("pt -filter _w", lambda r: not r.flags.writeable())]
    _test_pt_filter_common(arch_name, executions)

@pytest.mark.parametrize("arch_name", get_all_arch())
def test_pt_filter_read_only(arch_name):
    executions = [("pt -filter ro", lambda r: not r.flags.executable() and not r.flags.writeable())]
    _test_pt_filter_common(arch_name, executions)

@pytest.mark.parametrize("arch_name", get_all_arch())
def test_pt_filter_user_accessible(arch_name):
    if arch_name == "arm_64":
        # BUG: needs another kernel image
        pytest.skip(reason = "User ranges are never visible because user page table is unmapped")
    executions = [("pt -filter u", lambda r: r.flags.user_accessible()), ("pt -filter _u", lambda r: not r.flags.user_accessible())]
    _test_pt_filter_common(arch_name, executions)

@pytest.mark.parametrize("arch_name", get_all_arch())
def test_pt_filter_kernel_only_accessible(arch_name):
    if arch_name == "arm_64":
        # BUG: needs another kernel image
        pytest.skip(reason = "The _s would result into 0 ranges because user page table is unmapped.")
    executions = [("pt -filter s", lambda r: r.flags.super_accessible()), ("pt -filter _s", lambda r: not r.flags.super_accessible())]
    _test_pt_filter_common(arch_name, executions)

@pytest.mark.parametrize("arch_name", get_all_arch())
def test_pt_filter_multiple_filters_user(arch_name):
    if arch_name == "arm_64":
        # BUG: needs another kernel image
        pytest.skip(reason = "This would result into 0 ranges because user page table is unmapped.")
    executions = [ \
                  ("pt -filter w u", lambda r: r.flags.user_writeable()), \
                 ]
    _test_pt_filter_common(arch_name, executions)

@pytest.mark.parametrize("arch_name", get_all_arch())
def test_pt_filter_multiple_filters_super(arch_name):
    executions = [ \
                  ("pt -filter w s", lambda r: r.flags.super_writeable()), \
                  ("pt -filter x s", lambda r: r.flags.super_executable()), \
                 ]
    _test_pt_filter_common(arch_name, executions)

@pytest.mark.parametrize("arch_name", get_all_arch())
def test_pt_filter_and_search(arch_name):
    checker = lambda occ, data: occ.virt_range.flags.writeable() == True and data == b"Linux"
    _test_pt_search(arch_name, "pt -ss Linux -filter w", 5, checker)

    checker = lambda occ, data: occ.virt_range.flags.writeable() == False and occ.virt_range.flags.executable() == False and data == b"Linux"
    _test_pt_search(arch_name, "pt -ss Linux -filter ro", 5, checker)

@pytest.mark.parametrize("arch_name", get_all_arch())
def test_pt_range_command(arch_name):
    vm = create_linux_vm(arch_name)
    vm.start()
    vm.wait_for_shell()
    gdb = GdbCommandExecutor(vm)
    monitor = QemuMonitorExecutor(vm)

    res = gdb.run_cmd("pt")
    ranges = parse_va_ranges(arch_name, res.output)
    assert(len(ranges) > 10)

    r0, r1, r2, r3 = ranges[0:4]

    # cover first range only
    res = gdb.run_cmd(f"pt -range {r0.va_start} {r0.va_start + r0.length - 1}")
    subranges = parse_va_ranges(arch_name, res.output)
    assert(len(subranges) == 1)
    assert(subranges[0] == r0)

    # cover first range partially
    res = gdb.run_cmd(f"pt -range {r0.va_start + 0x1} {r0.va_start + r0.length - 1}")
    subranges = parse_va_ranges(arch_name, res.output)
    assert(len(subranges) == 0)

    # cover range 2 partially
    res = gdb.run_cmd(f"pt -range {r0.va_start + 0x1} {r1.va_start}")
    subranges = parse_va_ranges(arch_name, res.output)
    assert(len(subranges) == 1)
    assert(subranges[0] == r1)

    # cover ranges 0, 1, 2
    res = gdb.run_cmd(f"pt -range {r0.va_start} {r2.va_start}")
    subranges = parse_va_ranges(arch_name, res.output)
    assert(len(subranges) == 3)
    assert(subranges[0] == r0)
    assert(subranges[1] == r1)
    assert(subranges[2] == r2)

    # cover ranges 1, 2, 3
    res = gdb.run_cmd(f"pt -range {r1.va_start} {r3.va_start}")
    subranges = parse_va_ranges(arch_name, res.output)
    assert(len(subranges) == 3)
    assert(subranges[0] == r1)
    assert(subranges[1] == r2)
    assert(subranges[2] == r3)

    # end before start
    res = gdb.run_cmd(f"pt -range 0x40000 0x30000")
    subranges = parse_va_ranges(arch_name, res.output)
    assert(len(subranges) == 0)

@pytest.mark.parametrize("arch_name", get_all_arch())
def test_pt_has_command(arch_name):
    vm = create_linux_vm(arch_name)
    vm.start()
    vm.wait_for_shell()
    gdb = GdbCommandExecutor(vm)
    monitor = QemuMonitorExecutor(vm)

    res = gdb.run_cmd("pt")
    ranges = parse_va_ranges(arch_name, res.output)
    assert(len(ranges) > 10)

    r0, r1, r2, r3 = ranges[0:4]

    res = gdb.run_cmd(f"pt -has {r0.va_start}")
    subranges = parse_va_ranges(arch_name, res.output)
    assert(len(subranges) == 1)
    assert(subranges[0] == r0)

    res = gdb.run_cmd(f"pt -has {r0.va_start + 1}")
    subranges = parse_va_ranges(arch_name, res.output)
    assert(len(subranges) == 1)
    assert(subranges[0] == r0)

    res = gdb.run_cmd(f"pt -has {r0.va_start + r0.length - 1}")
    subranges = parse_va_ranges(arch_name, res.output)
    assert(len(subranges) == 1)
    assert(subranges[0] == r0)

    res = gdb.run_cmd(f"pt -has {r1.va_start}")
    subranges = parse_va_ranges(arch_name, res.output)
    assert(len(subranges) == 1)
    assert(subranges[0] == r1)

    res = gdb.run_cmd(f"pt -has {ranges[-1].va_start + ranges[-1].length - 1}")
    subranges = parse_va_ranges(arch_name, res.output)
    assert(len(subranges) == 1)
    assert(subranges[0] == ranges[-1])

    res = gdb.run_cmd(f"pt -has {ranges[-1].va_start + ranges[-1].length}")
    subranges = parse_va_ranges(arch_name, res.output)
    assert(len(subranges) == 0)

@pytest.mark.parametrize("arch_name", get_all_arch())
def test_pt_before_command(arch_name):
    if arch_name == "arm_64":
        # BUG: needs gdb_pt_dump fix
        pytest.skip(reason = "The gdb_pt_dump aarch64 backend does not implement cut_before and cut_after.")

    vm = create_linux_vm(arch_name)
    vm.start()
    vm.wait_for_shell()

    gdb = GdbCommandExecutor(vm)
    monitor = QemuMonitorExecutor(vm)

    res = gdb.run_cmd("pt")
    ranges = parse_va_ranges(arch_name, res.output)
    assert(len(ranges) > 10)

    r0, r1, r2, r3 = ranges[0:4]

    res = gdb.run_cmd(f"pt -before {r0.va_start}")
    subranges = parse_va_ranges(arch_name, res.output)
    assert(len(subranges) == 0)

    res = gdb.run_cmd(f"pt -before {r0.va_start + r0.length}")
    subranges = parse_va_ranges(arch_name, res.output)
    assert(len(subranges) == 1)
    assert(subranges[0] == r0)

    res = gdb.run_cmd(f"pt -before {r0.va_start + 0x100}")
    subranges = parse_va_ranges(arch_name, res.output)
    assert(len(subranges) == 1)
    r_tmp = copy.deepcopy(r0)
    r_tmp.length = 0x100
    print(r0.va_start, subranges[0].va_start, subranges[0].length)
    assert(subranges[0] == r_tmp)

    res = gdb.run_cmd(f"pt -before {r2.va_start + r2.length}")
    subranges = parse_va_ranges(arch_name, res.output)
    assert(len(subranges) == 3)
    assert(subranges[0] == r0)
    assert(subranges[1] == r1)
    assert(subranges[2] == r2)

    res = gdb.run_cmd(f"pt -before {r3.va_start + r3.length - 0x100}")
    subranges = parse_va_ranges(arch_name, res.output)
    assert(len(subranges) == 4)
    assert(subranges[0] == r0)
    assert(subranges[1] == r1)
    assert(subranges[2] == r2)
    r_tmp = copy.deepcopy(r3)
    r_tmp.length = r3.length - 0x100
    assert(subranges[3] == r_tmp)

    res = gdb.run_cmd(f"pt -before {ranges[-1].va_start + ranges[-1].length}")
    subranges = parse_va_ranges(arch_name, res.output)
    assert(subranges == ranges)

@pytest.mark.parametrize("arch_name", get_all_arch())
def test_pt_after_command(arch_name):
    if arch_name == "arm_64":
        # BUG: needs gdb_pt_dump fix
        pytest.skip(reason = "The gdb_pt_dump aarch64 backend does not implement cut_before and cut_after.")

    vm = create_linux_vm(arch_name)
    vm.start()
    vm.wait_for_shell()

    gdb = GdbCommandExecutor(vm)
    monitor = QemuMonitorExecutor(vm)

    res = gdb.run_cmd("pt")
    ranges = parse_va_ranges(arch_name, res.output)
    assert(len(ranges) > 10)

    res = gdb.run_cmd(f"pt -after {ranges[-1].va_start}")
    subranges = parse_va_ranges(arch_name, res.output)
    assert(subranges == [ranges[-1]])

    res = gdb.run_cmd(f"pt -after {ranges[-1].va_start + ranges[-1].length}")
    subranges = parse_va_ranges(arch_name, res.output)
    assert(subranges == [])

    res = gdb.run_cmd(f"pt -after {ranges[-1].va_start + 0x100}")
    subranges = parse_va_ranges(arch_name, res.output)
    r_tmp = copy.deepcopy(ranges[-1])
    r_tmp.va_start += 0x100
    r_tmp.length = ranges[-1].length - 0x100
    assert(subranges == [r_tmp])

    res = gdb.run_cmd(f"pt -after {ranges[0].va_start}")
    subranges = parse_va_ranges(arch_name, res.output)
    assert(subranges == ranges)

@pytest.mark.parametrize("arch_name", get_all_arch())
def test_pt_before_after_combination(arch_name):
    if arch_name == "arm_64":
        # BUG: needs gdb_pt_dump fix
        pytest.skip(reason = "The gdb_pt_dump aarch64 backend does not implement cut_before and cut_after.")

    vm = create_linux_vm(arch_name)
    vm.start()
    vm.wait_for_shell()

    gdb = GdbCommandExecutor(vm)
    monitor = QemuMonitorExecutor(vm)

    res = gdb.run_cmd("pt")
    ranges = parse_va_ranges(arch_name, res.output)
    assert(len(ranges) > 10)

    res = gdb.run_cmd(f"pt -after {ranges[0].va_start} -before {ranges[-1].va_start + ranges[-1].length}")
    subranges = parse_va_ranges(arch_name, res.output)
    assert(subranges == ranges)

    res = gdb.run_cmd(f"pt -after {ranges[1].va_start} -before {ranges[-1].va_start}")
    subranges = parse_va_ranges(arch_name, res.output)
    assert(subranges == ranges[1:-1])

    res = gdb.run_cmd(f"pt -after {ranges[2].va_start} -before {ranges[3].va_start}")
    subranges = parse_va_ranges(arch_name, res.output)
    assert(subranges == [ranges[2]])

    res = gdb.run_cmd(f"pt -after {ranges[2].va_start} -before {ranges[3].va_start + ranges[3].length}")
    subranges = parse_va_ranges(arch_name, res.output)
    assert(subranges == ranges[2:4])

    res = gdb.run_cmd(f"pt -after {ranges[2].va_start + 0x200} -before {ranges[4].va_start + 0x300}")
    subranges = parse_va_ranges(arch_name, res.output)

    r2_tmp = copy.deepcopy(ranges[2])
    r2_tmp.va_start += 0x200
    r2_tmp.length = r2_tmp.length - 0x200
    r4_tmp = copy.deepcopy(ranges[4])
    r4_tmp.length = 0x300
    assert(subranges == [r2_tmp, ranges[3], r4_tmp])

@pytest.mark.parametrize("arch_name", get_all_arch())
def test_pt_kaslr(arch_name):
    virt_pattern = re.compile(r'Virt:\s+([0-9a-fA-Fx]+)')
    phys_pattern = re.compile(r'Phys:\s+([0-9a-fA-Fx]+)')

    vm = create_linux_vm(arch_name)
    vm.start(kaslr=False)
    vm.wait_for_shell()

    gdb = GdbCommandExecutor(vm)

    res = gdb.run_cmd("pt -kaslr")
    output = ansi_escape(res.output)
    virt_matches = virt_pattern.findall(output)
    phys_matches = phys_pattern.findall(output)

    assert(int(virt_matches[0], 16) == vm.get_default_base_image_kaddr())
    assert(int(phys_matches[0], 16) == vm.get_default_base_image_paddr())

    # BUG: not implemented in gdb_pt_dump for aarch64
    if arch_name != "arm_64":
        assert(int(virt_matches[1], 16) == vm.get_default_physmap_kaddr())

    del gdb
    vm.stop()

    for u in range(4):
        vm.start(kaslr=True)
        vm.wait_for_shell()
        gdb = GdbCommandExecutor(vm)
        res = gdb.run_cmd("pt -kaslr")
        output = ansi_escape(res.output)
        virt_matches = virt_pattern.findall(output)
        phys_matches = phys_pattern.findall(output)
        assert(int(virt_matches[0], 16) != 0)
        assert(int(phys_matches[0], 16) != 0)

        # BUG: not implemented in gdb_pt_dump for aarch64
        if arch_name != "arm_64":
            assert(int(virt_matches[1], 16) != 0)

        del gdb
        vm.stop()

def get_custom_binaries():
    custom_x86_64 = [("x86_64", bin) for bin in get_x86_64_binary_names()]
    custom_arm_64 = [("arm_64", bin) for bin in get_arm_64_binary_names()]
    return custom_x86_64 + custom_arm_64

@pytest.mark.parametrize("arch_name, image_name", get_custom_binaries())
def test_golden_images(request, arch_name, image_name):
    vm = create_custom_vm(arch_name, image_name)
    vm.start()
    vm.wait_for_string_on_line(b"Done")

    test_name = request.node.name

    gdb = GdbCommandExecutor(vm)
    generated_image_name = "/tmp/.gdb_pt_dump_{}".format(image_name)
    print("Generated image path is {}".format(generated_image_name))
    gdb.run_cmd("pt -o {}".format(generated_image_name))

    generated_data = None
    with open(generated_image_name, "r") as generated_file:
        generated_data = generated_file.read()

    golden_image = os.path.join(ImageContainer().get_custom_kernels_golden_images(arch_name), image_name)
    expected_data = None
    with open(golden_image, "r") as golden_image_file:
        expected_data = golden_image_file.read()

    assert(expected_data == generated_data)

if __name__ == "__main__":
    print("This code should be invoked via 'pytest':", file=sys.stderr)
    print("")
    print("    pytest run_integration_tests.py")
    print("")

