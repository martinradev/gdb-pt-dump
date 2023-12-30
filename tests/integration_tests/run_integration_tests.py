#!/usr/bin/env pytest

import os
import copy
import re
import pytest
import sys
import filecmp

from vm_utils import *
from pt_utils import *

def verify_all_search_occurrences(monitor, occs, mem_len, checker):
    for occ in occs:
        memory = monitor.read_virt_memory(occ.occ_va, mem_len)
        assert(checker(occ, memory))

def get_all_arch():
    return ["x86_64", "arm_64", "riscv"]

def get_all_images():
    return [("x86_64", "linux_x86_64"), ("arm_64", "linux_arm_64_4k"), ("arm_64", "linux_arm_64_4k_kpti"), ("arm_64", "linux_arm_64_64k"), ("riscv", "linux_riscv")]

def create_resources(arch_name, linux_image, kaslr):
    vm = create_linux_vm(arch_name, linux_image)
    vm.start(kaslr=kaslr)
    vm.wait_for_shell()
    gdb = GdbCommandExecutor(vm)
    monitor = QemuMonitorExecutor(vm)

    if bool(os.getenv("GDB_PT_DUMP_TESTS_PAUSE_AFTER_BOOT")) == True:
        print("Sleeping...")
        time.sleep(10000)

    return (vm, gdb, monitor)

@pytest.fixture
def create_resources_fixture_nokaslr(arch_name, linux_image):
    vm, gdb, monitor = create_resources(arch_name, linux_image, kaslr=False)
    yield (vm, gdb, monitor)
    monitor.stop()
    vm.stop()

@pytest.fixture
def create_resources_fixture(arch_name, linux_image):
    vm, gdb, monitor = create_resources(arch_name, linux_image, kaslr=True)
    yield (vm, gdb, monitor)
    monitor.stop()
    vm.stop()

@pytest.mark.parametrize("arch_name, linux_image", get_all_images())
def test_pt_smoke(create_resources_fixture, arch_name, linux_image):
    vm, gdb, monitor = create_resources_fixture
    res = gdb.run_cmd("pt")

@pytest.mark.parametrize("arch_name, linux_image", get_all_images())
def test_pt_filter_smoke(create_resources_fixture, arch_name, linux_image):
    vm, gdb, monitor = create_resources_fixture
    gdb.run_cmd("pt")
    gdb.run_cmd("pt -filter x")
    gdb.run_cmd("pt -filter w")
    gdb.run_cmd("pt -filter ro")
    gdb.run_cmd("pt -filter w|x")
    gdb.run_cmd("pt -filter u")
    gdb.run_cmd("pt -filter s")
    gdb.run_cmd("pt -filter w x")

@pytest.mark.parametrize("arch_name, linux_image", get_all_images())
def test_pt_kaslr_smoke(create_resources_fixture, arch_name, linux_image):
    vm, gdb, monitor = create_resources_fixture
    res = gdb.run_cmd("pt -kaslr")

@pytest.mark.parametrize("arch_name, linux_image", get_all_images())
def test_pt_phys_verbose_smoke(create_resources_fixture, arch_name, linux_image):
    vm, gdb, monitor = create_resources_fixture
    res = gdb.run_cmd("pt -phys_verbose")

def _test_pt_search(vm, gdb, monitor, search_command, mem_len, checker):
    res = gdb.run_cmd(search_command)
    monitor.pause()
    occs = parse_occurrences(vm.get_arch(), res.output)
    assert(len(occs) > 0)
    verify_all_search_occurrences(monitor, occs, mem_len, checker)

@pytest.mark.parametrize("arch_name, linux_image", get_all_images())
def test_pt_search_string(create_resources_fixture, arch_name, linux_image):
    vm, gdb, monitor = create_resources_fixture
    checker = lambda _, mem: mem == b"Linux"
    _test_pt_search(vm, gdb, monitor, "pt -ss Linux", 5, checker)

@pytest.mark.parametrize("arch_name, linux_image", get_all_images())
def test_pt_search_s4(create_resources_fixture, arch_name, linux_image):
    vm, gdb, monitor = create_resources_fixture
    checker = lambda _, mem: mem == b"\x41\x41\x41\x41"
    _test_pt_search(vm, gdb, monitor, "pt -s4 0x41414141", 4, checker)

@pytest.mark.parametrize("arch_name, linux_image", get_all_images())
def test_pt_search_s8(create_resources_fixture, arch_name, linux_image):
    vm, gdb, monitor = create_resources_fixture
    checker = lambda _, mem: mem == b"\xfe\xff\xff\xff\xff\xff\xff\xff"
    _test_pt_search(vm, gdb, monitor, "pt -s8 0xfffffffffffffffe", 8, checker)

@pytest.mark.parametrize("arch_name, linux_image", get_all_images())
def test_pt_range_exists(create_resources_fixture, arch_name, linux_image):
    vm, gdb, monitor = create_resources_fixture
    res = gdb.run_cmd(f"pt")
    monitor.pause()

    ranges = parse_va_ranges(arch_name, res.output)
    assert(len(ranges) > 0)
    for r in ranges:
        print("Range base is", hex(r.va_start))
        addr = r.va_start
        data = monitor.read_virt_memory(addr, 4)
        assert(len(data) == 4)

        # BUG: for some reason qemu does not allow reading these physical addresses
        if r.va_start == 0xffff800010010000 or r.va_start == 0xffff800010030000 or r.va_start == 0xffffffc008010000 or r.va_start == 0xffffffc008030000 or r.va_start == 0xfffffe0008020000 or r.va_start == 0xfffffe0008040000 or r.va_start == 0xfffffe0008060000 or r.va_start == 0xfffffe00084e0000 or r.va_start == 0xff20000000245000 or r.va_start == 0xff2000000024d000:
            print(f"Skip reading {hex(r.va_start)} due to a weird qemu bug")
            continue

        addr = r.va_start + int(r.length / 2)
        data = monitor.read_virt_memory(addr, 4)
        assert(len(data) == 4)

        addr = r.va_start + r.length - 4
        data = monitor.read_virt_memory(addr, 4)
        assert(len(data) == 4)

@pytest.mark.parametrize("arch_name, linux_image", get_all_images())
def test_pt_walk_many_ranges(create_resources_fixture, arch_name, linux_image):
    vm, gdb, monitor = create_resources_fixture
    res = gdb.run_cmd(f"pt")
    monitor.pause()

    ranges = parse_va_ranges(arch_name, res.output)
    assert(len(ranges) > 0)
    for r in ranges[0:16]:
        output = gdb.run_cmd(f"pt -walk {hex(r.va_start)}")
        assert("Last stage faulted" not in output.output)

        output = gdb.run_cmd(f"pt -walk {hex(int(r.va_start + r.length / 2))}")
        assert("Last stage faulted" not in output.output)

        output = gdb.run_cmd(f"pt -walk {hex(r.va_start + r.length - 1)}")
        assert("Last stage faulted" not in output.output)

@pytest.mark.parametrize("arch_name, linux_image", get_all_images())
def test_pt_walk_first_stage_fault(create_resources_fixture, arch_name, linux_image):
    vm, gdb, monitor = create_resources_fixture
    res = gdb.run_cmd(f"pt")
    monitor.pause()

    ranges = parse_va_ranges(arch_name, res.output)
    assert(len(ranges) > 0)

    unmapped_address = ranges[0].va_start - 0x100
    output = gdb.run_cmd(f"pt -walk {hex(unmapped_address)}")
    assert("Last stage faulted" in output.output)

def _test_pt_filter_common(vm, gdb, monitor, executions):
    for (_cmd, _check) in executions:
        print(f"Running {_cmd}")
        res = gdb.run_cmd(_cmd)
        monitor.pause()

        ranges = parse_va_ranges(vm.get_arch(), res.output)
        assert(len(ranges) > 0)
        for r in ranges:
            assert(_check(r))

@pytest.mark.parametrize("arch_name, linux_image", get_all_images())
def test_pt_filter_executable(create_resources_fixture, arch_name, linux_image):
    vm, gdb, monitor = create_resources_fixture
    executions = [("pt -filter x", lambda r: r.flags.executable()), ("pt -filter _x", lambda r: not r.flags.executable())]
    _test_pt_filter_common(vm, gdb, monitor, executions)

@pytest.mark.parametrize("arch_name, linux_image", get_all_images())
def test_pt_filter_writeable(create_resources_fixture, arch_name, linux_image):
    vm, gdb, monitor = create_resources_fixture
    executions = [("pt -filter w", lambda r: r.flags.writeable()), ("pt -filter _w", lambda r: not r.flags.writeable())]
    _test_pt_filter_common(vm, gdb, monitor, executions)

@pytest.mark.parametrize("arch_name, linux_image", get_all_images())
def test_pt_filter_read_only(create_resources_fixture, arch_name, linux_image):
    vm, gdb, monitor = create_resources_fixture
    executions = [("pt -filter ro", lambda r: (not r.flags.user_executable() and not r.flags.user_writeable()) or (not r.flags.super_executable() and not r.flags.super_writeable()))]
    _test_pt_filter_common(vm, gdb, monitor, executions)

@pytest.mark.parametrize("arch_name, linux_image", get_all_images())
def test_pt_filter_user_accessible(create_resources_fixture, arch_name, linux_image):
    if arch_name == "arm_64" and "kpti" in linux_image:
        # BUG: needs another kernel image
        pytest.skip(reason = "User ranges are never visible because user page table is unmapped")
    vm, gdb, monitor = create_resources_fixture
    executions = [("pt -filter u", lambda r: r.flags.user_accessible())]
    _test_pt_filter_common(vm, gdb, monitor, executions)

@pytest.mark.parametrize("arch_name, linux_image", get_all_images())
def test_pt_filter_kernel_only_accessible(create_resources_fixture, arch_name, linux_image):
    if arch_name == "arm_64" and "kpti" in linux_image:
        # BUG: needs another kernel image
        pytest.skip(reason = "The _s would result into 0 ranges because user page table is unmapped.")
    executions = [("pt -filter s", lambda r: r.flags.super_accessible())]
    vm, gdb, monitor = create_resources_fixture
    _test_pt_filter_common(vm, gdb, monitor, executions)

@pytest.mark.parametrize("arch_name, linux_image", get_all_images())
def test_pt_filter_multiple_filters_user(create_resources_fixture, arch_name, linux_image):
    if arch_name == "arm_64" and "kpti" in linux_image:
        # BUG: needs another kernel image
        pytest.skip(reason = "This would result into 0 ranges because user page table is unmapped.")
    executions = [ \
                  ("pt -filter w u", lambda r: r.flags.user_writeable()), \
                 ]
    vm, gdb, monitor = create_resources_fixture
    _test_pt_filter_common(vm, gdb, monitor, executions)

@pytest.mark.parametrize("arch_name, linux_image", get_all_images())
def test_pt_filter_multiple_filters_super(create_resources_fixture, arch_name, linux_image):
    executions = [ \
                  ("pt -filter w s", lambda r: r.flags.super_writeable()), \
                  ("pt -filter x s", lambda r: r.flags.super_executable()), \
                 ]
    vm, gdb, monitor = create_resources_fixture
    _test_pt_filter_common(vm, gdb, monitor, executions)

@pytest.mark.parametrize("arch_name, linux_image", get_all_images())
def test_pt_filter_and_search(create_resources_fixture, arch_name, linux_image):
    checker = lambda occ, data: occ.virt_range.flags.writeable() == True and data == b"Linux"
    vm, gdb, monitor = create_resources_fixture
    _test_pt_search(vm, gdb, monitor, "pt -ss Linux -filter w", 5, checker)

    checker = lambda occ, data: \
        ((occ.virt_range.flags.user_executable() == False and occ.virt_range.flags.user_executable() == False) or \
        (occ.virt_range.flags.super_executable() == False and occ.virt_range.flags.super_executable() == False)) and \
        data == b"Linux"
    _test_pt_search(vm, gdb, monitor, "pt -ss Linux -filter ro", 5, checker)

@pytest.mark.parametrize("arch_name, linux_image", get_all_images())
def test_pt_range_command(create_resources_fixture, arch_name, linux_image):
    vm, gdb, monitor = create_resources_fixture

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

@pytest.mark.parametrize("arch_name, linux_image", get_all_images())
def test_pt_has_command(create_resources_fixture, arch_name, linux_image):
    vm, gdb, monitor = create_resources_fixture

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

@pytest.mark.parametrize("arch_name, linux_image", get_all_images())
def test_pt_before_command(create_resources_fixture, arch_name, linux_image):
    if arch_name == "arm_64":
        # BUG: needs gdb_pt_dump fix
        pytest.skip(reason = "The gdb_pt_dump aarch64 backend does not implement cut_before and cut_after.")

    vm, gdb, monitor = create_resources_fixture

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

@pytest.mark.parametrize("arch_name, linux_image", get_all_images())
def test_pt_after_command(create_resources_fixture, arch_name, linux_image):
    if arch_name == "arm_64":
        # BUG: needs gdb_pt_dump fix
        pytest.skip(reason = "The gdb_pt_dump aarch64 backend does not implement cut_before and cut_after.")

    vm, gdb, monitor = create_resources_fixture

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

@pytest.mark.parametrize("arch_name, linux_image", get_all_images())
def test_pt_before_after_combination(create_resources_fixture, arch_name, linux_image):
    if arch_name == "arm_64":
        # BUG: needs gdb_pt_dump fix
        pytest.skip(reason = "The gdb_pt_dump aarch64 backend does not implement cut_before and cut_after.")

    vm, gdb, monitor = create_resources_fixture

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

@pytest.mark.parametrize("arch_name, linux_image", get_all_images())
def test_pt_kaslr(create_resources_fixture_nokaslr, arch_name, linux_image):
    virt_pattern = re.compile(r'Virt:\s+([0-9a-fA-Fx]+)')
    phys_pattern = re.compile(r'Phys:\s+([0-9a-fA-Fx]+)')

    vm, gdb, monitor = create_resources_fixture_nokaslr

    res = gdb.run_cmd("pt -kaslr")
    output = ansi_escape(res.output)
    virt_matches = virt_pattern.findall(output)
    phys_matches = phys_pattern.findall(output)

    assert(int(virt_matches[0], 16) in vm.get_default_base_image_kaddr())
    assert(int(phys_matches[0], 16) in vm.get_default_base_image_paddr())

    # BUG: not implemented in gdb_pt_dump for aarch64
    if arch_name != "arm_64":
        assert(int(virt_matches[1], 16) == vm.get_default_physmap_kaddr())

    vm.stop()

    for u in range(4):
        vm.start(kaslr=True)
        vm.wait_for_shell()
        res = gdb.run_cmd("pt -kaslr")
        output = ansi_escape(res.output)
        virt_matches = virt_pattern.findall(output)
        phys_matches = phys_pattern.findall(output)
        assert(int(virt_matches[0], 16) != 0)
        assert(int(phys_matches[0], 16) != 0)

        # BUG: not implemented in gdb_pt_dump for aarch64
        if arch_name != "arm_64":
            assert(int(virt_matches[1], 16) != 0)

        vm.stop()

def get_custom_binaries():
    custom_x86_64 = [("x86_64", bin) for bin in get_x86_64_binary_names()]
    custom_arm_64 = [("arm_64", bin) for bin in get_arm_64_binary_names()]
    return custom_x86_64 + custom_arm_64

@pytest.fixture
def create_custom_resources_fixture(arch_name, image_name):
    vm = create_custom_vm(arch_name, image_name)
    vm.start()
    vm.wait_for_string_on_line(b"Done")
    gdb = GdbCommandExecutor(vm)
    monitor = QemuMonitorExecutor(vm)

    if bool(os.getenv("GDB_PT_DUMP_TESTS_PAUSE_AFTER_BOOT")) == True:
        print("Sleeping...")
        time.sleep(10000)

    yield (vm, gdb, monitor)
    monitor.stop()
    vm.stop()

@pytest.mark.parametrize("arch_name, image_name", get_custom_binaries())
def test_golden_images(request, create_custom_resources_fixture, arch_name, image_name):
    vm, gdb, monitor = create_custom_resources_fixture
    test_name = request.node.name
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

@pytest.mark.parametrize("arch_name, image_name", get_custom_binaries())
def test_phys_verbose_golden_images(request, create_custom_resources_fixture, arch_name, image_name):
    vm, gdb, monitor = create_custom_resources_fixture
    test_name = request.node.name
    generated_image_name = "/tmp/.gdb_pt_dump_phys_verbose_{}".format(image_name)
    print("Generated image path is {}".format(generated_image_name))
    gdb.run_cmd("pt -phys_verbose -o {}".format(generated_image_name))

    generated_data = None
    with open(generated_image_name, "r") as generated_file:
        generated_data = generated_file.read()

    golden_image = os.path.join(ImageContainer().get_custom_kernels_golden_images(arch_name), "phys_verbose_{}".format(image_name))
    expected_data = None
    with open(golden_image, "r") as golden_image_file:
        expected_data = golden_image_file.read()

    assert(expected_data == generated_data)

@pytest.mark.parametrize("arch_name, image_name", get_custom_binaries())
def test_pt_walk_golden_images(request, create_custom_resources_fixture, arch_name, image_name):
    vm, gdb, monitor = create_custom_resources_fixture
    test_name = request.node.name
    generated_image_name = "/tmp/.gdb_pt_dump_pt_walk_{}".format(image_name)
    print("Generated image path is {}".format(generated_image_name))
    gdb.run_cmd("pt -walk 0x2000 -o {}".format(generated_image_name))

    generated_data = None
    with open(generated_image_name, "r") as generated_file:
        generated_data = generated_file.read()

    golden_image = os.path.join(ImageContainer().get_custom_kernels_golden_images(arch_name), "pt_walk_{}".format(image_name))
    expected_data = None
    with open(golden_image, "r") as golden_image_file:
        expected_data = golden_image_file.read()

    assert(expected_data == generated_data)

def test_pt_x86_32():
    vm = VM_X86_64(ImageContainer().get_kolibri_x86_32(), fda_name = "kolibri.img")
    vm.start()

    time.sleep(15)

    gdb = GdbCommandExecutor(vm)
    res = gdb.run_cmd("pt")
    ranges = parse_va_ranges("x86_64", res.output)
    assert(len(ranges) > 0)

    monitor = QemuMonitorExecutor(vm)

    for r in ranges:
        addr = r.va_start
        data = monitor.read_virt_memory(addr, 4)
        assert(len(data) == 4)

    res = gdb.run_cmd(f"pt -walk {hex(ranges[0].va_start)}")
    assert("Last stage faulted" not in res.output)

    res = gdb.run_cmd("pt -ss Kolibri")
    occs = parse_occurrences("x86_64", res.output)
    assert(len(occs) > 1)

    monitor.stop()
    vm.stop()

@pytest.mark.parametrize("arch_name, linux_image", get_all_images())
def test_pt_read_virt_memory(create_resources_fixture_nokaslr, arch_name, linux_image):
    vm, gdb, monitor = create_resources_fixture_nokaslr

    res = gdb.run_cmd("pt")
    ranges = parse_va_ranges(arch_name, res.output)

    for r in ranges[:10]:
        gdb.run_cmd(f"pt -read_virt {hex(r.va_start)} {r.length} -o /tmp/virt_dump.bin")
        gdb.run_cmd(f"dump binary memory /tmp/qemu_virt_dump.bin {hex(r.va_start)} {hex(r.va_start + r.length)}")
        assert(filecmp.cmp("/tmp/virt_dump.bin", "/tmp/qemu_virt_dump.bin"))

if __name__ == "__main__":
    print("This code should be invoked via 'pytest':", file=sys.stderr)
    print("")
    print("    pytest run_integration_tests.py")
    print("")

