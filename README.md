# gdb-pt-dumper

`gdb-pt-dumper` is a gdb script to parse a guest page table and dump it to stdout in a pretty way.
Although this is also possible via `monitor info mem`, the QEMU monitor provides less and sometimes incorrect information, and does not handle efficiently cases when many small pages are mapped.

# Features

* Dumping a page from a specific guest physical address.
* Merging semantically-similar contiguous memory.
* Provide detailed architectural information: writeable, executable, U/S, cacheable, write-back.
* Cache collected information for future filtering and printing.
* Filter page table information.

# How to use

The script is standalone but I hope that it eventually makes it way into `pwndbg` and/or `gef`.

For now, do `source PATH_TO_PT_DUMPER/pt.py`.

For details, just do `help pt` in gdb.

# Examples

![Write or Executable](example_pictures/w_or_x.jpg "Write or Executable")

![User mappings](example_pictures/user.jpg "User mappings")

![More filters](example_pictures/more.jpg "More filters")

# Supported architectures

Currently, only `x86-64` is supported but `aarch64` is underway.
