
test_list = \
	setup_2mb_page_table_simple \
	setup_4k_page_table_complex \
	setup_4k_page_table_simple

tests_x86_64: $(foreach test_name,$(test_list),$(addsuffix .bin,$(test_name)))

define generate_test

$(1).bin: boot.o entry_$(1).o linker.ld
	echo "Creating $(1)"
	ld -m elf_x86_64 -Tlinker.ld -o x86_64_test_entry_$(1).bin entry_$(1).o boot.o

entry_$(1).o: entry.c ../../common/common.h ../common/common_x86.h
	gcc -DGDB_PT_DUMP_TEST=$(1) entry.c -I./ -I../../common/ -I../common/ -Wall -Wextra -Werror -O3 -fno-builtin -m64 -no-pie -fno-PIE -ffreestanding -nostdlib -c -o entry_$(1).o

endef

$(foreach test_name,$(test_list),$(eval $(call generate_test,$(test_name))))

boot.o: boot.asm
	nasm boot.asm -f elf64 -o boot.o

clean:
	find . -name "*.o" -exec rm {} \;
	find . -name "*.bin" -exec rm {} \;
