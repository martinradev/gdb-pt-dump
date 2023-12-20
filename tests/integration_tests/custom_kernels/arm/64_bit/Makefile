
test_list = \
	test_granularity_4k \
	test_granularity_16k \
	test_granularity_64k

tests_arm64: $(foreach test_name,$(test_list),$(addsuffix .bin,$(test_name)))

define generate_test

$(1).bin: boot.o entry_$(1).o linker.ld
	echo "Creating $(1)"
	aarch64-linux-gnu-ld -Bstatic -nostdlib -Tlinker.ld -o tmp_arm_test_entry_$(1).elf boot.o entry_$(1).o
	aarch64-linux-gnu-objcopy -O binary tmp_arm_test_entry_$(1).elf arm_test_entry_$(1).bin

entry_$(1).o: entry.c ../../common/common.h
	aarch64-linux-gnu-gcc -DGDB_PT_DUMP_TEST=$(1) entry.c -I./ -I../../common -Wall -Wextra -O3 -fno-builtin -no-pie -fno-PIE -ffreestanding -nostdlib -c -o entry_$(1).o

endef

$(foreach test_name,$(test_list),$(eval $(call generate_test,$(test_name))))

boot.o: boot.asm
	aarch64-linux-gnu-as boot.asm -o boot.o

clean:
	find . -name "*.elf" -exec rm {} \;
	find . -name "*.o" -exec rm {} \;
	find . -name "*.bin" -exec rm {} \;
