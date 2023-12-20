
all: custom_kernels

custom_kernels: custom_kernels_x86_64 custom_kernels_arm_64

custom_kernels_x86_64:
	make -C custom_kernels/x86/64_bit/
	cp custom_kernels/x86/64_bit/*.bin images/custom_kernels/x86_64/

custom_kernels_arm_64:
	make -C custom_kernels/arm/64_bit/
	cp custom_kernels/arm/64_bit/*.bin images/custom_kernels/arm_64/

clean:
	make -C custom_kernels/x86/64_bit/ clean
	make -C custom_kernels/arm/64_bit/ clean
