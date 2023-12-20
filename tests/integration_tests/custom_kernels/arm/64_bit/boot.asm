.extern entry
.global _start
.section .boot
_start:
	mov x30, 0x800000
	mov sp, x30
	bl entry
hang:
	b hang
