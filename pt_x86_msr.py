from pt_register import *

class PT_CR0(PT_Register):
    def __init__(self):
        super(PT_CR0, self).__init__("cr0", "Control Register 0")
        self.add_range("PE (Protected Mode Enable)", 0, 0, PT_Decipher_Meaning_Match({0: "Protected mode", 1: "Real mode"}))
        self.add_range("MP (Monitor co-processor)", 1, 1, PT_Decipher_Meaning_Passthrough)
        self.add_range("EM (Emulation)", 2, 2, PT_Decipher_Meaning_Match({1: "No x87 FPU present", 0: "x87 FPU present"}))
        self.add_range("TS (Task switched)", 3, 3, PT_Decipher_Meaning_Passthrough)
        self.add_range("ET (Extension type)", 4, 4, PT_Decipher_Meaning_Passthrough)
        self.add_range("NE (Numeric error)", 5, 5, PT_Decipher_Meaning_Passthrough)
        self.add_range("WP (Write protect)", 16, 16, PT_Decipher_Meaning_Passthrough)
        self.add_range("AM (Alignment mask)", 18, 18, PT_Decipher_Meaning_Passthrough)
        self.add_range("NW (Not write-through)", 29, 29, PT_Decipher_Meaning_Passthrough)
        self.add_range("CD (Cache disable)", 30, 30, PT_Decipher_Meaning_Passthrough)
        self.add_range("PG (Paging)", 31, 31, PT_Decipher_Meaning_Passthrough)

class PT_CR4(PT_Register):
    def __init__(self):
        super(PT_CR4, self).__init__("cr4", "Control Register 4")
        self.add_range("VME (Virtual 8086 Mode Extensions)", 0, 0, PT_Decipher_Meaning_Passthrough)
        self.add_range("PVI (Protected-model virtual interrupts)", 1, 1, PT_Decipher_Meaning_Passthrough)
        self.add_range("TSD (Time Stamp Disable)", 2, 2, PT_Decipher_Meaning_Passthrough)
        self.add_range("DE (Debugging Extensions)", 3, 3, PT_Decipher_Meaning_Passthrough)
        self.add_range("PSE (Page Size Extension)", 4, 4, PT_Decipher_Meaning_Passthrough)
        self.add_range("PAE (Physical Address Extension)", 5, 5, PT_Decipher_Meaning_Passthrough)
        self.add_range("MCE (Machine Check Exception)", 6, 6, PT_Decipher_Meaning_Passthrough)
        self.add_range("PGE (Page Global Enabled)", 7, 7, PT_Decipher_Meaning_Passthrough)
        self.add_range("PCE (Performance Monitor Counter Enable)", 8, 8, PT_Decipher_Meaning_Passthrough)
        self.add_range("OSFXSR", 9, 9, PT_Decipher_Meaning_Passthrough)
        self.add_range("OSXMMEXCPT", 10, 10, PT_Decipher_Meaning_Passthrough)
        self.add_range("UMIP (User mode instruction prevention)", 11, 11, PT_Decipher_Meaning_Passthrough)
        self.add_range("LA57", 12, 12, PT_Decipher_Meaning_Passthrough)
        self.add_range("VMXE", 13, 13, PT_Decipher_Meaning_Passthrough)
        self.add_range("SMXE", 14, 14, PT_Decipher_Meaning_Passthrough)
        self.add_range("FSGSBASE", 16, 16, PT_Decipher_Meaning_Passthrough)
        self.add_range("PCIDE", 17, 17, PT_Decipher_Meaning_Passthrough)
        self.add_range("OSXSAVE", 18, 18, PT_Decipher_Meaning_Passthrough)
        self.add_range("SMEP", 20, 20, PT_Decipher_Meaning_Passthrough)
        self.add_range("SMAP", 21, 21, PT_Decipher_Meaning_Passthrough)
        self.add_range("PKE", 22, 22, PT_Decipher_Meaning_Passthrough)

pt_cr0 = PT_CR0()
pt_cr4 = PT_CR4()

