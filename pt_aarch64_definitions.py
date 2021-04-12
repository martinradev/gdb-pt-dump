from pt_register import *

# Used the `Armv8, for Armv8-A architecture profile` manual.
# I hope this doesn't break any license. Please don't sue :(

class PT_TCR(PT_Register):
    def __init__(self):
        super(PT_TCR, self).__init__("TCR_EL1", "Translation Control Register EL1 (TCR EL1)")
        self.add_range("T0SZ", 0, 5, lambda x: f"{x} bits are truncated. TTBR0_EL1 addresses {64 - x} bits.")
        self.add_range("EPD0", 7, 7, PT_Decipher_Meaning_Match( \
            {0: "Perform translation table walk using TTBR0_EL1", \
             1: "A TLB miss on an address translated from TTBR0_EL1 generates a Translation fault. No translation table walk is performed."}))
        self.add_range("IRGN0", 8, 9, PT_Decipher_Meaning_Passthrough)
        self.add_range("ORGN0", 10, 11, PT_Decipher_Meaning_Passthrough)
        self.add_range("SH0", 12, 13, PT_Decipher_Meaning_Match( \
            {0b00: "Non-shareable.", \
             0b01: "Reserved.", \
             0b10: "Outer Shareable.", \
             0b11: "Inner Shareable."}))
        self.add_range("TG0", 14, 15, PT_Decipher_Meaning_Match( \
            {0b00: "4 KiB TTBR0_EL1 granule size", \
             0b01: "64 KiB TTBR0_EL1 granule size.", \
             0b10: "16 KiB TTBR0_EL1 granule size."}))
        self.add_range("T1SZ", 16, 21, lambda x: f"{x} bits are truncated. TTBR1_EL1 addresses {64 - x} bits.")
        self.add_range("A1", 22, 22, PT_Decipher_Meaning_Match( \
            {0: "TTBR0_EL1.ASID defines the ASID.", \
             1: "TTBR1_EL1.ASID defines the ASID."}))
        self.add_range("EPD1", 23, 23, PT_Decipher_Meaning_Match( \
            {0: "Perform translation table walk using TTBR1_EL1", \
             1: "A TLB miss on an address translated from TTBR1_EL1 generates a Translation fault. No translation table walk is performed."}))
        self.add_range("IRGN1", 24, 25, PT_Decipher_Meaning_Passthrough)
        self.add_range("ORGN1", 26, 27, PT_Decipher_Meaning_Passthrough)
        self.add_range("SH1", 28, 29, PT_Decipher_Meaning_Match( \
            {0b00: "Non-shareable.", \
             0b01: "Reserved.", \
             0b10: "Outer Shareable.", \
             0b11: "Inner Shareable."}))
        self.add_range("TG1", 30, 31, PT_Decipher_Meaning_Match( \
            {0b01: "16 KiB TTBR1_EL1 granule size", \
             0b10: "4 KiB TTBR1_EL1 granule size.", \
             0b11: "64 KiB TTBR1_EL1 granule size."}))
        self.add_range("IPS", 32, 34, PT_Decipher_Meaning_Match( \
            {0b000: "32 bits, 4 GB.", \
             0b001: "36 bits, 64 GB.", \
             0b010: "40 bits, 1 TB.", \
             0b011: "42 bits, 4 TB.", \
             0b100: "44 bits, 16 TB.", \
             0b101: "48 bits, 256 TB.", \
             0b110: "52 bits, 4 PB."}))
        self.add_range("AS", 36, 36, PT_Decipher_Meaning_Match( \
            {0: "8 bit - the upper 8 bits of TTBR0_EL1 and TTBR1_EL1 are ignored by hardware.", \
             1: "16 bit - the upper 16 bits of TTBR0_EL1 and TTBR1_EL1 are used for allocation and matching in the TLB."}))
        self.add_range("TBI0", 37, 37, PT_Decipher_Meaning_Match( \
            {0: "Top Byte used in the address calculation.",
             1: "Top Byte ignored in the address calculation."}))
        self.add_range("TBI1", 38, 38, PT_Decipher_Meaning_Match( \
            {0: "Top Byte used in the address calculation.",
             1: "Top Byte ignored in the address calculation."}))
 
pt_tcr = PT_TCR()
