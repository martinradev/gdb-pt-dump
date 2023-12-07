#pragma once

#include <stdint.h>
#include <stddef.h>

#define ONE_KB (1U * 1024U)
#define FOUR_KB (ONE_KB * 4U)
#define TWO_MB (2U * 1024U * 1024U)
#define ONE_GIB (1024U * 1024U * 1024U)

typedef volatile uint64_t* table_t;

typedef struct {
    uint64_t present                  : 1;  // Page table present flag
    uint64_t write                    : 1;  // Read/write flag
    uint64_t user                     : 1;  // User/supervisor flag
    uint64_t pwt                      : 1;  // Page-level write-through flag
    uint64_t pcd                      : 1;  // Page-level cache disable flag
    uint64_t accessed                 : 1;  // Accessed flag
    uint64_t ignored                  : 1;  // Accessed flag
    uint64_t page_size                : 1;  // Must be 0 for PDPE
    uint64_t ignored2                 : 4;  // Global page flag
    uint64_t page_frame               : 40; // Physical address of the 4-KByte page table
    uint64_t reserved3                : 11; // Reserved, set to 0
    uint64_t nx                       : 1;  // Execute disable flag
} pml4e;
typedef volatile pml4e* pml4_t;

typedef struct {
    uint64_t present                  : 1;  // Page table present flag
    uint64_t write                    : 1;  // Read/write flag
    uint64_t user                     : 1;  // User/supervisor flag
    uint64_t pwt                      : 1;  // Page-level write-through flag
    uint64_t pcd                      : 1;  // Page-level cache disable flag
    uint64_t accessed                 : 1;  // Accessed flag
    uint64_t dirty                    : 1;  // Accessed flag
    uint64_t page_size                : 1;  // Must be 0 for PDPE
    uint64_t global                   : 1;  // Global page flag
    uint64_t available                : 3;  // Available for software use
    uint64_t page_frame               : 40; // Physical address of the 4-KByte page table
    uint64_t reserved3                : 11; // Reserved, set to 0
    uint64_t nx                       : 1;  // Execute disable flag
} pdpe;
typedef volatile pdpe* pdp_t;

typedef struct {
    uint64_t present        : 1; // Page present in memory
    uint64_t write          : 1; // Writeable
    uint64_t user           : 1; // User-mode accessible
    uint64_t pwt            : 1; // Write-Through caching
    uint64_t pcd            : 1; // Cache Disabled
    uint64_t accessed       : 1; // Page has been accessed
    uint64_t dirty          : 1; // Page has been written to
    uint64_t page_size      : 1; // 1 if this entry maps a 2MiB page
    uint64_t global         : 1; // If set, the page won't be flushed from the TLB on CR3 writes
    uint64_t reserved       : 3; // Reserved bits (must be 0)
    uint64_t page_frame     : 40; // Physical address of the 4KB page frame or 1GB page frame
    uint64_t reserved3      : 11; // Reserved bits (must be 0)
    uint64_t nx             : 1;  // No Execute (NX) bit
} pde;
typedef volatile pde* pd_t;

typedef struct {
    uint64_t present        : 1;  // Page present in memory
    uint64_t write          : 1;  // Writeable
    uint64_t user           : 1;  // User-mode accessible
    uint64_t pwt            : 1;  // Write-Through caching
    uint64_t pcd            : 1;  // Cache Disabled
    uint64_t accessed       : 1;  // Page has been accessed
    uint64_t dirty          : 1;  // Page has been written to
    uint64_t pat            : 1;  // 1 if this entry maps a 2MiB page
    uint64_t global         : 1;  // If set, the page won't be flushed from the TLB on CR3 writes
    uint64_t reserved       : 3;  // Reserved bits (must be 0)
    uint64_t page_frame     : 40; // Physical address of the 4KB page frame or 1GB page frame
    uint64_t reserved2      : 11; // Reserved
    uint64_t nx             : 1;  // NX
} pte;
typedef volatile pte* pt_t;

inline uint64_t page_frame(const uint64_t addr) {
    return addr >> 12;
}

inline uint64_t pa(volatile const void *const addr) {
    return (uint64_t)addr;
}

inline void *va_ptr(volatile void *addr) {
    return (void *)addr;
}

inline void outb(uint16_t port, uint8_t value) {
    // Inline assembly to use the out instruction
    asm volatile ("outb %0, %1" : : "a"(value), "Nd"(port));
}

inline uint8_t inb(uint16_t port) {
    uint8_t data;
    asm volatile ("inb %w1, %b0" : "=a"(data) : "Nd"(port));
    return data;
}

#define IO_PORT 0x3f8

static void setup_serial() {
    // Copied from https://stackoverflow.com/questions/69481715/initialize-serial-port-with-x86-assembly
    outb(IO_PORT + 1, 0x00);    // Disable all interrupts
    outb(IO_PORT + 3, 0x80);    // Enable DLAB (set baud rate divisor)
    outb(IO_PORT + 0, 0x03);    // Set divisor to 3 (lo byte) 38400 baud
    outb(IO_PORT + 1, 0x00);    //                  (hi byte)
    outb(IO_PORT + 3, 0x03);    // 8 bits, no parity, one stop bit
    outb(IO_PORT + 2, 0xC7);    // Enable FIFO, clear them, with 14-byte threshold
    outb(IO_PORT + 4, 0x0B);    // IRQs enabled, RTS/DSR set
    outb(IO_PORT + 4, 0x1E);    // Set in loopback mode, test the serial chip
    outb(IO_PORT + 0, 0xAE);    // Test serial chip (send byte 0xAE and check if serial returns same byte)
    outb(IO_PORT + 4, 0x0F);
}

static inline void write_byte_to_serial(uint8_t data) {
    // Wait for the serial port to be ready to accept data
    while ((inb(IO_PORT + 5) & 0x20) == 0);

    // Write the byte to the serial port
    outb(IO_PORT, data);
}

static inline void write_str_to_serial(const char *data, size_t n) {
    for (size_t i = 0; i < n; ++i)
    {
        char c = data[i];
        write_byte_to_serial((uint8_t)c);
    }
    write_byte_to_serial('\n');
}

#define VIDMEM_ADDR 0xb8000

static uint32_t screen_line;

void write_to_screen(const char *const msg, unsigned msg_len)
{
    volatile uint16_t *vidmem = (volatile uint16_t *)VIDMEM_ADDR;
    for (unsigned i = 0; i < msg_len; ++i)
    {
        uint16_t value = (uint8_t)msg[i];
        value |= 0x0f00;
        vidmem[screen_line * 80 + i] = value;
    }
}

#define WRITE_MSG(MSG) \
    do { \
        write_to_screen(MSG, sizeof(MSG) - 1), screen_line++; \
        write_str_to_serial(MSG, sizeof(MSG) - 1); \
    } while (0)

void wr_cr3(const uint64_t new_cr3) {
    asm volatile(
        "movq %0, %%cr3\n\t"
        :
        : "r"(new_cr3)
        : "memory"
    );
}

unsigned long rd_cr3() {
    unsigned long value;
    asm volatile(
        "movq %%cr3, %0\n\t"
        : "=r"(value)
        :
        : "memory"
    );
    return value;
}

void wr_cr0(unsigned long new_cr0) {
    asm volatile(
        "movq %0, %%cr0\n\t"
        :
        : "r"(new_cr0)
        : "memory"
    );
}

unsigned long rd_cr0() {
    unsigned long value;
    asm volatile(
        "movq %%cr0, %0\n\t"
        : "=r"(value)
        :
        : "memory"
    );
    return value;
}

void map_all(size_t size) {
    pml4_t pml4 = (pml4_t)0x20000;
    pdp_t pdp = (pdp_t)0x21000;
    pml4[0] = (pml4e) { .page_frame = page_frame(pa(pdp)), .present = 1, .write = 1 };
    for (unsigned i = 0; i < size / ONE_GIB; ++i)
    {
        pdp[i] = (pdpe) { .page_frame = page_frame(ONE_GIB * i), .present = 1, .write = 1, .page_size = 1 };
    }
    wr_cr3(pa(pml4));
}

