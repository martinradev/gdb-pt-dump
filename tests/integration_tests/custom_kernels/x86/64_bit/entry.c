#include <stdint.h>
#include <stddef.h>

#define WIDTH 80
#define HEIGHT 64

#include "common.h"
#include "common_x86.h"

void setup_2mb_page_table_simple();
void setup_4k_page_table_simple();
void setup_4k_page_table_complex();
void test_complete();
void no_test_executed();

#define NUM_ENTRIES_PER_PAGE (4096 / sizeof(size_t))
_Static_assert(sizeof(size_t) == 8, "Expected that size_t is 8 bytes for 64-bit builds");

void entry() {
    map_all(1024 * 1024 * 1024);
    setup_serial();

#define DISPATCH(test) \
    do { \
        if (GDB_PT_DUMP_TEST == test) { \
            WRITE_MSG("Running: " #test); \
            test(); \
            test_complete(); \
        } \
    } while (0)

    WRITE_MSG("Searching for test...");
    DISPATCH(setup_2mb_page_table_simple);
    DISPATCH(setup_4k_page_table_complex);
    DISPATCH(setup_4k_page_table_simple);

    no_test_executed();
}

void test_complete() {
    WRITE_MSG("Done"); \
    while(1) {
        volatile int a = 0xcafefe;
        (void)a;
    }
}

void no_test_executed() {
    WRITE_MSG("Test not found"); \
    while(1) {
        volatile int a = 0xdeaddead;
        (void)a;
    }
}

// The memory ranges are as follows:
// 2mb rx
// 2mb rxw
// 2mb rx, user
// 2mb rx, wb=0
// 2mb rx, uc=1
// 4mb rx
void setup_2mb_page_table_simple()
{
    pml4_t pml4 = (pml4_t)0x10000;
    pdp_t pdp = (pdp_t)0x11000;
    pd_t pd = (pd_t)0x12000;
    pml4[0] = (pml4e) { .page_frame = page_frame(pa(pdp)), .present = 1, .write = 1};
    pdp[0] = (pdpe) { .page_frame = page_frame(pa(pd)), .present = 1, .write = 1};
    pd[0] = (pde) { .page_frame = page_frame(0x0), .present = 1, .page_size = 1};
    pd[1] = (pde) { .page_frame = page_frame(TWO_MB), .write = 1, .present = 1, .page_size = 1 };
    pd[2] = (pde) { .page_frame = page_frame(TWO_MB * 2), .user = 1, .present = 1, .page_size = 1 };
    pd[3] = (pde) { .page_frame = page_frame(TWO_MB * 3), .pwt = 1, .present = 1, .page_size = 1 };
    pd[4] = (pde) { .page_frame = page_frame(TWO_MB * 4), .pcd = 1, .present = 1, .page_size = 1 };
    pd[5] = (pde) { .page_frame = page_frame(TWO_MB * 5), .accessed = 1, .present = 1, .page_size = 1 };
    pd[6] = (pde) { .page_frame = page_frame(TWO_MB * 6), .global = 1, .present = 1, .page_size = 1 };

    wr_cr3(pa(pml4));
}

// The memory ranges are as follows:
// 4 mb rwx
// 2 mb rx, user
// 2 mib rx, wb=0
// 2 mib rx, uc=1
// 4 mib + 4kb rx
// gap 4kb
// 4kb rx
// gap 2032kb
// 4kb rwx
void setup_4k_page_table_simple()
{
    pml4_t pml4 = (pml4_t)0x10000;
    pdp_t pdp = (pdp_t)0x11000;
    pd_t pd = (pd_t)0x12000;
    pml4[0] = (pml4e) { .page_frame = page_frame(pa(pdp)), .present = 1, .write = 1 };
    pdp[0] = (pdpe) { .page_frame = page_frame(pa(pd)), .present = 1, .write = 1 };
    pd[0] = (pde) { .page_frame = page_frame(0x0), .present = 1, .page_size = 1, .write = 1 };
    pd[1] = (pde) { .page_frame = page_frame(TWO_MB), .present = 1, .write = 1, .page_size = 1 };
    pd[2] = (pde) { .page_frame = page_frame(TWO_MB * 2), .present = 1, .user = 1, .page_size = 1 };
    pd[3] = (pde) { .page_frame = page_frame(TWO_MB * 3), .pwt = 1, .present = 1, .page_size = 1 };
    pd[4] = (pde) { .page_frame = page_frame(TWO_MB * 4), .pcd = 1, .present = 1, .page_size = 1 };
    pd[5] = (pde) { .page_frame = page_frame(TWO_MB * 5), .global = 1, .present = 1, .page_size = 1 };
    pd[6] = (pde) { .page_frame = page_frame(TWO_MB * 6), .global = 1, .present = 1, .page_size = 1 };

    pt_t pt = (pt_t)0x13000;
    memset(va_ptr(pt), 0, 0x1000);

    pd[7] = (pde) { .page_frame = page_frame(pa(pt)), .present = 1 };
    pt[0] = (pte) { .page_frame = page_frame(0), .present = 1 };
    pt[2] = (pte) { .page_frame = page_frame(0x1000), .present = 1 };
    pt[511] = (pte) { .page_frame = page_frame(0x200000), .present = 1, .write = 1 };

    wr_cr3(pa(pml4));
}

// The memory ranges are as follows:
// 516 kb rx
// gap 4kb
// 360 kb rx
// 4 kb rx, user
// 396 kb rx
// 4kb rwx
// 36 kb rx
// gap 4kb
// 452 kb rx
// 4kb rwx
// 220 rw
// 4kb rwx
// 36 kb rx
// gap 4kb
// 4kb rx, user
// 254 mb rx
void setup_4k_page_table_complex()
{
    pml4_t pml4 = (pml4_t)0x100000;
    pdp_t pdp = (pdp_t)0x101000;
    pd_t pd = (pd_t)0x102000;
    pt_t pt = (pt_t)0x103000;

    pml4[0] = (pml4e) { .page_frame = page_frame(pa(pdp)), .present = 1, .write = 1 };
    pdp[0] = (pdpe) { .page_frame = page_frame(pa(pd)), .present = 1, .write = 1 };

    for (unsigned i = 0; i < 128; ++i)
    {
        pd[i] = (pde) { .page_frame = page_frame(pa(&pt[NUM_ENTRIES_PER_PAGE * i])), .present = 1, .write = 1 };
        for (unsigned j = 0; j < NUM_ENTRIES_PER_PAGE; ++j)
        {
            pt[i * NUM_ENTRIES_PER_PAGE + j] = (pte) { .page_frame = page_frame(i * TWO_MB + j * FOUR_KB), .present = 1 };
        }
    }

    pt[129] = (pte) { .page_frame = page_frame(0), .present = 0 };
    pt[220] = (pte) { .page_frame = page_frame(0), .present = 1, .user = 1 };
    pt[320] = (pte) { .page_frame = page_frame(0), .present = 1, .write = 1 };
    pt[330] = (pte) { .page_frame = page_frame(0), .present = 0 };
    pt[444] = (pte) { .page_frame = page_frame(0), .present = 1, .write = 1 };
    pt[500] = (pte) { .page_frame = page_frame(0), .present = 1, .write = 1 };
    pt[NUM_ENTRIES_PER_PAGE - 2] = (pte) { .page_frame = page_frame(0), .present = 0 };
    pt[NUM_ENTRIES_PER_PAGE - 1] = (pte) { .page_frame = page_frame(0), .present = 1, .user = 1 };

    wr_cr3(pa(pml4));
}

