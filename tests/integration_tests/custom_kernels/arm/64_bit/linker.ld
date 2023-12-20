ENTRY(_start)

MEMORY
{
    flash : ORIGIN = 0 LENGTH = 8M
}

SECTIONS
{
    .text :
    {
        boot.o(.boot)
        entry*.o
    } > flash
}
