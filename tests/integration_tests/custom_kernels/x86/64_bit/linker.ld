ENTRY(_start)
OUTPUT_FORMAT("binary")

SECTIONS
{
    . = 0x7c00;
    .boot : { boot.o(.boot) }
    . = 0x8000;
    .kernel : { entry*(.*) }
}
