ENTRY(_start)

MEMORY
{
    MAIN_RAM (rwx) : ORIGIN = 0x40000000, LENGTH = 64K
}

SECTIONS
{
    .text : {
        KEEP(*(.text.start))
        *(.text*)
        *(.rodata*)
    } > MAIN_RAM

    .data : {
        *(.data*)
    } > MAIN_RAM

    .bss : {
        *(.bss*)
        *(COMMON)
    } > MAIN_RAM

    . = ALIGN(16);
    . = ORIGIN(MAIN_RAM) + LENGTH(MAIN_RAM);
    _stack_top = .;
}
