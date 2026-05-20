.section .text
.global _start
_start:
    li a0, 1
    la a1, before_msg
    li a2, 20
    li a7, 64
    ecall

    .word 0xffffffff

    li a0, 77
    li a7, 93
    ecall

1:
    j 1b

.section .rodata
before_msg:
    .ascii "RVMT_ILLEGAL_BEFORE\n"
before_msg_end:
