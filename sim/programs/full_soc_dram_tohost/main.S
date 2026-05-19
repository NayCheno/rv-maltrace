.section .text.init
.globl _start
_start:
  lui t0, 0x10000
  sd zero, 0(t0)
1:
  j 1b
