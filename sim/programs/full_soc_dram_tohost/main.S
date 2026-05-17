.section .text.init
.globl _start
_start:
  li t0, 0x80000020
  li t1, 1
  sd t1, 0(t0)
1:
  j 1b
