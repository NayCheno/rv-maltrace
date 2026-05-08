.section .text
.globl rvmt_finish
rvmt_finish:
  li t0, 0x10000000
  sd a0, 0(t0)
1:
  j 1b
