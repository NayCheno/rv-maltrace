.section .text
.globl main
main:
  la t0, 1f
  csrw mepc, t0
  li t1, 0x1800
  csrc mstatus, t1
  li t1, 0x0800
  csrs mstatus, t1
  mret
1:
  li a0, 1
  tail rvmt_finish
