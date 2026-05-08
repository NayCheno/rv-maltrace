.section .text
.globl main
main:
  li t0, 0x12345000
  csrw satp, t0
  li t0, 0x80000000
  csrw stvec, t0
  li a0, 1
  tail rvmt_finish
