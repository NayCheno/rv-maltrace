.section .text
.globl main
main:
  .word 0xffffffff
  li a0, 1
  tail rvmt_finish
