.include "../common/test_macros.inc"

.section .text
.globl main
main:
  li a7, 64
  li a0, 1
  li a1, 0x80001000
  li a2, 5
  ecall
  li a0, 1
  tail rvmt_finish
