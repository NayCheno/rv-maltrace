.section .text.init
.globl _start
_start:
  la sp, _stack_top
  la t0, rvmt_trap_vector
  csrw mtvec, t0
  call main
  mv a0, a0
  call rvmt_finish
