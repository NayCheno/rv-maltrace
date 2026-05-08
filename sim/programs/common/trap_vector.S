.section .text
.globl rvmt_trap_vector
rvmt_trap_vector:
  csrr t0, mcause
  csrr t1, mepc

  li t2, 2
  beq t0, t2, 1f
  li t2, 3
  beq t0, t2, 1f
  li t2, 8
  beq t0, t2, 1f
  li t2, 9
  beq t0, t2, 1f
  li t2, 11
  beq t0, t2, 1f

  li a0, 2
  tail rvmt_finish

1:
  addi t1, t1, 4
  csrw mepc, t1
  mret
