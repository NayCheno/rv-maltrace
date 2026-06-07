.section .text.init
.globl _start
_start:
  li s0, 3

print_pass_marker:
  la t2, pass_marker

print_char:
  lbu t3, 0(t2)
  beqz t3, marker_done

wait_tx_empty:
  li t0, 0x10000014
  lbu t4, 0(t0)
  andi t4, t4, 0x20
  beqz t4, wait_tx_empty

  li t1, 0x10000000
  sb t3, 0(t1)
  addi t2, t2, 1
  j print_char

marker_done:
  addi s0, s0, -1
  bnez s0, print_pass_marker

hang:
  j hang

.section .rodata
pass_marker:
  .asciz "\r\nRVMT_BAREMETAL_PASS phase=4 board=genesys2 target=cva6 uart=pmod_jc\r\n"
