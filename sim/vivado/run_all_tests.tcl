set ::rvmt_run_xsim_library_only 1
source sim/vivado/run_xsim.tcl

set tests {smoke branch jump ecall syscall_ret pointer_string pointer_guardrails trap_illegal ebreak csr context backpressure filter board_minimal}
set adapter_tests {rvfi_adapter}
set no_compare_tests {bram_ring}
set failed 0

foreach test $tests {
  puts "RVMT_TEST_START=$test"
  if {[rvmt_run_xsim $test]} {
    puts stderr "RVMT_TEST_FAIL=$test"
    set failed 1
  } else {
    puts "RVMT_TEST_PASS=$test"
  }
}

foreach test $adapter_tests {
  puts "RVMT_TEST_START=$test"
  if {[rvmt_run_xsim_top $test tb_cva6_rvfi_trace_adapter]} {
    puts stderr "RVMT_TEST_FAIL=$test"
    set failed 1
  } else {
    puts "RVMT_TEST_PASS=$test"
  }
}

foreach test $no_compare_tests {
  puts "RVMT_TEST_START=$test"
  if {[rvmt_run_xsim_top_no_compare $test tb_trace_bram_ring]} {
    puts stderr "RVMT_TEST_FAIL=$test"
    set failed 1
  } else {
    puts "RVMT_TEST_PASS=$test"
  }
}

exit $failed
