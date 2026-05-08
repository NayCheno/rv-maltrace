set do_waves 0
if {[info exists ::env(RVMT_WAVES)] && $::env(RVMT_WAVES) eq "1"} {
  set do_waves 1
}

if {$do_waves} {
  log_wave -recursive /*
}

run -all
quit
