proc rvmt_bin {name} {
  set exe [info nameofexecutable]
  set bin_dir [file dirname $exe]
  set candidates [list [file join $bin_dir $name] [file join $bin_dir "${name}.bat"] [file join $bin_dir "${name}.exe"]]
  foreach candidate $candidates {
    if {[file exists $candidate]} {
      return $candidate
    }
  }
  return $name
}

proc rvmt_run_cmd {cmd} {
  puts "+ [join $cmd { }]"
  if {[catch {exec {*}$cmd >@ stdout 2>@ stderr} result]} {
    puts stderr $result
    return 1
  }
  return 0
}

proc rvmt_run_xsim_top {test_name top} {
  set snap ${top}_snap
  set result_dir [file normalize "results/vivado_sim/${test_name}"]
  file mkdir $result_dir

  file delete -force xsim.dir
  file delete -force xvlog.log xelab.log xsim.log

  if {[rvmt_run_cmd [list [rvmt_bin xvlog] -sv -f sim/vivado/trace_rtl.f -f sim/vivado/trace_sim.f]]} {
    return 1
  }
  if {[rvmt_run_cmd [list [rvmt_bin xelab] work.$top -s $snap -debug typical]]} {
    return 1
  }
  if {[rvmt_run_cmd [list [rvmt_bin xsim] $snap -tclbatch sim/vivado/run_all.tcl -testplusarg TEST_NAME=${test_name} -testplusarg RESULT_DIR=${result_dir}]]} {
    return 1
  }

  set python python
  if {[info exists ::env(PYTHON)]} {
    set python $::env(PYTHON)
    if {[file isdirectory $python]} {
      if {[file exists [file join $python python.exe]]} {
        set python [file join $python python.exe]
      } elseif {[file exists [file join $python python]]} {
        set python [file join $python python]
      }
    }
  }
  set expected [file normalize "sim/golden/${test_name}.expected.json"]
  set trace [file join $result_dir trace.jsonl]
  return [rvmt_run_cmd [list $python tools/compare_trace.py --trace $trace --expected $expected --log [file join $result_dir compare.log]]]
}

proc rvmt_run_xsim_top_no_compare {test_name top} {
  set snap ${top}_snap
  set result_dir [file normalize "results/vivado_sim/${test_name}"]
  file mkdir $result_dir

  file delete -force xsim.dir
  file delete -force xvlog.log xelab.log xsim.log

  if {[rvmt_run_cmd [list [rvmt_bin xvlog] -sv -f sim/vivado/trace_rtl.f -f sim/vivado/trace_sim.f]]} {
    return 1
  }
  if {[rvmt_run_cmd [list [rvmt_bin xelab] work.$top -s $snap -debug typical]]} {
    return 1
  }
  if {[rvmt_run_cmd [list [rvmt_bin xsim] $snap -tclbatch sim/vivado/run_all.tcl -testplusarg TEST_NAME=${test_name} -testplusarg RESULT_DIR=${result_dir}]]} {
    return 1
  }

  set status_path [file join $result_dir xsim_status.log]
  set fd [open $status_path w]
  puts $fd "\[PASS\] $test_name xsim completed without compare_trace"
  close $fd
  return 0
}

proc rvmt_run_xsim {test_name} {
  return [rvmt_run_xsim_top $test_name tb_trace_top_unit]
}

if {![info exists ::rvmt_run_xsim_library_only]} {
  set test_name smoke
  if {$argc > 0} {
    set test_name [lindex $argv 0]
  }
  exit [rvmt_run_xsim $test_name]
}
