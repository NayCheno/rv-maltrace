set ltx_file {D:/Code/research/rv-maltrace/build/vivado/genesys2-cv64a6_imafdc_sv39-trace/work-fpga/ariane_xilinx.ltx}
set csv_file {D:/Code/research/rv-maltrace/results/board/genesys2_trace_validation/20260608-1932-phase6-com7-trace-attempt/02_ila_capture/ila_capture.csv}
puts "RVMT_LTX_FILE=$ltx_file"
puts "RVMT_CSV_FILE=$csv_file"
open_hw_manager
connect_hw_server -url localhost:3121
set targets [get_hw_targets *]
puts "RVMT_HW_TARGETS=$targets"
if {[llength $targets] == 0} { puts "RVMT_NO_HW_TARGETS"; exit 3 }
open_hw_target [lindex $targets 0]
set devs [get_hw_devices xc7k325t_0]
puts "RVMT_HW_DEVICES=$devs"
if {[llength $devs] == 0} { puts "RVMT_NO_XC7K325T"; exit 4 }
set dev [lindex $devs 0]
current_hw_device $dev
if {[catch {set_property BSCAN_SWITCH_USER_MASK 1 $dev} err]} {
  puts "RVMT_BSCAN_SET_ERROR=$err"
} else {
  puts "RVMT_BSCAN_SET_OK=1"
}
if {[catch {puts "RVMT_BSCAN_PROP=[get_property BSCAN_SWITCH_USER_MASK $dev]"} err]} {
  puts "RVMT_BSCAN_GET_ERROR=$err"
}
set_property PROBES.FILE $ltx_file $dev
if {![catch {set_property FULL_PROBES.FILE $ltx_file $dev} err]} {
  puts "RVMT_FULL_PROBES_SET_OK=1"
} else {
  puts "RVMT_FULL_PROBES_SET_ERROR=$err"
}
refresh_hw_device $dev
set ilas [get_hw_ilas *]
puts "RVMT_HW_ILAS=$ilas"
if {[llength $ilas] == 0} {
  puts "RVMT_NO_HW_ILA"
  exit 2
}
set ila [lindex $ilas 0]
puts "RVMT_ILA=$ila"
puts "RVMT_ILA_PROPERTIES_BEGIN"
foreach prop [lsort [list_property $ila]] {
  if {![catch {set val [get_property $prop $ila]}]} {
    puts "RVMT_ILA_PROPERTY $prop=$val"
  }
}
puts "RVMT_ILA_PROPERTIES_END"
puts "RVMT_PROBES_BEGIN"
foreach probe [get_hw_probes *] {
  puts "RVMT_PROBE=$probe"
  foreach prop [lsort [list_property $probe]] {
    if {![catch {set val [get_property $prop $probe]}]} {
      puts "RVMT_PROBE_PROPERTY $probe $prop=$val"
    }
  }
}
puts "RVMT_PROBES_END"
if {![catch {set_property CONTROL.WINDOW_COUNT 1 $ila} err]} {
  puts "RVMT_SET_WINDOW_COUNT_OK"
} else {
  puts "RVMT_SET_WINDOW_COUNT_ERROR=$err"
}
if {![catch {set_property CONTROL.TRIGGER_POSITION 0 $ila} err]} {
  puts "RVMT_SET_TRIGGER_POSITION_OK"
} else {
  puts "RVMT_SET_TRIGGER_POSITION_ERROR=$err"
}
if {![catch {set_property TRIGGER_COMPARE_VALUE eq1'b1 [get_hw_probes rvmt_trace_fire]} err]} {
  puts "RVMT_SET_FIRE_TRIGGER_OK"
} else {
  puts "RVMT_SET_FIRE_TRIGGER_ERROR=$err"
}
run_hw_ila $ila
set wait_rc [catch {wait_on_hw_ila -timeout 20 $ila} wait_err]
puts "RVMT_WAIT_RC=$wait_rc"
puts "RVMT_WAIT_ERR=$wait_err"
if {$wait_rc != 0} {
  stop_hw_ila $ila
}
set data_rc [catch {set data [upload_hw_ila_data $ila]} data_err]
puts "RVMT_UPLOAD_RC=$data_rc"
puts "RVMT_UPLOAD_ERR=$data_err"
if {$data_rc != 0} {
  exit 5
}
set write_rc [catch {write_hw_ila_data -force -csv_file $csv_file $data} write_err]
puts "RVMT_WRITE_RC=$write_rc"
puts "RVMT_WRITE_ERR=$write_err"
if {$write_rc != 0} {
  exit 6
}
puts "RVMT_ILA_CAPTURE_DONE"
exit 0
