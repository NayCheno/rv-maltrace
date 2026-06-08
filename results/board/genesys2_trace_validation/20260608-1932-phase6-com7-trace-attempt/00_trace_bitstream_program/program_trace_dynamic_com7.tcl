set bit_file {D:/Code/research/rv-maltrace/build/vivado/genesys2-cv64a6_imafdc_sv39-trace/work-fpga/ariane_xilinx.bit}
set ltx_file {D:/Code/research/rv-maltrace/build/vivado/genesys2-cv64a6_imafdc_sv39-trace/work-fpga/ariane_xilinx.ltx}
puts "RVMT_BIT_FILE=$bit_file"
puts "RVMT_LTX_FILE=$ltx_file"
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
set_property PROGRAM.FILE $bit_file $dev
set_property PROBES.FILE $ltx_file $dev
if {![catch {set_property FULL_PROBES.FILE $ltx_file $dev} err]} {
  puts "RVMT_FULL_PROBES_SET_OK=1"
} else {
  puts "RVMT_FULL_PROBES_SET_ERROR=$err"
}
program_hw_devices $dev
after 2000
refresh_hw_device $dev
puts "RVMT_HW_ILAS_BEGIN"
set ilas [get_hw_ilas *]
foreach ila $ilas {
  puts "RVMT_HW_ILA=$ila"
}
puts "RVMT_HW_ILAS_END"
puts "RVMT_HW_PROBES_BEGIN"
foreach probe [get_hw_probes *] {
  puts "RVMT_HW_PROBE=$probe"
}
puts "RVMT_HW_PROBES_END"
if {[llength $ilas] == 0} {
  puts "RVMT_DEBUG_HUB_NOT_DETECTED"
  exit 2
}
puts "RVMT_DEBUG_HUB_PASS"
exit 0
