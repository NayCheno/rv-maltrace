open_hw_manager
connect_hw_server -allow_non_jtag
foreach server [get_hw_servers] {
  refresh_hw_server $server
}

set targets [get_hw_targets -quiet *]
if {[llength $targets] == 0} {
  puts "RVMT_NO_HW_TARGETS"
  close_hw_manager
  exit 12
}
current_hw_target [lindex $targets 0]
open_hw_target

set rvmt_found 0
foreach device [get_hw_devices] {
  set part [get_property PART $device]
  puts "RVMT_HW_DEVICE=$device PART=$part"
  if {[string match -nocase *xc7a35t* $part] || [string match -nocase *xc7a35t* $device]} {
    set rvmt_found 1
  }
}

close_hw_manager
if {!$rvmt_found} {
  puts "RVMT_ARTIX7_35T_NOT_FOUND"
  exit 12
}
puts "RVMT_ARTIX7_35T_FOUND"
