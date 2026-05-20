if {[llength $argv] < 1} {
  puts "usage: program_bitstream.tcl <bitstream.bit>"
  exit 2
}

set bitstream [file normalize [lindex $argv 0]]
if {![file exists $bitstream]} {
  puts "missing bitstream: $bitstream"
  exit 2
}

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

set target_device ""
foreach device [get_hw_devices] {
  set part [get_property PART $device]
  puts "RVMT_HW_DEVICE=$device PART=$part"
  if {$target_device eq "" && ([string match -nocase *xc7a35t* $part] || [string match -nocase *xc7a35t* $device])} {
    set target_device $device
  }
}

if {$target_device eq ""} {
  close_hw_manager
  puts "RVMT_ARTIX7_35T_NOT_FOUND"
  exit 12
}

current_hw_device $target_device
refresh_hw_device $target_device
set_property PROGRAM.FILE $bitstream $target_device
program_hw_devices $target_device
refresh_hw_device $target_device
close_hw_manager

puts "RVMT_PROGRAMMED_BITSTREAM=$bitstream"
