if {[llength $argv] >= 1} {
  set build_dir [file normalize [lindex $argv 0]]
} else {
  set script_dir [file dirname [file normalize [info script]]]
  set build_dir [file normalize [file join $script_dir .. .. .. build vivado artix7_35t_led_blink]]
}

set script_dir [file dirname [file normalize [info script]]]
set board_dir [file normalize [file join $script_dir ..]]
set rtl_file [file join $board_dir rtl led_blink.v]
set xdc_file [file join $board_dir constraints led_blink.xdc]

file mkdir $build_dir
cd $build_dir
read_verilog $rtl_file
read_xdc $xdc_file

synth_design -top led_blink -part xc7a35tfgg484-2
opt_design
place_design
route_design

report_utilization -file [file join $build_dir led_blink_utilization.rpt]
report_timing_summary -file [file join $build_dir led_blink_timing.rpt]
report_route_status -file [file join $build_dir led_blink_route_status.rpt]
write_checkpoint -force [file join $build_dir led_blink_routed.dcp]
write_bitstream -force [file join $build_dir led_blink.bit]

puts "RVMT_ARTIX7_LED_BITSTREAM=[file join $build_dir led_blink.bit]"
