set bit_file {D:/Code/research/rv-maltrace/build/vivado/genesys2-cv64a6_imafdc_sv39-trace/work-fpga/ariane_xilinx.bit}
set ltx_file {D:/Code/research/rv-maltrace/build/vivado/genesys2-cv64a6_imafdc_sv39-trace/work-fpga/ariane_xilinx.ltx}
if {![file exists $bit_file]} {
    error "Missing bitstream: $bit_file"
}
if {![file exists $ltx_file]} {
    error "Missing probes file: $ltx_file"
}
open_hw_manager
if {[info exists env(HW_SERVER_URL)] && $env(HW_SERVER_URL) ne ""} {
    connect_hw_server -url $env(HW_SERVER_URL)
} else {
    connect_hw_server -url localhost:3121
}
set targets [get_hw_targets *]
puts "RVMT_HW_TARGETS=$targets"
if {[llength $targets] == 0} {
    error "No hardware targets found"
}
open_hw_target [lindex $targets 0]
set devs [get_hw_devices xc7k325t_0]
if {[llength $devs] == 0} {
    error "No xc7k325t_0 hardware device found"
}
set dev [lindex $devs 0]
current_hw_device $dev
puts "RVMT_HW_DEVICE=$dev PART=[get_property PART $dev]"
puts "RVMT_BITSTREAM=$bit_file"
puts "RVMT_PROBES=$ltx_file"
set_property PROGRAM.FILE $bit_file $dev
program_hw_devices $dev
set_property BSCAN_SWITCH_USER_MASK 1 $dev
set_property PROBES.FILE $ltx_file $dev
catch {set_property FULL_PROBES.FILE $ltx_file $dev}
refresh_hw_device $dev
puts "RVMT_PROGRAM_FILE=[get_property PROGRAM.FILE $dev]"
puts "RVMT_BSCAN_SWITCH_USER_MASK=[get_property BSCAN_SWITCH_USER_MASK $dev]"
set ilas [get_hw_ilas *]
puts "RVMT_HW_ILAS=$ilas"
if {[llength $ilas] > 0} {
    set probe_names {}
    foreach probe [get_hw_probes *] {
        lappend probe_names [get_property NAME $probe]
    }
    puts "RVMT_HW_PROBES=$probe_names"
    puts "RVMT_DEBUG_HUB_PASS"
} else {
    puts "RVMT_DEBUG_HUB_FAIL=no_hw_ila"
}
close_hw_manager
