set bit_file {D:/Code/research/rv-maltrace/build/vivado/genesys2-cv64a6_imafdc_sv39/work-fpga/ariane_xilinx.bit}
if {![file exists $bit_file]} {
    error "Missing bitstream: $bit_file"
}
open_hw_manager
if {[info exists env(HW_SERVER_URL)] && $env(HW_SERVER_URL) ne ""} {
    connect_hw_server -url $env(HW_SERVER_URL)
} else {
    connect_hw_server
}
open_hw_target
set devs [get_hw_devices xc7k325t_0]
if {[llength $devs] == 0} {
    error "No xc7k325t_0 hardware device found"
}
set dev [lindex $devs 0]
current_hw_device $dev
puts "RVMT_HW_DEVICE=$dev PART=[get_property PART $dev]"
puts "RVMT_BITSTREAM=$bit_file"
set_property PROGRAM.FILE $bit_file $dev
program_hw_devices $dev
refresh_hw_device $dev
puts "RVMT_PROGRAM_FILE=[get_property PROGRAM.FILE $dev]"
puts "RVMT_PROGRAM_DONE=xc7k325t_0"
close_hw_manager
