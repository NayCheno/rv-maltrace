set repo_root [file normalize [pwd]]
set bit_file [file join $repo_root build vivado genesys2-oled-phase-test genesys2_oled_phase_test.bit]

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

current_hw_device [lindex $devs 0]
set_property PROGRAM.FILE $bit_file [lindex $devs 0]
program_hw_devices [lindex $devs 0]
refresh_hw_device [lindex $devs 0]
