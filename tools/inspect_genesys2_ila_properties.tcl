set ltx_file [file normalize {build/vivado/genesys2-cv64a6_imafdc_sv39-trace/work-fpga/ariane_xilinx.ltx}]
set hw_server_url {localhost:3121}
if {$argc >= 1} {
  set ltx_file [file normalize [lindex $argv 0]]
}
if {$argc >= 2} {
  set hw_server_url [lindex $argv 1]
}

open_hw_manager
connect_hw_server -url $hw_server_url
set targets [get_hw_targets *]
puts "RVMT_HW_TARGETS=$targets"
if {[llength $targets] == 0} { puts "RVMT_NO_HW_TARGETS"; exit 3 }
open_hw_target [lindex $targets 0]
set devs [get_hw_devices xc7k325t_0]
puts "RVMT_HW_DEVICES=$devs"
if {[llength $devs] == 0} { puts "RVMT_NO_XC7K325T"; exit 4 }
set dev [lindex $devs 0]
current_hw_device $dev
set_property BSCAN_SWITCH_USER_MASK 1 $dev
set_property PROBES.FILE $ltx_file $dev
catch {set_property FULL_PROBES.FILE $ltx_file $dev}
refresh_hw_device $dev
set ilas [get_hw_ilas *]
puts "RVMT_HW_ILAS=$ilas"
if {[llength $ilas] == 0} { puts "RVMT_NO_HW_ILA"; exit 2 }
set ila [lindex $ilas 0]
puts "RVMT_ILA_PROPERTIES_BEGIN"
foreach prop [lsort [list_property $ila]] {
  set value ""
  catch {set value [get_property $prop $ila]}
  puts "$prop=$value"
}
puts "RVMT_ILA_PROPERTIES_END"
set probes [get_hw_probes * -of_objects $ila]
foreach probe $probes {
  puts "RVMT_PROBE_BEGIN $probe"
  foreach prop [lsort [list_property $probe]] {
    set value ""
    catch {set value [get_property $prop $probe]}
    puts "$prop=$value"
  }
  puts "RVMT_PROBE_END $probe"
}
exit 0
