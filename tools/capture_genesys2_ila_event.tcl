if {$argc < 3} {
  puts "usage: capture_genesys2_ila_event.tcl <evt_hex> <primary_hex_or_X> <csv_file> ?timeout_seconds? ?trigger_position? ?event_only_capture? ?ltx_file? ?hw_server_url?"
  exit 64
}

set evt_hex [string tolower [lindex $argv 0]]
set primary_arg [string tolower [lindex $argv 1]]
set csv_file [lindex $argv 2]
set timeout_seconds 120
if {$argc >= 4} {
  set timeout_seconds [lindex $argv 3]
}
set trigger_position 0
if {$argc >= 5} {
  set trigger_position [lindex $argv 4]
}
set event_only_capture 0
if {$argc >= 6} {
  set event_only_capture [lindex $argv 5]
}
set ltx_file [file normalize {build/vivado/genesys2-cv64a6_imafdc_sv39-trace/work-fpga/ariane_xilinx.ltx}]
if {$argc >= 7} {
  set ltx_file [file normalize [lindex $argv 6]]
}
set hw_server_url {localhost:3121}
if {$argc >= 8} {
  set hw_server_url [lindex $argv 7]
}

if {$primary_arg eq "x"} {
  set compare "eq104'hXXXXXXXXXXXXXXXXXXXXXXXXX${evt_hex}"
} else {
  scan $primary_arg "%x" primary_value
  set primary_hex [format "%08x" $primary_value]
  set compare "eq104'hX${primary_hex}XXXXXXXXXXXXXXXX${evt_hex}"
}

puts "RVMT_LTX_FILE=$ltx_file"
puts "RVMT_CSV_FILE=$csv_file"
puts "RVMT_TRIGGER_EVT_HEX=$evt_hex"
puts "RVMT_TRIGGER_PRIMARY=$primary_arg"
puts "RVMT_TRIGGER_COMPARE=$compare"
puts "RVMT_TIMEOUT_SECONDS=$timeout_seconds"
puts "RVMT_TRIGGER_POSITION=$trigger_position"
puts "RVMT_EVENT_ONLY_CAPTURE=$event_only_capture"

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
set fire_probe [get_hw_probes rvmt_trace_fire]
set payload_probe [get_hw_probes rvmt_trace_probe_payload]
set_property CONTROL.WINDOW_COUNT 1 $ila
set_property CONTROL.TRIGGER_POSITION $trigger_position $ila
set_property TRIGGER_COMPARE_VALUE eq1'b1 $fire_probe
set_property TRIGGER_COMPARE_VALUE $compare $payload_probe

if {$event_only_capture} {
  set cap_rc [catch {
    set_property CONTROL.CAPTURE_MODE BASIC $ila
    set_property CONTROL.CAPTURE_CONDITION AND $ila
    set_property CAPTURE_COMPARE_VALUE eq1'b1 $fire_probe
  } cap_err]
  puts "RVMT_EVENT_ONLY_CAPTURE_RC=$cap_rc"
  puts "RVMT_EVENT_ONLY_CAPTURE_ERR=$cap_err"
}

puts "RVMT_TRIGGER_PAYLOAD_COMPARE=[get_property TRIGGER_COMPARE_VALUE $payload_probe]"
puts "RVMT_CAPTURE_MODE=[get_property CONTROL.CAPTURE_MODE $ila]"
puts "RVMT_CAPTURE_CONDITION=[get_property CONTROL.CAPTURE_CONDITION $ila]"
puts "RVMT_FIRE_CAPTURE_COMPARE=[get_property CAPTURE_COMPARE_VALUE $fire_probe]"
run_hw_ila $ila
puts "RVMT_ILA_ARMED"
flush stdout
set wait_rc [catch {wait_on_hw_ila -timeout $timeout_seconds $ila} wait_err]
puts "RVMT_WAIT_RC=$wait_rc"
puts "RVMT_WAIT_ERR=$wait_err"
if {$wait_rc != 0} {
  stop_hw_ila $ila
  puts "RVMT_TRIGGER_TIMEOUT"
  exit 7
}
set data_rc [catch {set data [upload_hw_ila_data $ila]} data_err]
puts "RVMT_UPLOAD_RC=$data_rc"
puts "RVMT_UPLOAD_ERR=$data_err"
if {$data_rc != 0} { exit 5 }
set write_rc [catch {write_hw_ila_data -force -csv_file $csv_file $data} write_err]
puts "RVMT_WRITE_RC=$write_rc"
puts "RVMT_WRITE_ERR=$write_err"
if {$write_rc != 0} { exit 6 }
puts "RVMT_ILA_CAPTURE_DONE"
exit 0
