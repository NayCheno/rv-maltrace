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
set ltx_file [file normalize {build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx.ltx}]
if {$argc >= 7} {
  set ltx_file [file normalize [lindex $argv 6]]
}
set hw_server_url {localhost:3121}
if {$argc >= 8} {
  set hw_server_url [lindex $argv 7]
}

set payload_width 136
set payload_nibbles [expr {$payload_width / 4}]
if {$evt_hex eq "x"} {
  set evt_compare "X"
} else {
  scan $evt_hex "%x" evt_value
  set evt_compare [format "%01x" [expr {$evt_value & 0xf}]]
}
if {$primary_arg eq "x"} {
  set compare "eq${payload_width}'h[string repeat X [expr {$payload_nibbles - 1}]]${evt_compare}"
} else {
  scan $primary_arg "%x" primary_value
  set primary_hex [format "%08x" $primary_value]
  set compare "eq${payload_width}'h[string repeat X 9]${primary_hex}[string repeat X 16]${evt_compare}"
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
set bram_probe [get_hw_probes -quiet rvmt_trace_bram_probe_payload]
set bram_segment_probes [get_hw_probes -quiet rvmt_trace_bram_*]
puts "RVMT_BRAM_PROBE=$bram_probe"
puts "RVMT_BRAM_SEGMENT_PROBES=$bram_segment_probes"
set_property CONTROL.WINDOW_COUNT 1 $ila
set_property CONTROL.TRIGGER_POSITION $trigger_position $ila
set_property TRIGGER_COMPARE_VALUE eq1'b1 $fire_probe
set_property TRIGGER_COMPARE_VALUE $compare $payload_probe
set trigger_condition_rc [catch {set_property CONTROL.TRIGGER_CONDITION AND $ila} trigger_condition_err]
puts "RVMT_TRIGGER_CONDITION_RC=$trigger_condition_rc"
puts "RVMT_TRIGGER_CONDITION_ERR=$trigger_condition_err"

if {$event_only_capture} {
  set cap_rc [catch {
    set_property CONTROL.CAPTURE_MODE BASIC $ila
    set_property CONTROL.CAPTURE_CONDITION AND $ila
    set_property CAPTURE_COMPARE_VALUE eq1'b1 $fire_probe
  } cap_err]
  puts "RVMT_EVENT_ONLY_CAPTURE_RC=$cap_rc"
  puts "RVMT_EVENT_ONLY_CAPTURE_ERR=$cap_err"
  if {$cap_rc != 0} {
    puts "RVMT_EVENT_ONLY_CAPTURE_UNSUPPORTED"
    exit 8
  }
}

puts "RVMT_TRIGGER_PAYLOAD_COMPARE=[get_property TRIGGER_COMPARE_VALUE $payload_probe]"
puts "RVMT_TRIGGER_CONDITION=[get_property CONTROL.TRIGGER_CONDITION $ila]"
puts "RVMT_CAPTURE_MODE=[get_property CONTROL.CAPTURE_MODE $ila]"
puts "RVMT_CAPTURE_CONDITION=[get_property CONTROL.CAPTURE_CONDITION $ila]"
puts "RVMT_FIRE_CAPTURE_COMPARE=[get_property CAPTURE_COMPARE_VALUE $fire_probe]"
if {$event_only_capture} {
  set capture_mode [string toupper [get_property CONTROL.CAPTURE_MODE $ila]]
  set fire_capture_compare [get_property CAPTURE_COMPARE_VALUE $fire_probe]
  if {$capture_mode eq "ALWAYS"} {
    puts "RVMT_EVENT_ONLY_CAPTURE_NOT_APPLIED"
    exit 8
  }
  if {$fire_capture_compare ne "eq1'b1"} {
    puts "RVMT_EVENT_ONLY_CAPTURE_COMPARE_NOT_APPLIED"
    exit 8
  }
}
catch {stop_hw_ila $ila}
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
