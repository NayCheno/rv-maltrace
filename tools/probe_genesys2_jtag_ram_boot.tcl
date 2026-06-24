set ltx_file [file normalize {build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx.ltx}]
set hw_server_url {localhost:3121}
if {$argc >= 1} {
  set ltx_file [file normalize [lindex $argv 0]]
}
if {$argc >= 2} {
  set hw_server_url [lindex $argv 1]
}

proc rvmt_puts_kv {key value} {
  puts "$key=$value"
}

proc rvmt_try_get {key script} {
  set value ""
  set rc [catch {uplevel 1 $script} value]
  rvmt_puts_kv "${key}_RC" $rc
  if {$rc == 0} {
    rvmt_puts_kv $key $value
  } else {
    rvmt_puts_kv "${key}_ERR" $value
    rvmt_puts_kv $key ""
  }
}

rvmt_puts_kv RVMT_READ_ONLY 1
rvmt_puts_kv RVMT_HW_SERVER_URL $hw_server_url
rvmt_puts_kv RVMT_LTX_FILE $ltx_file
rvmt_puts_kv RVMT_LTX_EXISTS [file exists $ltx_file]
rvmt_puts_kv RVMT_PROBE_PURPOSE {read-only JTAG/RAM-boot feasibility inventory}
rvmt_puts_kv RVMT_NO_PROGRAM_RESET_OR_MEMORY_WRITE 1
rvmt_try_get RVMT_HW_AXI_COMMANDS {lsort [info commands *hw*axi*]}
rvmt_try_get RVMT_HW_AXIS_COMMANDS {lsort [info commands *hw*axis*]}
rvmt_try_get RVMT_HW_MEM_COMMANDS {lsort [info commands *hw*mem*]}
rvmt_try_get RVMT_HW_DEBUG_COMMANDS {lsort [info commands *hw*debug*]}

set rc [catch {open_hw_manager} err]
rvmt_puts_kv RVMT_OPEN_HW_MANAGER_RC $rc
if {$rc != 0} {
  rvmt_puts_kv RVMT_OPEN_HW_MANAGER_ERR $err
  exit 20
}

set rc [catch {connect_hw_server -url $hw_server_url} err]
rvmt_puts_kv RVMT_CONNECT_HW_SERVER_RC $rc
if {$rc != 0} {
  rvmt_puts_kv RVMT_CONNECT_HW_SERVER_ERR $err
  exit 21
}

set targets [get_hw_targets *]
rvmt_puts_kv RVMT_HW_TARGETS $targets
rvmt_puts_kv RVMT_HW_TARGET_COUNT [llength $targets]
if {[llength $targets] == 0} {
  puts "RVMT_NO_HW_TARGETS"
  exit 22
}

set rc [catch {open_hw_target [lindex $targets 0]} err]
rvmt_puts_kv RVMT_OPEN_HW_TARGET_RC $rc
if {$rc != 0} {
  rvmt_puts_kv RVMT_OPEN_HW_TARGET_ERR $err
  exit 23
}

set all_devs [get_hw_devices *]
set genesys_devs [get_hw_devices -quiet xc7k325t_0]
rvmt_puts_kv RVMT_HW_DEVICES $all_devs
rvmt_puts_kv RVMT_XC7K325T_DEVICES $genesys_devs
rvmt_puts_kv RVMT_HW_DEVICE_COUNT [llength $all_devs]
rvmt_puts_kv RVMT_XC7K325T_DEVICE_COUNT [llength $genesys_devs]
if {[llength $all_devs] == 0} {
  puts "RVMT_NO_HW_DEVICES"
  exit 24
}

set dev [lindex $all_devs 0]
if {[llength $genesys_devs] > 0} {
  set dev [lindex $genesys_devs 0]
}
current_hw_device $dev
rvmt_puts_kv RVMT_CURRENT_HW_DEVICE $dev

set ltx_rc [catch {
  if {[file exists $ltx_file]} {
    set_property BSCAN_SWITCH_USER_MASK 1 $dev
    set_property PROBES.FILE $ltx_file $dev
    catch {set_property FULL_PROBES.FILE $ltx_file $dev}
  }
} ltx_err]
rvmt_puts_kv RVMT_SET_PROBES_FILE_RC $ltx_rc
rvmt_puts_kv RVMT_SET_PROBES_FILE_ERR $ltx_err

set refresh_rc [catch {refresh_hw_device $dev} refresh_err]
rvmt_puts_kv RVMT_REFRESH_HW_DEVICE_RC $refresh_rc
rvmt_puts_kv RVMT_REFRESH_HW_DEVICE_ERR $refresh_err
if {$refresh_rc != 0} {
  exit 25
}

rvmt_try_get RVMT_HW_ILAS {get_hw_ilas *}
rvmt_try_get RVMT_HW_VIOS {get_hw_vios *}
rvmt_try_get RVMT_HW_PROBES {get_hw_probes *}
rvmt_try_get RVMT_HW_DEBUG_CORES {get_hw_debug_cores *}
rvmt_try_get RVMT_HW_AXIS {get_hw_axis *}
rvmt_try_get RVMT_HW_AXI {get_hw_axi *}
rvmt_try_get RVMT_HW_MEMS {get_hw_mems *}

puts "RVMT_DEVICE_PROPERTIES_BEGIN"
foreach prop [lsort [list_property $dev]] {
  set value ""
  catch {set value [get_property $prop $dev]}
  puts "$prop=$value"
}
puts "RVMT_DEVICE_PROPERTIES_END"

puts "RVMT_JTAG_RAM_BOOT_PROBE_DONE"
exit 0
