if {$argc < 1} {
  puts "usage: program_genesys2_bitstream.tcl <bit_file> ?ltx_file_or_X? ?hw_server_url?"
  exit 64
}

set bit_file [file normalize [lindex $argv 0]]
if {![file exists $bit_file]} {
  puts "RVMT_BIT_FILE_MISSING=$bit_file"
  exit 65
}

set ltx_file ""
if {$argc >= 2} {
  set ltx_arg [lindex $argv 1]
  if {[string tolower $ltx_arg] ne "x" && $ltx_arg ne ""} {
    set ltx_file [file normalize $ltx_arg]
    if {![file exists $ltx_file]} {
      puts "RVMT_LTX_FILE_MISSING=$ltx_file"
      exit 66
    }
  }
}

set hw_server_url {localhost:3121}
if {$argc >= 3} {
  set hw_server_url [lindex $argv 2]
}

puts "RVMT_BIT_FILE=$bit_file"
puts "RVMT_LTX_FILE=$ltx_file"
puts "RVMT_HW_SERVER_URL=$hw_server_url"

open_hw_manager
connect_hw_server -url $hw_server_url
set targets [get_hw_targets *]
puts "RVMT_HW_TARGETS=$targets"
if {[llength $targets] == 0} {
  puts "RVMT_NO_HW_TARGETS"
  exit 3
}

open_hw_target [lindex $targets 0]
set devs [get_hw_devices xc7k325t_0]
puts "RVMT_HW_DEVICES=$devs"
if {[llength $devs] == 0} {
  puts "RVMT_NO_XC7K325T"
  exit 4
}

set dev [lindex $devs 0]
current_hw_device $dev
set_property PROGRAM.FILE $bit_file $dev
if {$ltx_file ne ""} {
  set_property PROBES.FILE $ltx_file $dev
  catch {set_property FULL_PROBES.FILE $ltx_file $dev}
}

program_hw_devices $dev
refresh_hw_device $dev
puts "RVMT_PROGRAM_DONE"
exit 0
