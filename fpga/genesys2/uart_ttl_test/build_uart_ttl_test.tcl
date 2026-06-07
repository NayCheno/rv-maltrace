set repo_root [file normalize [pwd]]
set src_file [file join $repo_root fpga genesys2 uart_ttl_test genesys2_jc_uart_test.sv]
set xdc_file [file join $repo_root fpga genesys2 uart_ttl_test genesys2_jc_uart_test.xdc]
set out_dir [file join $repo_root build vivado genesys2-jc-uart-test]
file mkdir $out_dir

read_verilog -sv $src_file
read_xdc $xdc_file

synth_design -top genesys2_jc_uart_test -part xc7k325tffg900-2
opt_design
place_design
route_design

report_timing_summary -file [file join $out_dir timing_summary.rpt]
report_utilization -file [file join $out_dir utilization.rpt]
write_checkpoint -force [file join $out_dir genesys2_jc_uart_test.dcp]
write_bitstream -force [file join $out_dir genesys2_jc_uart_test.bit]
