set root_dir "D:/Code/research/rv-maltrace"
set work_dir "$root_dir/build/vivado/genesys2-cv64a6_imafdc_sv39-trace/work-fpga"
set report_dir "$root_dir/build/vivado/genesys2-cv64a6_imafdc_sv39-trace/reports"
set evidence_dir "$root_dir/results/board/genesys2_trace_validation/20260609-1901-onboard-com7-trace-gating-fix/00_trace_build/recovery_explore"

file mkdir $evidence_dir
file mkdir $report_dir

open_checkpoint "$work_dir/ariane_xilinx_physopt.dcp"

route_design -directive Explore

report_route_status -file "$evidence_dir/route_status_explore.rpt"
report_timing_summary -max_paths 10 -routable_nets -report_unconstrained -warn_on_violation -file "$evidence_dir/timing_summary_explore.rpt"

set worst_path [lindex [get_timing_paths -max_paths 1 -setup] 0]
set wns [get_property SLACK $worst_path]
puts "RVMT_RECOVERY_WNS=$wns"

if {$wns < 0} {
    puts "RVMT_RECOVERY_RESULT=TIMING_FAIL"
    exit 2
}

report_route_status -file "$work_dir/ariane_xilinx_route_status.rpt"
report_timing_summary -max_paths 10 -routable_nets -report_unconstrained -warn_on_violation -file "$work_dir/ariane_xilinx_timing_summary_routed.rpt"
check_timing -file "$report_dir/ariane.check_timing.rpt"
report_timing -max_paths 100 -nworst 100 -delay_type max -sort_by slack -file "$report_dir/ariane.timing_WORST_100.rpt"
report_timing -nworst 1 -delay_type max -sort_by group -file "$report_dir/ariane.timing.rpt"
report_utilization -hierarchical -file "$report_dir/ariane.utilization.rpt"

write_checkpoint -force "$work_dir/ariane_xilinx_routed.dcp"
write_debug_probes -force "$work_dir/ariane_xilinx.ltx"
write_bitstream -force "$work_dir/ariane_xilinx.bit"
write_cfgmem -format mcs -interface SPIx4 -size 256 -loadbit "up 0x0 $work_dir/ariane_xilinx.bit" -file "$work_dir/ariane_xilinx.mcs" -force

puts "RVMT_RECOVERY_RESULT=PASS"
