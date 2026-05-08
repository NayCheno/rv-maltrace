.PHONY: sim-smoke sim-all sim-summary baremetal

sim-smoke:
	vivado -mode batch -source sim/vivado/run_xsim.tcl -tclargs smoke

sim-all:
	uv run rvmt sim:trace-unit

sim-summary:
	uv run rvmt sim:summary

baremetal:
	uv run rvmt baremetal:build
