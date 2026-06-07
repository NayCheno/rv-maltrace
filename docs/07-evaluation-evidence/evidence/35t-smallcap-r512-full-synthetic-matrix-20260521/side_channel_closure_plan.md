# 35T Side-Channel Closure Plan: 35t-sidechannel-closure-r2048-20260522

Status: PASS

Scope: Artix-7 35T / LiteX / VexRiscv only.

Baseline side-channel run: `35t-targeted-board-validation-20260522`

Closure results root: `results/experiments/35t/35t-sidechannel-closure-r2048-20260522`

Target trace records: `2048`

Trace CSR map: `vendor/litex/linux-on-litex-vexriscv/build/embedfire_rise_pro_trace_r2048/csr.csv` (PRESENT)

Focused samples: `batch_open_read_write`, `illegal_trap`, `process_chain`, `dynamic_executable_memory`

## Current Failures

- batch_open_read_write: failures=missing_strong_expected, marker_scope, drop_rate_median_gt_5pct; blockers=trace_record_cap_hit, runtime_process_attribution; drop_rate=0.13220338983050847; marker=FAIL; runtime=BLOCKED; missing=batch_file_read_write
- illegal_trap: failures=missing_strong_expected, marker_scope, drop_rate_median_gt_5pct; blockers=trace_record_cap_hit, runtime_process_attribution; drop_rate=0.09219858156028368; marker=FAIL; runtime=BLOCKED; missing=illegal_instruction_trap
- process_chain: failures=missing_strong_expected, marker_scope, drop_rate_median_gt_5pct; blockers=trace_record_cap_hit, runtime_process_attribution; drop_rate=0.6055469953775039; marker=FAIL; runtime=BLOCKED; missing=process_creation_chain
- dynamic_executable_memory: failures=missing_strong_expected; blockers=none; drop_rate=0.0; marker=PASS; runtime=PASS; missing=dynamic_executable_memory

## Closure Requirements

- focused closure samples have strict gate_status PASS
- sample_status PASS for every focused sample
- marker_scope PASS with begin/end markers in every focused rep
- runtime_process_attribution PASS for every focused rep
- no focused rep hits the trace record cap
- drop_rate_median <= 0.05
- no missing expected strong behavior rules
- UNKNOWN and corrupt event counts remain zero

## Commands

### trace-build

Hardware required: no

```bash
uv run rvmt board:artix7:trace-build --run-id 35t-sidechannel-closure-r2048-20260522 --trace-records 2048 --baud 921600
```

Expected output: `vendor/litex/linux-on-litex-vexriscv/build/embedfire_rise_pro_trace_r2048/csr.csv`

Pass condition: trace-capacity-specific LiteX CSR map and bitstream are generated

### groundtruth

Hardware required: no

```bash
uv run python tools/experiment_35t.py --stage groundtruth --run-id 35t-sidechannel-closure-r2048-20260522 --reps 5 --trace-records 2048 --trace-profile p0c_syscall_trap_drop --trace-profile-policy 35t_small_capacity --runtime-order classic --warmup 0 --sample batch_open_read_write --sample illegal_trap --sample process_chain --sample dynamic_executable_memory
```

Expected output: `results/experiments/35t/35t-sidechannel-closure-r2048-20260522/samples`

Pass condition: host and QEMU baselines are present for the focused closure samples

### rootfs

Hardware required: no

```bash
uv run python tools/experiment_35t.py --stage rootfs --run-id 35t-sidechannel-closure-r2048-20260522 --reps 5 --trace-records 2048 --trace-profile p0c_syscall_trap_drop --trace-profile-policy 35t_small_capacity --runtime-order classic --warmup 0 --sample batch_open_read_write --sample illegal_trap --sample process_chain --sample dynamic_executable_memory
```

Expected output: `build/board/artix7_35t/rootfs_exp_overlay/usr/bin/rvmt_exp_runner`

Pass condition: 35T runner and focused sample binaries are rebuilt into the rootfs overlay

### trace-load

Hardware required: yes

```bash
uv run rvmt board:artix7:trace-load --run-id 35t-sidechannel-closure-r2048-20260522 --trace-records 2048 --port COM5 --baud 921600
```

Expected output: `vendor/litex/linux-on-litex-vexriscv/build/embedfire_rise_pro_trace_r2048/gateware/embedfire_rise_pro.bit`

Pass condition: the board is programmed with the same trace depth used by the closure run

### linux-boot-after-trace-load

Hardware required: yes

```bash
uv run rvmt board:artix7:linux-boot-capture --run-id 35t-sidechannel-closure-r2048-20260522 --port COM5 --baud 921600 --duration 3600.0
```

Expected output: `results/board/artix7_35t_litex/35t-sidechannel-closure-r2048-20260522/06_linux_boot/uart_linux_boot.log`

Pass condition: Linux is reloaded after trace bitstream programming and reaches RVMT_LINUX_USER_PASS

### board-side-channel-rerun

Hardware required: yes

```bash
uv run python tools/experiment_35t.py --stage board --run-id 35t-sidechannel-closure-r2048-20260522 --reps 5 --trace-records 2048 --trace-profile p0c_syscall_trap_drop --trace-profile-policy 35t_small_capacity --runtime-order classic --warmup 0 --sample batch_open_read_write --sample illegal_trap --sample process_chain --sample dynamic_executable_memory --port COM5 --baud 921600 --duration 3600.0 --board-runner-path /usr/bin/rvmt_exp_runner --syscall-side-channel
```

Expected output: `results/experiments/35t/35t-sidechannel-closure-r2048-20260522/board/raw_uart.log`

Pass condition: UART capture contains syscall side-channel observations, begin/end markers, and trace dumps for every focused rep

### analyze

Hardware required: no

```bash
uv run python tools/experiment_35t.py --stage analyze --run-id 35t-sidechannel-closure-r2048-20260522 --reps 5 --trace-records 2048 --trace-profile p0c_syscall_trap_drop --trace-profile-policy 35t_small_capacity --runtime-order classic --warmup 0 --sample batch_open_read_write --sample illegal_trap --sample process_chain --sample dynamic_executable_memory
```

Expected output: `results/experiments/35t/35t-sidechannel-closure-r2048-20260522/samples`

Pass condition: semantic recovery, behavior audit, alignment, and trace-code joins are regenerated

### report

Hardware required: no

```bash
uv run python tools/experiment_35t.py --stage report --run-id 35t-sidechannel-closure-r2048-20260522 --reps 5 --trace-records 2048 --trace-profile p0c_syscall_trap_drop --trace-profile-policy 35t_small_capacity --runtime-order classic --warmup 0 --sample batch_open_read_write --sample illegal_trap --sample process_chain --sample dynamic_executable_memory
```

Expected output: `results/experiments/35t/35t-sidechannel-closure-r2048-20260522/aggregate/gate_report.json`

Pass condition: aggregate reports are regenerated for the focused closure run

### strict-gate

Hardware required: no

```bash
uv run python tools/check_35t_next_gate.py --run-id 35t-sidechannel-closure-r2048-20260522 --root results/experiments/35t --reps 5 --sample batch_open_read_write --sample illegal_trap --sample process_chain --sample dynamic_executable_memory
```

Expected output: `results/experiments/35t/35t-sidechannel-closure-r2048-20260522/aggregate/gate_report.json`

Pass condition: all focused samples have strict gate_status PASS

## Verification

- status: PASS
- gate_report: `results/experiments/35t/35t-sidechannel-closure-r2048-20260522/aggregate/gate_report.json`
- failure: none
- batch_open_read_write: PASS; drop_rate=0.0; marker=PASS; runtime=PASS; capped_reps=0; missing=none
- illegal_trap: PASS; drop_rate=0.008710801393728223; marker=PASS; runtime=PASS; capped_reps=0; missing=none
- process_chain: PASS; drop_rate=0.0; marker=PASS; runtime=PASS; capped_reps=0; missing=none
- dynamic_executable_memory: PASS; drop_rate=0.0; marker=PASS; runtime=PASS; capped_reps=0; missing=none

## Promotion Rule

Do not update paper-facing claims to side-channel 13/13 until closure_verification.status is PASS.

## Non-claims

- no CVA6 board claim
- no real malware detection claim
- no mature detector claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
