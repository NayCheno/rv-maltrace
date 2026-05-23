# 35T Explain Interface

`rvmt explain:35t` prints a bounded, terminal-first explanation for one 35T sample repetition.

```powershell
uv run rvmt explain:35t `
  --run-id 35t-smallcap-r512-full-synthetic-matrix-20260521 `
  --sample file_scan `
  --rep auto
```

Default behavior is console output. The report shows trace health, gate status, recovered syscall and graph summaries, suspicious behavior cues, evidence warnings, and non-claims.

Use `--format markdown --tee-out <path>` to print and save a Markdown copy. Use `--out <path>` only when terminal output should be suppressed.

```powershell
uv run rvmt explain:35t `
  --run-id 35t-smallcap-r512-full-synthetic-matrix-20260521 `
  --sample anti_debug_like `
  --rep auto `
  --format markdown `
  --tee-out reports/anti_debug_like_explain.md
```

JSON output is available for downstream tooling:

```powershell
uv run rvmt explain:35t `
  --run-id 35t-smallcap-r512-full-synthetic-matrix-20260521 `
  --sample file_scan `
  --rep rep_00 `
  --format json
```

Run-level process visualization is available with `--flow`. It does not require `--sample` and prints the whole application chain from board execution through evidence packaging.

```powershell
uv run rvmt explain:35t `
  --flow `
  --run-id 35t-extension-r512-nonnetwork-20260523
```

The flow view also prints captured key information per sample: gate status, trace event count, DROP/unknown/corrupt summary, matched expected behavior, recovered syscall head, semantic fd/path and process-tree status, top suspicious cues, and evidence source.

By default, `--flow` uses a compact dashboard with one row per sample. Use `--detail full` when you need syscall heads, cue titles, and evidence paths for each sample.

```powershell
uv run rvmt explain:35t `
  --flow `
  --detail full `
  --run-id 35t-extension-r512-nonnetwork-20260523
```

Use `--format markdown` or `--format json` with `--flow` to export the same process view.

`explain:35t --flow` is read-only. To actually run the board workload, execute samples, capture trace, analyze, report, and then show the same compact dashboard, use `run:35t` with `--stage board-analyze-report --live-flow`. This stage deliberately skips `rootfs`, image build, bitstream load, and any image flashing.

```powershell
uv run rvmt run:35t `
  --stage board-analyze-report `
  --live-flow `
  --run-id 35t-live-r512-nonnetwork-YYYYMMDD `
  --trace-records 512 `
  --trace-profile-policy 35t_small_capacity `
  --runtime-order abba `
  --reps 5 `
  --include-extension-samples `
  --sample direct_syscall_open_read `
  --sample file_encryption_sim_non_destructive `
  --sample mprotect_exec_variant `
  --sample multi_level_process_chain `
  --sample obfuscated_syscall_wrapper `
  --sample proc_status_tracerpid_check `
  --sample self_modifying_code_sim `
  --sample timing_anti_analysis_loop `
  --port COM5 `
  --baud 921600
```

The command is intentionally an explanation and behavior-audit interface. It does not report real malware detection, classifier accuracy, mature detector quality, CVA6 validation, or complete semantic reconstruction.
