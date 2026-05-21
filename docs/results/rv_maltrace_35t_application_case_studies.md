# RV-MalTrace 35T Application Case Studies

Scope: Artix-7 35T / LiteX / VexRiscv only.

Claim level:

```text
35T hardware-trace-assisted synthetic malware-like behavior audit prototype
```

Evidence bundle:

```text
run_id: 35t-smallcap-r512-full-synthetic-matrix-20260521
trace_records: 512
trace_profile_policy: 35t_small_capacity
samples: 13
gate: 13/13 PASS
full_matrix_ready: True
```

Non-claims:

- no CVA6 board claim
- no real malware detection claim
- no mature detector claim
- no classifier accuracy claim
- no complete semantic reconstruction claim

## Case Study: illegal_trap

### Goal

Show why `illegal_trap` needs the trap-capable profile and what the current evidence proves for a controlled synthetic illegal-instruction trap behavior.

### Trace Profile

`illegal_trap` uses `p0c_syscall_trap_drop` under `trace_profile_policy: 35t_small_capacity`.

This is the only sample in the current full matrix that requires the heavier trap-capable profile. The other 12 samples use `p0a_syscall_drop`.

### Raw Trace Evidence

Aggregate evidence from `aggregate/gate_report.json`:

- Gate: PASS.
- Drop median: 5 records.
- Drop rate median: 0.03067484662576687, below the 0.05 gate limit.
- Capped reps: none.
- UNKNOWN/corrupt: 0/0.
- Aggregate event counts: `MARKER: 10`, `SYSCALL_ENTRY: 90`, `SYSCALL_RET: 90`, `TRAP: 596`.

Representative `rep_00` evidence:

- Path: `results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/samples/malware_like_synthetic/illegal_trap/board/trace-on/rep_00/`
- Trace events: 158.
- Event counts: `MARKER: 2`, `SYSCALL_ENTRY: 18`, `SYSCALL_RET: 18`, `TRAP: 120`.
- DROP accounting: `drop_records: 0`, `dropped_event_count: 0`, `max_drop_value: 0`.

### Marker Scope Result

Representative `rep_00` marker scope:

- Status: PASS.
- Begin marker: event index 0, value `0xb0000f79`.
- End marker: event index 157, value `0xe0000f79`.

Aggregate gate result: marker scope PASS for 5/5 trace-on reps.

### Runtime Process Attribution

Representative runtime process map:

- Schema: `rvmt.runtime_process_map.v1`.
- Status: PASS.
- Target process: PID/TGID 511.
- Target command: `illegal_trap`.
- Target executable: `/usr/bin/illegal_trap`.
- Target map count: 6.

Aggregate gate result: runtime process attribution PASS for 5/5 trace-on reps.

### Code Map / Trace-Code Join Evidence

Code map:

- Path: `results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/samples/malware_like_synthetic/illegal_trap/build/illegal_trap.code_map.json`
- Schema: `rvmt.code_map.v1`.
- ELF: `build/board/artix7_35t/rootfs_exp_overlay/usr/bin/illegal_trap`.
- SHA-256: `82b5f33b58b578350f715f9b205263cf12d733d91b902a5b5db4986faf5d92ea`.
- Load ranges: 2.
- Sections: 16.
- Symbols: 1946.
- Syscall sites: 100.
- Trap sites: 1.
- Trap site: `.word 0xffffffff`, `kind: illegal_instruction`, PC `0x000000000001056c`, section `.text`, symbol `main`, symbol offset `0x44`.

Trace-code join:

- Path: `results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/samples/malware_like_synthetic/illegal_trap/board/trace-on/rep_00/trace_code_map/trace_code_map_summary.json`
- Schema: `rvmt.trace_code_join.summary.v1`.
- Attribution model: `marker_scope_static_code_map_runtime_process_map`.
- Runtime process map status: PASS.
- Runtime process attribution proven: true.
- Process-attributed code-site events: 16.
- Target-attributed events: 27.
- PC owner counts: `kernel: 121`, `target_sample: 27`, `unknown: 10`.
- Callsite kind counts: `illegal_instruction_site: 2`, `normal_code: 11`, `syscall_site: 14`, `unknown: 131`.

Function-level attribution is available from ELF symbol ranges. Source-line
attribution is not available in the current evidence bundle because no
DWARF/source-location records are committed for this run.

Needed next: compile or retain debug-line metadata and emit source file/line
records without claiming complete semantic reconstruction.

### Recovered Behavior

Representative behavior recovery:

- Marker scope is PASS.
- Target syscall sequence includes one target-attributed `write`.
- Trap context transitions include target-sample PCs with cause `0x00000002`, which corresponds to the illegal-instruction trap evidence used by the audit rule.
- Target trap count in representative `rep_00`: 13 target-attributed trap transitions.

### Audit Rule Hits

Expected behavior:

- `illegal_instruction_trap`

Matched expected behavior:

- `illegal_instruction_trap`

Representative matched rule detail:

- Rule: `illegal_instruction_trap`.
- Family: `trap_behavior`.
- Evidence strength: `strong`.
- Description: trap context plus handler-visible write.
- Observed syscall counts include `write: 1`.

### Strong Evidence

Strong evidence is the combination of:

- trap-capable trace profile `p0c_syscall_trap_drop`;
- target-scoped marker range;
- runtime process map for `/usr/bin/illegal_trap`;
- code-map trap site in `main`;
- trace-code join proving target-sample code attribution;
- audit rule `illegal_instruction_trap` matched as expected.

### Weak Evidence / Benign Overlap

The audit also records weak `anti_analysis_indicator` because a `ptrace` syscall is present, but the weak reason says marker-scoped runtime process/code-site attribution is missing for that indicator. This is not treated as strong expected evidence for `illegal_trap`.

Benign overlap is not the basis for this case.

### What This Case Proves

This case proves that, on the current 35T run, the trap-capable profile can capture and audit a controlled synthetic illegal-instruction trap behavior with target/code-map support.

### What This Case Does Not Prove

This does not prove a real exploit, real malware detection, mature trap semantics, CVA6 validation, or complete semantic reconstruction.

## Case Study: process_chain

### Goal

Show that `process_chain` is no longer a 35T full-matrix blocker under the 512-record `35t_small_capacity` policy, and show the current runtime process attribution and behavior audit boundary.

### Trace Profile

`process_chain` uses `p0a_syscall_drop`.

The current result avoids using the trap-heavy profile for this sample, which keeps the trace within the 512-record budget.

### Raw Trace Evidence

Aggregate evidence from `aggregate/gate_report.json`:

- Gate: PASS.
- Drop median: 0.0.
- Drop rate median: 0.0.
- Capped reps: none.
- UNKNOWN/corrupt: 0/0.
- Aggregate event counts: `MARKER: 10`, `SYSCALL_ENTRY: 380`, `SYSCALL_RET: 380`.

Capacity-specific evidence from `aggregate/process_chain_capacity_debug.md`:

- `rep_00` through `rep_04`: 154 events each.
- DROP: 0 for every rep.
- DROP rate: 0.000000 for every rep.
- Cap: False for every rep.
- TRAP: 0 for every rep.
- Strong: True for every rep.

Representative `rep_00` evidence:

- Trace events: 154.
- Event counts: `MARKER: 2`, `SYSCALL_ENTRY: 76`, `SYSCALL_RET: 76`.
- DROP accounting: `drop_records: 0`, `dropped_event_count: 0`, `max_drop_value: 0`.

### Marker Scope Result

Representative `rep_00` marker scope:

- Status: PASS.
- Begin marker: event index 0, value `0xb000ab34`.
- End marker: event index 153, value `0xe000ab34`.

Aggregate gate result: marker scope PASS for 5/5 trace-on reps.

### Runtime Process Attribution

Representative runtime process map:

- Schema: `rvmt.runtime_process_map.v1`.
- Status: PASS.
- Target process: PID/TGID 462.
- Target command: `process_chain`.
- Target executable: `/usr/bin/process_chain`.
- Target map count: 6.

Aggregate gate result: runtime process attribution PASS for 5/5 trace-on reps.

### Code Map / Trace-Code Join Evidence

Code map:

- Path: `results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/samples/malware_like_synthetic/process_chain/build/process_chain.code_map.json`
- Schema: `rvmt.code_map.v1`.
- ELF: `build/board/artix7_35t/rootfs_exp_overlay/usr/bin/process_chain`.
- SHA-256: `376caa60d58400425e2a8089f2903d677001d7419283d4b8966fb4906c54346c`.
- Load ranges: 2.
- Sections: 16.
- Symbols: 1939.
- Syscall sites: 100.
- Trap sites: 0.

Trace-code join:

- Path: `results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/samples/malware_like_synthetic/process_chain/board/trace-on/rep_00/trace_code_map/trace_code_map_summary.json`
- Schema: `rvmt.trace_code_join.summary.v1`.
- Attribution model: `marker_scope_static_code_map_runtime_process_map`.
- Runtime process map status: PASS.
- Runtime process attribution proven: true.
- Process-attributed code-site events: 18.
- Target-attributed events: 18.
- PC owner counts: `kernel: 62`, `target_sample: 18`, `unknown: 74`.
- Callsite kind counts: `syscall_site: 18`, `unknown: 136`.

Function-level attribution is available from ELF symbol ranges. Source-line
attribution is not available in the current evidence bundle because no
DWARF/source-location records are committed for this run.

Needed next: emit source-line records from debug information and join them back
to syscall-site PCs.

### Recovered Behavior

Representative target-attributed syscall sequence includes:

```text
clone, waitid, execve, clone, waitid, execve
```

Representative target syscall counts include:

```text
clone: 2
waitid: 2
execve: 2
```

### Audit Rule Hits

Expected behavior:

- `process_creation_chain`

Matched expected behavior:

- `process_creation_chain`

Representative matched rule detail:

- Rule: `process_creation_chain`.
- Family: `process_chain`.
- Evidence strength: `strong`.
- Description: parent/child process creation syscall shape with target attribution and wait boundary.

### Strong Evidence

Strong evidence is the combination of:

- no cap hit at 154 events per rep;
- zero DROP for every rep;
- marker PASS for 5/5 trace-on reps;
- runtime process attribution PASS for 5/5 trace-on reps;
- target-attributed `clone`, `execve`, and `waitid` syscall shape;
- stable audit match for `process_creation_chain`.

### Weak Evidence / Benign Overlap

Strict parent-child closure is not fully proven in the current evidence bundle. `process_chain_capacity_debug.md` records `Boundary closed: False` and reports missing or non-overlapping strict clone-parent return and wait-pid evidence for the reps.

The committed `process_tree_summary` now makes that boundary explicit as `PARTIAL`:
it observes target-attributed `clone`, `waitid`, and `execve` shapes, but does
not close parent-child edges unless positive clone-return child PID evidence and
wait PID evidence match. The current evidence also lacks dereferenced exec paths.

Committed summary:

```text
docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/process_tree_summary.md
```

The audit also records weak `anti_analysis_indicator` due to a `ptrace` syscall without target code-site attribution. This is not part of the strong process-chain evidence.

### What This Case Proves

This case proves that `process_chain` passes the 35T 512-record synthetic matrix gate and is not a current 35T blocker under `35t_small_capacity`.

### What This Case Does Not Prove

This does not prove complete process tree reconstruction, real malware process-chain detection, CVA6 validation, or a mature detector.

## Case Study: dynamic_executable_memory

### Goal

Show a controlled synthetic executable-memory behavior audit using `mmap` and `mprotect` evidence, without claiming real malware detection.

### Trace Profile

`dynamic_executable_memory` uses `p0a_syscall_drop`.

The current expected behavior can be audited from syscall entry/return, marker scope, DROP accounting, runtime process attribution, and local code-map join evidence. TRAP capture is not required for this sample.

### Raw Trace Evidence

Aggregate evidence from `aggregate/gate_report.json`:

- Gate: PASS.
- Drop median: 0.0.
- Drop rate median: 0.0.
- Capped reps: none.
- UNKNOWN/corrupt: 0/0.
- Aggregate event counts: `MARKER: 10`, `SYSCALL_ENTRY: 100`, `SYSCALL_RET: 100`.

Representative `rep_00` evidence:

- Trace events: 42.
- Event counts: `MARKER: 2`, `SYSCALL_ENTRY: 20`, `SYSCALL_RET: 20`.
- DROP accounting: `drop_records: 0`, `dropped_event_count: 0`, `max_drop_value: 0`.

### Marker Scope Result

Representative `rep_00` marker scope:

- Status: PASS.
- Begin marker: event index 0, value `0xb0006257`.
- End marker: event index 41, value `0xe0006257`.

Aggregate gate result: marker scope PASS for 5/5 trace-on reps.

### Runtime Process Attribution

Representative runtime process map:

- Schema: `rvmt.runtime_process_map.v1`.
- Status: PASS.
- Target process: PID/TGID 490.
- Target command: `dynamic_executa`.
- Target executable: `/usr/bin/dynamic_executable_memory`.
- Target map count: 6.

Aggregate gate result: runtime process attribution PASS for 5/5 trace-on reps.

### Code Map / Trace-Code Join Evidence

Code map:

- Path: `results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/samples/malware_like_synthetic/dynamic_executable_memory/build/dynamic_executable_memory.code_map.json`
- Schema: `rvmt.code_map.v1`.
- ELF: `build/board/artix7_35t/rootfs_exp_overlay/usr/bin/dynamic_executable_memory`.
- SHA-256: `26af1591ca37703d2c08716db4d4d4fdff811b8a7bafb94db70826374f1eb674`.
- Load ranges: 2.
- Sections: 16.
- Symbols: 1936.
- Syscall sites: 100.
- Trap sites: 0.

Trace-code join:

- Path: `results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/samples/malware_like_synthetic/dynamic_executable_memory/board/trace-on/rep_00/trace_code_map/trace_code_map_summary.json`
- Schema: `rvmt.trace_code_join.summary.v1`.
- Attribution model: `marker_scope_static_code_map_runtime_process_map`.
- Runtime process map status: PASS.
- Runtime process attribution proven: true.
- Process-attributed code-site events: 16.
- Target-attributed events: 16.
- PC owner counts: `kernel: 18`, `target_sample: 16`, `unknown: 8`.
- Callsite kind counts: `syscall_site: 16`, `unknown: 26`.

Exact source line for the `mmap` and `mprotect` sites: Not available in current evidence bundle.
Needed next: extend code-map generation to preserve source-line metadata and link each target syscall site to a function/source location.

### Recovered Behavior

Representative target-attributed syscall sequence includes:

```text
mmap, mprotect, mprotect
```

Representative target syscall counts include:

```text
mmap: 1
mprotect: 2
```

The all-syscall recovery for `rep_00` observes `mmap: 2` and `mprotect: 4`, while target-attributed evidence narrows the sample-owned shape.

### Audit Rule Hits

Expected behavior:

- `dynamic_executable_memory`

Matched expected behavior:

- `dynamic_executable_memory`

Representative matched rule detail:

- Rule: `dynamic_executable_memory`.
- Family: `memory_permission`.
- Evidence strength: `strong`.
- Description: `mmap` followed by `mprotect` with `PROT_EXEC` set.

### Strong Evidence

Strong evidence is the combination of:

- marker-scoped target trace;
- runtime process attribution to `/usr/bin/dynamic_executable_memory`;
- code-map assisted target syscall sites;
- target-attributed `mmap` and `mprotect` sequence;
- audit rule hit for `dynamic_executable_memory`;
- no cap hit and zero DROP.

### Weak Evidence / Benign Overlap

Exact memory-object semantics are not complete. The current evidence supports syscall-shape and argument-rule audit, not full executable-memory provenance.

Needed next: recover memory-region identity, protection transitions, and source-line attribution for the `mmap` and `mprotect` calls.

The audit also records weak `anti_analysis_indicator` due to a `ptrace` syscall without target code-site attribution. This is not part of the strong executable-memory evidence.

### What This Case Proves

This case proves that the current 35T prototype can audit a controlled synthetic `mmap` plus executable `mprotect` behavior under the 512-record policy.

### What This Case Does Not Prove

This does not prove real malware unpacking, shellcode execution, complete memory semantics, CVA6 validation, or mature malware detection.

## Case Study: file_scan

### Goal

Show the strong/weak and benign-overlap boundary for directory scanning. This case is useful because `many_file_scan` can appear in benign workloads such as `ls`.

### Trace Profile

`file_scan` uses `p0a_syscall_drop`.

The case depends on syscall entry/return, marker scope, runtime process attribution, and trace-code join evidence. TRAP capture is not required.

### Raw Trace Evidence

Aggregate evidence from `aggregate/gate_report.json`:

- Gate: PASS.
- Drop median: 0.0.
- Drop rate median: 0.0.
- Capped reps: none.
- UNKNOWN/corrupt: 0/0.
- Aggregate event counts: `MARKER: 10`, `SYSCALL_ENTRY: 100`, `SYSCALL_RET: 100`.

Representative `rep_00` evidence:

- Trace events: 42.
- Event counts: `MARKER: 2`, `SYSCALL_ENTRY: 20`, `SYSCALL_RET: 20`.
- DROP accounting: `drop_records: 0`, `dropped_event_count: 0`, `max_drop_value: 0`.

### Marker Scope Result

Representative `rep_00` marker scope:

- Status: PASS.
- Begin marker: event index 0, value `0xb000a445`.
- End marker: event index 41, value `0xe000a445`.

Aggregate gate result: marker scope PASS for 5/5 trace-on reps.

### Runtime Process Attribution

Representative runtime process map:

- Schema: `rvmt.runtime_process_map.v1`.
- Status: PASS.
- Target process: PID/TGID 420.
- Target command: `file_scan`.
- Target executable: `/usr/bin/file_scan`.
- Target map count: 6.

Aggregate gate result: runtime process attribution PASS for 5/5 trace-on reps.

### Code Map / Trace-Code Join Evidence

Code map:

- Path: `results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/samples/malware_like_synthetic/file_scan/build/file_scan.code_map.json`
- Schema: `rvmt.code_map.v1`.
- ELF: `build/board/artix7_35t/rootfs_exp_overlay/usr/bin/file_scan`.
- SHA-256: `9a247b9124f63ba1ba3666bfb36dea960ad8aac03833ae0037655a3309b72a9c`.
- Load ranges: 2.
- Sections: 16.
- Symbols: 1940.
- Syscall sites: 100.
- Trap sites: 0.

Trace-code join:

- Path: `results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/samples/malware_like_synthetic/file_scan/board/trace-on/rep_00/trace_code_map/trace_code_map_summary.json`
- Schema: `rvmt.trace_code_join.summary.v1`.
- Attribution model: `marker_scope_static_code_map_runtime_process_map`.
- Runtime process map status: PASS.
- Runtime process attribution proven: true.
- Process-attributed code-site events: 16.
- Target-attributed events: 16.
- PC owner counts: `kernel: 17`, `target_sample: 16`, `unknown: 9`.
- Callsite kind counts: `syscall_site: 16`, `unknown: 26`.

Path and fd flow reconstruction: Partial in the committed evidence snapshot.
The updated `fd_path_flow_summary` observes target-attributed fd/path syscall
shape and explicitly separates return-only register snapshots from entry fd
arguments. It still does not fully link `openat(path) -> fd ->
getdents64/close`, because the current evidence does not include dereferenced
path strings and the representative `openat` lacks paired successful fd-return
evidence.

Committed summary:

```text
docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/fd_path_flow_summary.md
```

### Recovered Behavior

Representative target-attributed syscall sequence includes:

```text
openat, getdents64, getdents64
```

Representative target syscall counts include:

```text
openat: 1
getdents64: 2
```

The all-syscall recovery for `rep_00` observes `openat: 1`, `getdents64: 3`, and `close: 1`.

### Audit Rule Hits

Expected behavior:

- `many_file_scan`

Matched expected behavior:

- `many_file_scan`

Representative matched rule detail:

- Rule: `many_file_scan`.
- Family: `file_discovery`.
- Evidence strength: `strong`.
- Description: directory scan syscall shape.

### Strong Evidence

Strong evidence is the combination of:

- marker PASS and runtime process attribution PASS;
- target-code-site evidence for `/usr/bin/file_scan`;
- repeated directory-read syscall shape;
- audit rule `many_file_scan` matched as expected;
- no cap hit and zero DROP.

### Weak Evidence / Benign Overlap

This behavior has benign overlap. The benign `ls` sample also matches `many_file_scan`, and the gate report treats that as benign expected overlap rather than unexpected strong malware-like evidence.

This case must therefore be described as controlled synthetic file-discovery audit evidence, not malware detection.

The audit also records weak `anti_analysis_indicator` due to a `ptrace` syscall without target code-site attribution. This is not part of the strong `file_scan` evidence.

### What This Case Proves

This case proves that the 35T prototype can recover and audit a controlled directory-scan syscall shape and keep benign-overlap language explicit.

### What This Case Does Not Prove

This does not prove malicious intent, real malware detection, file path reconstruction, classifier accuracy, CVA6 validation, or complete semantic reconstruction.
