# Linux Benign Dataset

Phase 6.2 defines the benign Linux behavior dataset. This is a run plan and
sample specification, not board or Linux experiment evidence.

The dataset manifest is:

```text
experiments/linux_behavior/benign/manifest.json
```

Run evidence must be captured under:

```text
results/linux_behavior/<run-id>/benign/
```

## Dataset

| Order | Sample | Command shape | Expected behavior | Network | Status | Evidence directory |
| ---: | --- | --- | --- | --- | --- | --- |
| 1 | hello | `./rvmt_benign_workload hello` | stdout write | no | TODO(EXPERIMENT) | `01_hello/` |
| 2 | ls | `./rvmt_benign_workload ls` | directory listing | no | TODO(EXPERIMENT) | `02_ls/` |
| 3 | cat | `./rvmt_benign_workload cat` | file read and stdout write | no | TODO(EXPERIMENT) | `03_cat/` |
| 4 | cp | `./rvmt_benign_workload cp` | file copy | no | TODO(EXPERIMENT) | `04_cp/` |
| 5 | sha256sum | `./rvmt_benign_workload sha256sum` | file hash | no | TODO(EXPERIMENT) | `05_sha256sum/` |
| 6 | small_network_client | `./small_network_client 127.0.0.1 7` | small client socket/connect/read/write sequence | optional, disabled by default | OPTIONAL_DISABLED_BY_DEFAULT | `06_small_network_client/` |

The five default non-network samples use the repository-owned
`board/artix7_35t/linux/rvmt_benign_workload.c` wrapper so host, QEMU, and 35T
board runs execute the same source-controlled workload shape. The `sha256sum`
row is a benign file-hash workload name; the wrapper emits a deterministic
repository-local hash value instead of depending on an external coreutils
binary.

The `small_network_client` source is kept in
`experiments/linux_behavior/benign/programs/small_network_client.c`. It may be
used only when a planned target network setup is available; it remains disabled
by default to preserve the Phase 6.1 network policy.

## Expected Artifacts

Each enabled sample directory under the run root must contain:

- `trace.jsonl`: exported committed behavior trace.
- `semantic_events.json`: recovered syscall/control/context events.
- `behavior_graph.json`: behavior graph for this sample.
- `recovery_report.md`: comparison against the expected behavior.

All samples in this dataset are benign. The dataset must not include real
malware, repackaged malware, unknown-provenance binaries, or destructive
payloads.
