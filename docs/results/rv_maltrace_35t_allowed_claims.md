# RV-MalTrace 35T Allowed Claims

Allowed bounded claim:

```text
35T / LiteX / VexRiscv hardware-trace-assisted synthetic malware-like behavior audit prototype.
```

Supported scope:

- Artix-7 35T constrained-board feasibility.
- 512-record small-capacity trace policy.
- 13-sample synthetic/benign full-matrix gate.
- Local code map, trace-code join, semantic recovery, behavior graph, and rule audit.
- Host/QEMU/strace/software instrumentation/eBPF/QEMU-plugin baselines as bounded comparisons.
- Representative fd/path and process-tree semantic closure.
- Lightweight public artifact package plus controlled raw-artifact escrow policy.

Forbidden positive claims:

- CVA6 validation.
- Real malware detection.
- Classifier accuracy.
- Complete semantic reconstruction.
- Mature detector.
- Standalone CCF-A main contribution.
- Enabled hardware user-pointer snapshot.

Baseline wording boundary:

- QEMU-plugin, eBPF, and software instrumentation are bounded baselines.
- They are not substitutes for hardware trace evidence.
- Suspicious cues are behavior-audit findings, not detection verdicts.
