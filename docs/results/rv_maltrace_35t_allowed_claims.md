# RV-MalTrace 35T Allowed Claims

Allowed bounded claim:

```text
35T / LiteX / VexRiscv hardware-trace-assisted malware-behavior evidence-chain prototype.
```

Supported scope:

- Artix-7 35T constrained-board feasibility.
- 512-record small-capacity trace policy.
- 13-sample synthetic/benign full-matrix gate.
- Six board-tested real-malware-derived behavior rows from DarthRa and Mirai references.
- Local code map, trace-code join, semantic recovery, behavior graph, and rule audit.
- Host/QEMU/strace/software instrumentation/eBPF/QEMU-plugin baselines as bounded comparisons.
- Representative fd/path and process-tree semantic closure.
- Lightweight public artifact package plus controlled raw-artifact escrow policy.

Forbidden positive claims:

- CVA6 validation.
- Uncontrolled or network-enabled real-malware payload execution.
- Malware-family detection accuracy, IOC coverage, TTP coverage, or classifier accuracy.
- Payload equivalence to the original malware binary/source.
- Complete semantic reconstruction.
- Mature detector.
- Standalone CCF-A main contribution.
- Enabled hardware user-pointer snapshot.

Baseline wording boundary:

- QEMU-plugin, eBPF, and software instrumentation are bounded baselines.
- They are not substitutes for hardware trace evidence.
- Suspicious cues are behavior-audit findings, not detection verdicts.
- Safety controls on real-malware-derived cases bound execution risk; they do not remove those cases from the paper's real-malware behavior-feasibility discussion.
