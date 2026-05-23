# RV-MalTrace 35T Assessment Source

This repository-local assessment source replaces references to private local paths when explaining the current 35T-only evidence plan.

Primary objective:

```text
35T-only evidence hardening
```

Final evidence product:

```text
35T gate + semantic artifacts + behavior audit + terminal explanation interface + suspicious cue summary + artifact package + bounded claim statement
```

Required terminal interface:

```powershell
uv run rvmt explain:35t --run-id <run> --sample <sample> --rep auto
```

Required output properties:

- Default output is a readable terminal report, not file-only JSON.
- The report shows trace health, gate status, recovered syscall/trap/process/file behavior, suspicious cues, evidence sources, warnings, and bounded non-claims.
- Suspicious cues come from behavior-audit rules, syscall-pattern cues, trace-health anomalies, or semantic confidence boundaries.
- Weak, inferred, side-channel, and missing evidence is explicitly marked.

Priority closure:

- P0.1: claim boundary and paper wording.
- P0.2: externally auditable artifact package and raw release policy.
- P0.3: `rvmt explain:35t` terminal explanation interface.
- P1.1: 8 network-free extension candidates gated on 35T.
- P1.2: independent extension evidence snapshot.
- P2.1: fd/path and process-tree case-study matrix.
- P2.2: bounded selective pointer snapshot design review while hardware pointer capture remains default-disabled.

Allowed claim:

```text
35T / LiteX / VexRiscv hardware-trace-assisted synthetic malware-like behavior audit prototype.
```

Forbidden positive claims:

- CVA6 validation.
- Real malware detection.
- Classifier accuracy.
- Complete semantic reconstruction.
- Mature detector.
- Standalone CCF-A main contribution.
- Enabled full hardware user-pointer snapshot.
