# RV-MalTrace 35T Report Outline

## Claim Boundary

State the bounded claim as a 35T / LiteX / VexRiscv hardware-trace-assisted malware-behavior evidence-chain prototype. The core 13-sample matrix remains the controlled synthetic/benign feasibility gate; the 5/24 evidence packages add board-tested real-malware-derived DarthRa and Mirai behavior cases.

## Primary 35T Gate

Report the 13-sample full-matrix result for `35t-smallcap-r512-full-synthetic-matrix-20260521`, including trace records, DROP, marker scope, runtime process attribution, and expected behavior matching.

## Semantic Artifacts

Summarize recovered syscall/trap/process/file behavior, behavior graphs, trace-code joins, fd/path representative closure, and process-tree representative closure. Keep trace-proven, inferred, side-channel, and missing evidence separate.

## Terminal Explanation Interface

Document `uv run rvmt explain:35t --run-id <run> --sample <sample> --rep auto` as the default terminal explanation command. Show that it prints trace health, gate status, recovered behaviors, suspicious cues, evidence sources, warnings, and non-claims.

## Artifact Package

Describe public lightweight artifacts, controlled raw package policy, and local-only build package boundaries. State that hash plus sanitized excerpts plus controlled escrow are not equivalent to full raw public release.

## Extension Gate

Report extension samples separately from the primary 13-sample gate. The first extension gate is network-free and excludes `loopback_network_client` by default.

## Real-Malware-Derived Behavior Evidence

Report the six board-tested real-malware-derived behavior rows as evidence that RV-MalTrace can track, validate, and rule-detect/audit behaviors selected from real malware references under safety controls. Describe the safety controls as execution containment, not as a reason to remove these rows from the real-malware feasibility narrative.

## Limitations

Repeat non-claims for CVA6 validation, uncontrolled/network-enabled payload execution, malware-family accuracy, IOC/TTP coverage, mature detector status, complete semantic reconstruction, and enabled hardware user-pointer snapshot.
