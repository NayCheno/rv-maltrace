# RV-MalTrace 35T Report Outline

## Claim Boundary

State the bounded claim as a 35T / LiteX / VexRiscv hardware-trace-assisted synthetic malware-like behavior audit prototype.

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

## Limitations

Repeat non-claims for CVA6 validation, real malware detection, mature detector status, classifier accuracy, complete semantic reconstruction, and enabled hardware user-pointer snapshot.
