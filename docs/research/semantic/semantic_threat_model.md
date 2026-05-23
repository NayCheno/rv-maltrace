# Semantic Threat Model

Status: BOUNDARY_SPECIFIED

Claim level: 35T hardware-trace-assisted synthetic malware-like behavior audit prototype.

This threat model applies to the current Artix-7 35T / LiteX / VexRiscv
evidence line. The current claim is limited to controlled benign and synthetic
malware-like workloads. It is not a real malware detector claim.

## Trusted Components

- hardware trace tap
- FPGA bitstream under test
- Linux kernel
- board runner
- offline analysis tools

## In Scope

- user-mode malware-like workload
- user-mode syscall behavior
- user-mode ptrace or TracerPid checks
- user-mode timing checks
- user-mode file, process, and memory-mapping behavior

## Out of Scope

- kernel rootkit
- malicious kernel
- malicious kernel module
- compromised eBPF program
- compromised board runner
- firmware or bitstream tampering
- real malware detection accuracy

## Semantic Route Boundaries

The event-only hardware trace route is the current 35T claim. It is
authoritative for committed event, syscall, return, trap, marker, DROP, and
capacity evidence in the bounded prototype.

The selective memory snapshot route is deferred. It must remain default-disabled
until timing, bandwidth, noninterference, and pointer-safety evidence exists.

The kernel helper metadata route is an optional deferred companion under a
trusted kernel model. It can provide pid, fd, and path metadata for offline
alignment, but it cannot support any resistance claim against a malicious kernel
or kernel rootkit.

The eBPF metadata alignment route is an optional deferred companion under a
trusted kernel and eBPF runtime model. It is comparison or enrichment only, not
an MVP dependency and not a replacement for RTL trace evidence.

## Required Wording

When helper or eBPF companion evidence is discussed, use the wording:
trusted kernel, user-mode malware-like workload, and kernel rootkit out of
scope.

Canonical phrase: trusted kernel, user-mode malware-like workload, kernel rootkit out of scope.

## Non-Claims

- no kernel rootkit resistance claim
- no malicious kernel resistance claim
- no eBPF tamper resistance claim
- no real malware detection claim
- no complete pointer semantic reconstruction claim
- no helper or eBPF MVP dependency claim
