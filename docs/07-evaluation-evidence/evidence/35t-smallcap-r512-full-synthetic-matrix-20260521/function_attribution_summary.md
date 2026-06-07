# 35T Function Attribution Summary: 35t-smallcap-r512-full-synthetic-matrix-20260521

Status: PASS

Scope: Artix-7 35T / LiteX / VexRiscv only.

Claim level: 35T hardware-trace-assisted synthetic malware-like behavior audit prototype.

## Overall

- Function level: available (6/6 samples)

## Samples

- illegal_trap: status=PASS; functions=1103
- process_chain: status=PASS; functions=1101
- dynamic_executable_memory: status=PASS; functions=1099
- file_scan: status=PASS; functions=1101
- batch_open_read_write: status=PASS; functions=1101
- self_copy_sim: status=PASS; functions=1101

## Limitations

- function-level attribution is symbol/range based and is not source-line attribution
- source-line availability is tracked separately in source_attribution_summary.json
- this does not prove complete semantic reconstruction

## Non-claims

- no CVA6 board claim
- no real malware detection claim
- no mature detector claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
