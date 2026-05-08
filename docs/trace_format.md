# Trace Format

The MVP trace stream is a sequence of committed behavior events. Simulation
uses JSONL because event payloads are sparse and easy to diff.

## Event Types

RTL packets carry the numeric `trace_evt_e` value. JSONL emits the matching
string name for readability.

| Numeric Code | RTL Name | JSONL Name |
| ---: | --- | --- |
| 0 | `EVT_NONE` | `NONE` |
| 1 | `EVT_RETIRE` | `RETIRE` |
| 2 | `EVT_BRANCH` | `BRANCH` |
| 3 | `EVT_JUMP` | `JUMP` |
| 4 | `EVT_ECALL` | `ECALL` |
| 5 | `EVT_TRAP` | `TRAP` |
| 6 | `EVT_CSR` | `CSR` |
| 7 | `EVT_SATP` | `SATP` |
| 8 | `EVT_PRIV` | `PRIV` |
| 9 | `EVT_MARKER` | `MARKER` |
| 10 | `EVT_DROP` | `DROP` |

| Event | Meaning | Required Fields |
| --- | --- | --- |
| `RETIRE` | Committed instruction | `cycle`, `pc`, `instr`, `priv` |
| `BRANCH` | Committed conditional branch | `cycle`, `pc`, `instr`, `taken`, `target` |
| `JUMP` | Committed `jal` or `jalr` | `cycle`, `pc`, `instr`, `target` |
| `ECALL` | Committed syscall instruction | `cycle`, `pc`, `instr`, `priv`, `a0`-`a7` |
| `TRAP` | Trap, exception, or interrupt | `cycle`, `pc`, `cause`, `tval`, `priv` |
| `CSR` | Watched CSR write | `cycle`, `pc`, `instr`, `csr`, `value`, `priv` |
| `SATP` | `satp` write | `cycle`, `pc`, `instr`, `csr`, `value`, `satp`, `priv` |
| `PRIV` | Privilege mode change | `cycle`, `pc`, `old_priv`, `new_priv` |
| `MARKER` | Test or sink marker | `cycle`, `value` |
| `DROP` | Dropped trace event marker | `cycle`, `value` |

## Packet Fields

| Field | Width | Meaning |
| --- | ---: | --- |
| `valid` | 1 | Packet is valid. |
| `evt` | 4 | Encoded event type. |
| `cycle` | 64 | Local trace cycle counter. |
| `pc` | 64 | Committed PC or trap PC. |
| `instr` | 32 | Committed 32-bit instruction word. |
| `target` | 64 | Branch/jump target or next PC. |
| `taken` | 1 | Conditional branch taken flag. |
| `priv` | 2 | Current privilege mode. |
| `old_priv` | 2 | Previous privilege mode for `PRIV`. |
| `new_priv` | 2 | New privilege mode for `PRIV`. |
| `satp` | 64 | Address translation context. |
| `csr` | 12 | CSR address for CSR/SATP events. |
| `value` | 64 | CSR value, marker value, or drop count. |
| `cause` | 64 | Trap cause. |
| `tval` | 64 | Trap value. |
| `a0`-`a7` | 64 each | Syscall argument shadow registers. |

## JSONL Example

```json
{"cycle":4,"evt":"RETIRE","pc":"0x0000000080000000","instr":"0x00000513","priv":"M"}
{"cycle":7,"evt":"BRANCH","pc":"0x0000000080000010","instr":"0x00050863","taken":true,"target":"0x0000000080000020"}
{"cycle":10,"evt":"ECALL","pc":"0x0000000080000040","instr":"0x00000073","priv":"M","a7":"0x0000000000000040","a0":"0x0000000000000001"}
```

## Comparison Rules

- Strict fields: `evt`, `pc`, `instr`, `target`, `taken`, syscall arguments,
  `cause`, `csr`, and `value` when present in the golden file.
- Loose fields: `cycle`, `satp`, and `tval` unless the golden file specifies
  exact values.
- Golden values may use `"ANY"` to assert that a field is present without
  constraining its exact value.
