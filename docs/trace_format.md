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

## Filter Controls

`trace_filter.sv` can suppress events before they enter the trace queue. The
default configuration passes all events.

| Control | Meaning |
| --- | --- |
| `enable_retire` | Emit `RETIRE` events. |
| `enable_branch` | Emit `BRANCH` events. |
| `enable_jump` | Emit `JUMP` events. |
| `enable_syscall` | Emit `ECALL` events. |
| `enable_trap` | Emit `TRAP` events. |
| `enable_context` | Emit `CSR`, `SATP`, and `PRIV` context events. |
| `enable_marker` | Emit `MARKER` events. |
| `enable_drop` | Emit `DROP` events for queue overflow accounting. |
| `pc_filter_enable`, `pc_start`, `pc_end` | When enabled, pass only packets with `pc_start <= pc <= pc_end`. |
| `priv_filter_enable`, `priv_mask` | When enabled, pass only packets whose `priv` bit is set in `priv_mask`. |

## Compressed Trace Prototype

`tools/compress_trace.py` provides the Phase 2 packet compression prototype for
simulation traces. It keeps JSONL as the carrier for easy inspection, but each
record uses a variable payload shape:

```json
{"header":{"version":1,"seq":0,"evt":"BRANCH","cycle_delta":4,"pc_delta":"0x80000220","payload_len":57},"payload":{"instr":"0x00050863","taken":true,"target_delta":"0x10"}}
```

Compression rules:

- `cycle_delta` is relative to the previous emitted event cycle.
- `pc_delta` is relative to the previous emitted event PC and may be negative;
  it is omitted for events such as `MARKER` and `DROP` that do not carry `pc`.
- Branch and jump targets are stored as `target_delta` relative to the event PC.
- Event-specific fields stay in `payload`; unchanged context fields are omitted
  from `payload.ctx` and reconstructed by the decompressor.
- `payload_len` is the byte length of the canonical JSON payload used by this
  prototype, not a final hardware wire encoding.

The prototype supports round-trip checking:

```powershell
uv run python tools/compress_trace.py results/vivado_sim/rvfi_adapter/trace.jsonl --out results/vivado_sim/rvfi_adapter/trace.compact.jsonl --stats
uv run python tools/compress_trace.py results/vivado_sim/rvfi_adapter/trace.compact.jsonl --decompress --out results/vivado_sim/rvfi_adapter/trace.roundtrip.jsonl
uv run python tools/compress_trace.py results/vivado_sim/rvfi_adapter/trace.jsonl --check-roundtrip --stats
uv run python tools/compress_trace.py sim/golden/compression_edges.trace.jsonl --check-roundtrip --stats
```

## Selective Memory Trace

Phase 2.3 reserves the memory trace policy but leaves it disabled. The RTL
package defines:

| Mode | RTL Name | Meaning |
| ---: | --- | --- |
| 0 | `TRACE_MEM_MODE_NONE` | Do not emit memory trace records. |
| 1 | `TRACE_MEM_MODE_ADDR` | Future mode for load/store address-only records. |
| 2 | `TRACE_MEM_MODE_RANGE` | Future mode for address-range-selected records. |

`TRACE_MEM_MODE_DEFAULT` is `TRACE_MEM_MODE_NONE`. The current JSONL event set
does not define load/store trace records or memory data payload fields.
