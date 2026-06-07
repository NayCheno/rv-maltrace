# 35T Pointer Snapshot Design Review

This note records the bounded design review for a future selective
user-pointer snapshot route. It is not enablement evidence and it is not a 35T
hardware user-pointer snapshot PASS claim.

The structured design record is:

```text
experiments/linux_behavior/pointer_snapshot_design_review.json
```

## Current Policy

The current 35T policy remains:

```text
TRACE_MEM_MODE_NONE
hardware_user_pointer_snapshot = DEFERRED
default_enabled = false
small_capacity_profiles = ARG_MEM_DISABLED
```

The existing `p2_pointer_snapshot` profile is a gated experiment profile. It
must not enable `ARG_MEM` by default, and the small-capacity 35T profiles must
remain event-only for the current claim.

## Bounded Allowlist

The first enablement candidate is restricted to pathname prefixes for selected
syscall arguments:

| Syscall | Argument | Payload | Limit |
| --- | --- | --- | ---: |
| `openat` | `a1` | pathname prefix | 64 bytes |
| `execve` | `a0` | pathname prefix | 64 bytes |

The route must stop at NUL or the byte limit, whichever comes first. It must not
record general load/store payloads.

## Safety Guardrails

Any later implementation must keep:

- default-disabled control path
- page-boundary clipping
- fault and timeout handling
- no load/store payload trace mode
- no core backpressure
- DROP or explicit truncation accounting on overflow

## Gates Still Required

Before enablement or any upgraded claim, the project still needs timing/resource
evidence, bandwidth and DROP accounting, trace-off/trace-on noninterference
evidence, semantic accuracy against ground truth, and a raw pointer payload
release policy.

Synthetic ARG_MEM fixtures and syscall side-channel path strings cannot be used
as substitutes for enabled hardware user-pointer memory snapshot evidence.
