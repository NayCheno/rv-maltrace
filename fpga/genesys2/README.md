# Genesys 2 FPGA Notes

The active Genesys 2 target is configured through `[tool.rv-maltrace]` in
`pyproject.toml`:

```text
board       = "genesys2"
target      = "cv64a6_imafdc_sv39"
xilinx_part = "xc7k325tffg900-2"  # derived from board unless explicitly overridden
```

The canonical board constraints currently come from the CVA6 tree:

```text
rtl/cva6/corev_apu/fpga/constraints/genesys-2.xdc
```

Use this directory for repository-owned overlays or notes only after they are
needed by a reproducible board gate. Keep the upstream CVA6 constraints as the
single active source until a change has a checkable reason.

## Bring-up Order

1. Baseline bitstream and timing evidence.
2. LED/UART/reset sanity checks.
3. Bare-metal tohost or UART pass.
4. Trace-enabled bare-metal with the first-board minimal event profile.
5. BRAM/ILA or UART trace dump decoded by host tools.
6. Buildroot or minimal Linux boot, if resources allow.
7. Linux syscall trace and semantic reconstruction.

## First-Board Trace Profile

Keep the first-board profile narrow:

```text
enabled:  SYSCALL_ENTRY, SYSCALL_RET, TRAP, PRIV, CSR/SATP context, DROP
deferred: RETIRE, full branch stream, full memory trace
```

`EVT_DROP` must remain observable. A full trace sink must drop and count records
instead of stalling CVA6.
