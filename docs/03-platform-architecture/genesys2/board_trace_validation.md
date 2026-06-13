# Board Trace Validation Programs

Phase 5.3 defines the first trace-enabled Genesys 2 validation program set and
links it to the accepted first board trace evidence.

This document is the Phase 5.3 trace-program specification and current
board-evidence index. Expected JSON files are specifications; raw board
evidence lives under the recorded evidence run root.

```text
results/board/genesys2_trace_validation/20260609-2345-phase6-syscall-ret-fix/
```

Validation command:

```powershell
uv run python tools/check_board_trace_evidence.py --root . --run-root results/board/genesys2_trace_validation/20260609-2345-phase6-syscall-ret-fix
```

Boundary: this is first-board BRAM/ILA trace validation evidence. It does not
claim a production streaming/DMA trace sink, full-retire trace coverage, or
long-run workload generalization.

## Program Matrix

| Order | Program | Source | Expected trace evidence | Status | Evidence directory |
| ---: | --- | --- | --- | --- | --- |
| 1 | hello_write | `board/trace_validation/programs/hello_write.c` | syscall `write` (`a7=64`) | BOARD_EVIDENCE_PASS | `01_hello_write/` |
| 2 | file_open_read_write | `board/trace_validation/programs/file_open_read_write.c` | creates `/tmp/rvmt_trace_validation_input.txt`, then syscalls `openat` (`a7=56`), `read` (`a7=63`), `write` (`a7=64`), `close` (`a7=57`) | BOARD_EVIDENCE_PASS | `02_file_open_read_write/` |
| 3 | fork_exec | `board/trace_validation/programs/fork_exec.c` | syscalls `clone` (`a7=220`), `execve` (`a7=221`), `wait4` (`a7=260`) | BOARD_EVIDENCE_PASS | `03_fork_exec/` |
| 4 | illegal_instruction | `board/trace_validation/programs/illegal_instruction.c` | trap event from an illegal instruction | BOARD_EVIDENCE_PASS | `04_illegal_instruction/` |

## Expected Artifacts

Each accepted program directory under the board run contains:

- `program.log`: stdout/stderr or serial console excerpt.
- `trace.jsonl`: exported board trace parsed into the project JSONL format.
- `compare.log`: manual or scripted comparison against the matching expected
  file under `board/trace_validation/expected/`.
- `observation.md`: board operator notes.

The first-board trace profile from Phase 5.2 remains active: full retire is
disabled, `RETIRE` must not be required, and syscall/trap/context/branch plus
drop accounting are the only first-board behavior signal families.
