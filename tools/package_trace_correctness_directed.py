from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
import tempfile
from pathlib import Path
from typing import Any

from check_fuzz_trace import CHECKS, check_trace, event_counts


DEFAULT_OUT = Path("results/evaluation/genesys2-cva6/current/trace_correctness_directed_summary.json")
DIRECTED_CASE_COUNT = 50
RANDOM_CASE_COUNT = 10
RANDOM_SEED = 0x52564D54
INVARIANTS = sorted(CHECKS)


def hx(value: int) -> str:
    return f"0x{value:x}"


def syscall_entry(cycle: int, pc: int, syscall_id: int, *, pid: int = 1) -> dict[str, Any]:
    return {
        "cycle": cycle,
        "evt": "SYSCALL_ENTRY",
        "pc": hx(pc),
        "instr": "0x00000073",
        "priv": "U",
        "syscall_id": hx(syscall_id),
        "pid": pid,
        "tgid": pid,
        "a0": "0x1",
        "a1": hx(0x80000000 + syscall_id * 16),
        "a2": "0x8",
        "a3": "0x0",
        "a4": "0x0",
        "a5": "0x0",
        "a6": "0x0",
        "a7": "0x40",
    }


def syscall_ret(cycle: int, pc: int, entry_pc: int, syscall_id: int, duration: int, *, pid: int = 1) -> dict[str, Any]:
    return {
        "cycle": cycle,
        "evt": "SYSCALL_RET",
        "pc": hx(pc),
        "instr": "0x10200073",
        "priv": "S",
        "sret_qualified": True,
        "target": hx(entry_pc + 4),
        "syscall_id": hx(syscall_id),
        "duration": duration,
        "pid": pid,
        "tgid": pid,
        "a0": "0x1",
    }


def trap(cycle: int, pc: int, cause: int = 2) -> dict[str, Any]:
    return {
        "cycle": cycle,
        "evt": "TRAP",
        "pc": hx(pc),
        "instr": "0xffffffff",
        "cause": hx(cause),
        "tval": "0xffffffff",
        "priv": "U",
    }


def priv(cycle: int, pc: int, old: str = "U", new: str = "S") -> dict[str, Any]:
    return {"cycle": cycle, "evt": "PRIV", "pc": hx(pc), "old_priv": old, "new_priv": new}


def csr(cycle: int, pc: int, csr_addr: int = 0x100, value: int = 0) -> dict[str, Any]:
    return {"cycle": cycle, "evt": "CSR", "pc": hx(pc), "instr": "0x10001073", "csr": hx(csr_addr), "value": hx(value), "priv": "S"}


def satp(cycle: int, pc: int, value: int = 0) -> dict[str, Any]:
    return {
        "cycle": cycle,
        "evt": "SATP",
        "pc": hx(pc),
        "instr": "0x18051073",
        "csr": "0x180",
        "value": hx(value),
        "satp": hx(value),
        "priv": "S",
    }


def branch(cycle: int, pc: int, target: int, taken: bool = True) -> dict[str, Any]:
    return {"cycle": cycle, "evt": "BRANCH", "pc": hx(pc), "instr": "0x00050863", "target": hx(target), "taken": taken}


def jump(cycle: int, pc: int, target: int) -> dict[str, Any]:
    return {"cycle": cycle, "evt": "JUMP", "pc": hx(pc), "instr": "0x0000006f", "target": hx(target)}


def retire(cycle: int, pc: int, *, port: int | None = None, priv_value: str = "U") -> dict[str, Any]:
    event: dict[str, Any] = {"cycle": cycle, "evt": "RETIRE", "pc": hx(pc), "instr": "0x00000013", "priv": priv_value}
    if port is not None:
        event["commit_port"] = port
    return event


def arg_mem(cycle: int, pc: int, syscall_id: int, last: bool) -> dict[str, Any]:
    return {
        "cycle": cycle,
        "evt": "ARG_MEM",
        "pc": hx(pc),
        "priv": "U",
        "syscall_id": hx(syscall_id),
        "arg_index": 1,
        "mem_addr": hx(0x80000000 + syscall_id * 16),
        "mem_data": "0x2f746d70",
        "mem_size": 4,
        "mem_last": last,
    }


def drop(cycle: int, value: int) -> dict[str, Any]:
    return {"cycle": cycle, "evt": "DROP", "value": hx(value)}


def marker(cycle: int, value: int) -> dict[str, Any]:
    return {"cycle": cycle, "evt": "MARKER", "value": hx(value)}


def case_config(case_id: str, events: list[dict[str, Any]]) -> dict[str, Any]:
    counts = event_counts(events)
    min_counts = {event: count for event, count in counts.items() if count > 0}
    return {
        "id": case_id,
        "invariants": INVARIANTS,
        "min_counts": min_counts,
        "allowed_trap_causes": ["0x2", "0x3"],
    }


def summarize_case(case_id: str, category: str, events: list[dict[str, Any]]) -> dict[str, Any]:
    config = case_config(case_id, events)
    errors = check_trace(events, config)
    return {
        "id": case_id,
        "category": category,
        "status": "FAIL" if errors else "PASS",
        "event_count": len(events),
        "event_counts": dict(sorted(event_counts(events).items())),
        "invariants": INVARIANTS,
        "errors": errors,
    }


def directed_cases() -> list[tuple[str, str, list[dict[str, Any]]]]:
    cases: list[tuple[str, str, list[dict[str, Any]]]] = []
    for i in range(15):
        base = 0x1000 + i * 0x100
        entry_cycle = 10 + i * 10
        sid = i
        events = [
            marker(entry_cycle - 1, i),
            syscall_entry(entry_cycle, base, sid, pid=100 + i),
            arg_mem(entry_cycle + 1, base, sid, last=True),
            syscall_ret(entry_cycle + 3, base + 0x10, base, sid, 3, pid=100 + i),
            retire(entry_cycle + 4, base + 4),
            drop(entry_cycle + 5, i + 1),
        ]
        cases.append((f"directed_syscall_pair_{i:02d}", "syscall_entry_return_pairing", events))

    for i in range(10):
        base = 0x3000 + i * 0x100
        cycle = 200 + i * 10
        events = [
            trap(cycle, base, 2 if i % 2 == 0 else 3),
            priv(cycle + 1, base, "U", "S"),
            csr(cycle + 2, base + 4, 0x100 + i, i),
            satp(cycle + 3, base + 8, i << 12),
            retire(cycle + 4, base + 0x10, priv_value="S"),
            drop(cycle + 5, i + 1),
        ]
        cases.append((f"directed_trap_context_{i:02d}", "trap_privilege_context", events))

    for i in range(10):
        base = 0x5000 + i * 0x100
        cycle = 400 + i * 10
        events = [
            branch(cycle, base, base + 0x20, taken=i % 2 == 0),
            jump(cycle + 1, base + 4, base + 0x40),
            retire(cycle + 2, base + 8, port=0),
            retire(cycle + 2, base + 12, port=1),
            drop(cycle + 3, i + 1),
        ]
        cases.append((f"directed_dual_commit_cf_{i:02d}", "dual_commit_control_flow", events))

    for i in range(15):
        base = 0x7000 + i * 0x100
        cycle = 600 + i * 10
        sid = 100 + i
        events = [
            trap(cycle, base, 2),
            marker(cycle, i),
            syscall_entry(cycle, base + 0x10, sid, pid=200 + i),
            arg_mem(cycle, base + 0x10, sid, last=False),
            csr(cycle, base + 0x14, 0x140, i),
            priv(cycle, base + 0x18, "U", "S"),
            branch(cycle, base + 0x1c, base + 0x30, True),
            retire(cycle, base + 0x20, port=0),
            retire(cycle, base + 0x24, port=1),
            syscall_ret(cycle + 2, base + 0x28, base + 0x10, sid, 2, pid=200 + i),
            arg_mem(cycle + 3, base + 0x10, sid, last=True),
            drop(cycle + 4, i + 1),
        ]
        cases.append((f"directed_same_cycle_mixed_{i:02d}", "same_cycle_event_order", events))

    if len(cases) != DIRECTED_CASE_COUNT:
        raise AssertionError(f"directed case generator produced {len(cases)} cases")
    return cases


def random_cases() -> list[tuple[str, str, list[dict[str, Any]]]]:
    rng = random.Random(RANDOM_SEED)
    cases: list[tuple[str, str, list[dict[str, Any]]]] = []
    for i in range(RANDOM_CASE_COUNT):
        base = 0x9000 + i * 0x400
        cycle = 900 + i * 30
        sid0 = 1000 + i * 2
        sid1 = sid0 + 1
        ret0_cycle = cycle + 3 + rng.randrange(0, 3)
        events = [
            marker(cycle, rng.randrange(1, 0x100)),
            syscall_entry(cycle + 1, base, sid0, pid=300 + i),
            arg_mem(cycle + 2, base, sid0, last=True),
            syscall_ret(ret0_cycle, base + 0x10, base, sid0, ret0_cycle - (cycle + 1), pid=300 + i),
            branch(cycle + 7, base + 0x14, base + 0x40 + 2 * rng.randrange(0, 8), bool(rng.randrange(0, 2))),
            jump(cycle + 8, base + 0x18, base + 0x60 + 2 * rng.randrange(0, 8)),
            trap(cycle + 9, base + 0x80, 2 if rng.randrange(0, 2) == 0 else 3),
            priv(cycle + 10, base + 0x80, "U", "S"),
            satp(cycle + 11, base + 0x84, rng.randrange(0, 0x1000) << 12),
            retire(cycle + 12, base + 0x88, port=0),
            retire(cycle + 12, base + 0x8c, port=1),
            syscall_entry(cycle + 13, base + 0xa0, sid1, pid=300 + i),
            syscall_ret(cycle + 15, base + 0xb0, base + 0xa0, sid1, 2, pid=300 + i),
            drop(cycle + 16, i + 1),
        ]
        cases.append((f"random_event_sequence_{i:02d}", "seeded_random_event_sequence", events))
    return cases


def negative_cases() -> list[tuple[str, str, list[dict[str, Any]]]]:
    base = 0xC000
    return [
        ("negative_unmatched_syscall_ret", "syscall_pairing", [syscall_ret(1, base, base - 4, 7, 1)]),
        ("negative_missing_syscall_ret", "syscall_pairing", [syscall_entry(1, base, 8)]),
        (
            "negative_same_cycle_order",
            "same_cycle_event_order",
            [retire(3, base, port=0), trap(3, base + 4, 2)],
        ),
        (
            "negative_dual_commit_reverse",
            "dual_commit_order",
            [retire(4, base, port=1), retire(4, base + 4, port=0)],
        ),
        (
            "negative_trap_retire_overlap",
            "trap_not_retire",
            [trap(5, base, 2), {"cycle": 6, "evt": "RETIRE", "pc": hx(base), "instr": "0xffffffff", "priv": "U"}],
        ),
        ("negative_drop_nonmonotonic", "drop_count_monotonic", [drop(7, 2), drop(8, 2)]),
        (
            "negative_cross_pid_return",
            "syscall_pairing",
            [syscall_entry(9, base, 9, pid=10), syscall_ret(10, base + 0x10, base, 9, 1, pid=11)],
        ),
        (
            "negative_unqualified_sret_return",
            "strict_sret_qualification",
            [
                syscall_entry(12, base, 10, pid=12),
                {**syscall_ret(13, base + 0x10, base, 10, 1, pid=12), "sret_qualified": False},
            ],
        ),
        (
            "negative_unaligned_branch_target",
            "control_flow_targets_aligned",
            [branch(11, base, base + 3, True)],
        ),
    ]


def corpus_digest(payload: dict[str, Any]) -> str:
    stable = {
        "positive_cases": payload["positive_cases"],
        "negative_cases": payload["negative_cases"],
        "coverage": payload["coverage"],
    }
    encoded = json.dumps(stable, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def package_summary() -> dict[str, Any]:
    positive_rows = [summarize_case(case_id, category, events) for case_id, category, events in [*directed_cases(), *random_cases()]]
    negative_rows = []
    for case_id, category, events in negative_cases():
        config = case_config(case_id, events)
        errors = check_trace(events, config)
        negative_rows.append(
            {
                "id": case_id,
                "category": category,
                "status": "EXPECTED_FAIL" if errors else "UNEXPECTED_PASS",
                "event_count": len(events),
                "event_counts": dict(sorted(event_counts(events).items())),
                "errors": errors,
            }
        )
    category_counts: dict[str, int] = {}
    aggregate_counts: dict[str, int] = {}
    for row in positive_rows:
        category = str(row["category"])
        category_counts[category] = category_counts.get(category, 0) + 1
        for event, count in row["event_counts"].items():
            aggregate_counts[event] = aggregate_counts.get(event, 0) + int(count)
    negative_category_counts: dict[str, int] = {}
    for row in negative_rows:
        category = str(row["category"])
        negative_category_counts[category] = negative_category_counts.get(category, 0) + 1
    coverage = {
        "directed_case_count": DIRECTED_CASE_COUNT,
        "seeded_random_case_count": RANDOM_CASE_COUNT,
        "negative_sensitivity_case_count": len(negative_rows),
        "random_seed": hx(RANDOM_SEED),
        "category_counts": dict(sorted(category_counts.items())),
        "negative_category_counts": dict(sorted(negative_category_counts.items())),
        "event_counts": dict(sorted(aggregate_counts.items())),
        "requirements": {
            "syscall_entry_return_pairing": category_counts.get("syscall_entry_return_pairing", 0) >= 15,
            "trap_and_privilege_transition": category_counts.get("trap_privilege_context", 0) >= 10,
            "dual_commit_order": category_counts.get("dual_commit_control_flow", 0) >= 10,
            "same_cycle_event_order": category_counts.get("same_cycle_event_order", 0) >= 15,
            "seeded_random_event_sequences": category_counts.get("seeded_random_event_sequence", 0) >= RANDOM_CASE_COUNT,
            "drop_accounting": aggregate_counts.get("DROP", 0) >= DIRECTED_CASE_COUNT + RANDOM_CASE_COUNT,
            "pointer_argument_fragment": aggregate_counts.get("ARG_MEM", 0) >= 20,
            "strict_sret_negative_sensitivity": negative_category_counts.get("strict_sret_qualification", 0) >= 1,
        },
    }
    status = "PASS"
    if any(row["status"] != "PASS" for row in positive_rows):
        status = "FAIL"
    if any(row["status"] != "EXPECTED_FAIL" for row in negative_rows):
        status = "FAIL"
    if not all(coverage["requirements"].values()):
        status = "FAIL"
    summary = {
        "schema": "rvmt.trace_correctness.directed_corpus.v1",
        "status": status,
        "positive_case_count": len(positive_rows),
        "directed_case_count": DIRECTED_CASE_COUNT,
        "seeded_random_case_count": RANDOM_CASE_COUNT,
        "negative_sensitivity_case_count": len(negative_rows),
        "invariant_catalog": INVARIANTS,
        "coverage": coverage,
        "positive_cases": positive_rows,
        "negative_cases": negative_rows,
        "claim_boundary": {
            "local_directed_trace_corpus": True,
            "vivado_run_performed": False,
            "genesys2_board_run_performed": False,
            "processor_bug_discovery_claimed": False,
            "real_malware_validation_claimed": False,
            "cycle_level_overhead_claimed": False,
        },
        "non_claims": [
            "This corpus validates RV-MalTrace trace event invariant handling and directed edge cases; it is not a new Vivado or Genesys2 board run.",
            "The seeded random event sequences are deterministic checker fixtures, not a RISCV-DV processor bug-discovery campaign.",
            "The corpus does not add malware validation, production streaming/DMA throughput, or cycle-level overhead evidence.",
        ],
    }
    summary["corpus_digest"] = corpus_digest(summary)
    return summary


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def self_test() -> int:
    summary = package_summary()
    if summary.get("status") != "PASS":
        print("[FAIL] directed trace correctness corpus did not pass", file=sys.stderr)
        return 1
    if summary.get("directed_case_count") != 50 or summary.get("seeded_random_case_count") != 10:
        print("[FAIL] directed trace correctness corpus counts are wrong", file=sys.stderr)
        return 1
    if any(row.get("status") != "EXPECTED_FAIL" for row in summary.get("negative_cases", [])):
        print("[FAIL] directed trace correctness negative cases did not fail as expected", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "summary.json"
        write_json(out, summary)
        loaded = json.loads(out.read_text(encoding="utf-8"))
        if loaded.get("corpus_digest") != corpus_digest(loaded):
            print("[FAIL] directed trace correctness corpus digest is unstable", file=sys.stderr)
            return 1
    print("[PASS] trace correctness directed corpus packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package deterministic directed trace-correctness corpus evidence.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    out = args.out if args.out.is_absolute() else root / args.out
    summary = package_summary()
    write_json(out, summary)
    print(f"[{summary['status']}] wrote trace correctness directed corpus summary to {out}")
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
