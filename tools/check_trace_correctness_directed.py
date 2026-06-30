from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    as_dict,
    as_list,
    load_json,
    require,
)

from package_trace_correctness_directed import DEFAULT_OUT, corpus_digest, package_summary, write_json


REQUIRED_REQUIREMENTS = {
    "syscall_entry_return_pairing",
    "trap_and_privilege_transition",
    "dual_commit_order",
    "same_cycle_event_order",
    "seeded_random_event_sequences",
    "drop_accounting",
    "pointer_argument_fragment",
    "strict_sret_negative_sensitivity",
}
REQUIRED_INVARIANTS = {
    "known_event_types",
    "trace_schema_required_fields",
    "control_flow_targets_aligned",
    "trap_not_retire",
    "syscall_pairing",
    "same_cycle_event_order",
    "dual_commit_order",
    "context_events_well_formed",
    "drop_count_monotonic",
    "sret_return_qualified",
}
REQUIRED_NEGATIVE_CASE_IDS = {
    "negative_unmatched_syscall_ret",
    "negative_missing_syscall_ret",
    "negative_same_cycle_order",
    "negative_dual_commit_reverse",
    "negative_trap_retire_overlap",
    "negative_drop_nonmonotonic",
    "negative_cross_pid_return",
    "negative_unqualified_sret_return",
    "negative_unaligned_branch_target",
}


def check_summary(data: dict[str, Any], *, compare_generated: bool = True) -> list[str]:
    errors: list[str] = []
    require(errors, data.get("schema") == "rvmt.trace_correctness.directed_corpus.v1", "schema mismatch")
    require(errors, data.get("status") == "PASS", "status must be PASS")
    require(errors, int(data.get("directed_case_count") or 0) >= 50, "directed_case_count must be at least 50")
    require(errors, int(data.get("seeded_random_case_count") or 0) >= 10, "seeded_random_case_count must be at least 10")
    require(errors, int(data.get("positive_case_count") or 0) >= 60, "positive_case_count must be at least 60")
    require(errors, int(data.get("negative_sensitivity_case_count") or 0) >= 6, "negative sensitivity coverage is too small")

    invariants = set(str(item) for item in as_list(data.get("invariant_catalog")))
    missing_invariants = sorted(REQUIRED_INVARIANTS - invariants)
    require(errors, not missing_invariants, f"missing invariants: {', '.join(missing_invariants)}")

    coverage = as_dict(data.get("coverage"))
    requirements = as_dict(coverage.get("requirements"))
    missing_requirements = sorted(REQUIRED_REQUIREMENTS - set(requirements))
    require(errors, not missing_requirements, f"missing coverage requirements: {', '.join(missing_requirements)}")
    for key in sorted(REQUIRED_REQUIREMENTS):
        require(errors, requirements.get(key) is True, f"coverage requirement did not pass: {key}")
    category_counts = as_dict(coverage.get("category_counts"))
    negative_category_counts = as_dict(coverage.get("negative_category_counts"))
    for key, minimum in {
        "syscall_entry_return_pairing": 15,
        "trap_privilege_context": 10,
        "dual_commit_control_flow": 10,
        "same_cycle_event_order": 15,
        "seeded_random_event_sequence": 10,
    }.items():
        require(errors, int(category_counts.get(key) or 0) >= minimum, f"{key} coverage below {minimum}")
    event_counts = as_dict(coverage.get("event_counts"))
    for event in ("SYSCALL_ENTRY", "SYSCALL_RET", "TRAP", "PRIV", "RETIRE", "ARG_MEM", "DROP"):
        require(errors, int(event_counts.get(event) or 0) > 0, f"aggregate event coverage missing {event}")

    positive_cases = as_list(data.get("positive_cases"))
    negative_cases = as_list(data.get("negative_cases"))
    require(errors, len(positive_cases) == int(data.get("positive_case_count") or -1), "positive case count mismatch")
    require(errors, len(negative_cases) == int(data.get("negative_sensitivity_case_count") or -1), "negative case count mismatch")
    require(
        errors,
        int(negative_category_counts.get("strict_sret_qualification") or 0) >= 1,
        "strict SRET negative sensitivity coverage missing",
    )
    negative_ids = {str(row.get("id")) for row in negative_cases if isinstance(row, dict)}
    missing_negative_ids = sorted(REQUIRED_NEGATIVE_CASE_IDS - negative_ids)
    require(errors, not missing_negative_ids, f"missing negative cases: {', '.join(missing_negative_ids)}")
    for row in positive_cases:
        if isinstance(row, dict):
            require(errors, row.get("status") == "PASS", f"{row.get('id')}: positive case did not pass")
            require(errors, not row.get("errors"), f"{row.get('id')}: positive case has errors")
            if int(as_dict(row.get("event_counts")).get("SYSCALL_RET") or 0) > 0:
                require(errors, "sret_return_qualified" in as_list(row.get("invariants")), f"{row.get('id')}: missing strict SRET invariant")
    for row in negative_cases:
        if isinstance(row, dict):
            require(errors, row.get("status") == "EXPECTED_FAIL", f"{row.get('id')}: negative case did not fail")
            require(errors, bool(row.get("errors")), f"{row.get('id')}: negative case has no checker errors")
            if row.get("id") == "negative_unqualified_sret_return":
                require(
                    errors,
                    any("sret_qualified=true" in str(error) for error in as_list(row.get("errors"))),
                    "negative_unqualified_sret_return must fail on sret_qualified=true",
                )

    boundary = as_dict(data.get("claim_boundary"))
    require(errors, boundary.get("local_directed_trace_corpus") is True, "local directed-corpus boundary missing")
    require(errors, boundary.get("vivado_run_performed") is False, "must not claim a Vivado run")
    require(errors, boundary.get("genesys2_board_run_performed") is False, "must not claim a Genesys2 board run")
    require(errors, boundary.get("processor_bug_discovery_claimed") is False, "must not claim processor bug discovery")
    require(errors, boundary.get("real_malware_validation_claimed") is False, "must not claim real malware validation")
    require(errors, boundary.get("cycle_level_overhead_claimed") is False, "must not claim cycle-level overhead")

    non_claims = " ".join(str(item).lower() for item in as_list(data.get("non_claims")))
    require(errors, "not a new vivado or genesys2 board run" in non_claims, "non-claim must reject board/Vivado evidence")
    require(errors, "not a riscv-dv processor bug-discovery campaign" in non_claims, "non-claim must reject processor fuzzing")
    require(errors, "does not add malware validation" in non_claims, "non-claim must reject malware validation")
    require(errors, data.get("corpus_digest") == corpus_digest(data), "corpus_digest mismatch")

    if compare_generated:
        generated = package_summary()
        require(errors, data.get("corpus_digest") == generated.get("corpus_digest"), "summary does not match regenerated corpus digest")
        require(errors, data.get("positive_case_count") == generated.get("positive_case_count"), "regenerated positive case count mismatch")
        require(errors, data.get("negative_sensitivity_case_count") == generated.get("negative_sensitivity_case_count"), "regenerated negative case count mismatch")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "summary.json"
        summary = package_summary()
        write_json(path, summary)
        errors = check_summary(load_json(path))
        if errors:
            print("[FAIL] trace correctness checker rejected good fixture", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        summary["directed_case_count"] = 49
        summary["corpus_digest"] = corpus_digest(summary)
        errors = check_summary(summary, compare_generated=False)
        if not any("directed_case_count" in error for error in errors):
            print("[FAIL] trace correctness checker missed too few directed cases", file=sys.stderr)
            return 1
        summary = package_summary()
        summary["claim_boundary"]["genesys2_board_run_performed"] = True
        summary["corpus_digest"] = corpus_digest(summary)
        errors = check_summary(summary, compare_generated=False)
        if not any("Genesys2 board run" in error for error in errors):
            print("[FAIL] trace correctness checker missed false board-run claim", file=sys.stderr)
            return 1
    print("[PASS] trace correctness directed corpus checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check deterministic directed trace-correctness corpus evidence.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    path = args.summary if args.summary.is_absolute() else root / args.summary
    if not path.is_file():
        print(f"[FAIL] missing trace correctness directed corpus summary: {path}", file=sys.stderr)
        return 1
    try:
        errors = check_summary(load_json(path))
    except Exception as exc:
        print(f"[FAIL] trace correctness directed corpus checker error: {exc}", file=sys.stderr)
        return 2
    if errors:
        print("[FAIL] trace correctness directed corpus summary is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] trace correctness directed corpus accepted: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
