from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    as_list,
    load_json,
    require,
    write_json,
)

from genesys2_latest import DEFAULT_LATEST_MANIFEST, LATEST_SCHEMA, load_latest_manifest, repo_path


REQUIRED_ACTIVE_ROOTS = {
    "p0_continuous_trace",
    "p0_bram_repetitions",
    "safe_surrogate_bram_repetitions",
    "safe_surrogate_runtime_map",
    "pointer_snapshot_bram",
    "production_runtime_benchmark",
}

DATED_BOARD_RUN_RE = re.compile(r"results[/\\]board[/\\]genesys2_trace_validation[/\\]20\d{6}")


def command_tokens(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        result: list[str] = []
        for item in value:
            result.extend(command_tokens(item))
        return result
    return []


def check_suite_commands(errors: list[str], root: Path) -> None:
    suite_path = root / "tools" / "check_suites.json"
    try:
        data = load_json(suite_path)
    except Exception as exc:
        errors.append(f"check_suites.json load failed: {exc}")
        return
    suites = as_list(data.get("suites"))
    for suite in suites:
        if not isinstance(suite, dict) or suite.get("current") is not True or suite.get("legacy") is True:
            continue
        for check in as_list(suite.get("checks")):
            if not isinstance(check, dict):
                continue
            for token in command_tokens(check.get("command")):
                require(
                    errors,
                    DATED_BOARD_RUN_RE.search(token) is None,
                    f"{suite.get('id')}.{check.get('id')}: current suite command must resolve board run roots through latest_manifest, not hardcode {token}",
                )


def check_latest_standard(root: Path, manifest_path: Path) -> list[str]:
    errors: list[str] = []
    try:
        manifest_file, manifest = load_latest_manifest(root, manifest_path)
    except Exception as exc:
        return [str(exc)]
    require(errors, manifest.get("schema") == LATEST_SCHEMA, f"{manifest_file}: latest schema mismatch")
    require(errors, manifest.get("status") == "PASS", f"{manifest_file}: status must be PASS")
    require(errors, manifest.get("canonical_evaluation_root") == "results/evaluation/genesys2-cva6/current", "canonical_evaluation_root must be current")
    current_root = repo_path(root, str(manifest.get("canonical_evaluation_root") or ""))
    require(errors, current_root.is_dir(), f"canonical evaluation root missing: {current_root}")
    policy = manifest.get("policy") if isinstance(manifest.get("policy"), dict) else {}
    require(errors, policy.get("latest_is_authoritative") is True, "policy.latest_is_authoritative must be true")
    require(errors, policy.get("dated_run_roots_are_provenance_only") is True, "policy.dated_run_roots_are_provenance_only must be true")
    require(errors, policy.get("do_not_select_by_chronological_order") is True, "policy.do_not_select_by_chronological_order must be true")
    active_roots = manifest.get("active_run_roots") if isinstance(manifest.get("active_run_roots"), dict) else {}
    missing = sorted(REQUIRED_ACTIVE_ROOTS - set(active_roots))
    require(errors, not missing, f"active_run_roots missing: {', '.join(missing)}")
    for key in REQUIRED_ACTIVE_ROOTS:
        value = active_roots.get(key)
        if value:
            require(errors, repo_path(root, str(value)).is_dir(), f"active_run_roots.{key} missing directory: {value}")

    try:
        p0_bram = load_json(current_root / "p0_bram_trace_summary.json")
        safe_bram = load_json(current_root / "safe_surrogate_bram_trace_summary.json")
        drop = load_json(current_root / "drop_accounting_summary.json")
        pointer = load_json(current_root / "pointer_snapshot_guardrails.json")
    except Exception as exc:
        errors.append(f"current summary load failed: {exc}")
        return errors

    require(errors, p0_bram.get("run_root") == active_roots.get("p0_bram_repetitions"), "p0_bram_trace_summary.run_root must match latest manifest")
    require(errors, safe_bram.get("run_root") == active_roots.get("safe_surrogate_bram_repetitions"), "safe_surrogate_bram_trace_summary.run_root must match latest manifest")
    require(errors, drop.get("p0_run_root") == active_roots.get("p0_continuous_trace"), "drop_accounting_summary.p0_run_root must match latest manifest")
    require(errors, drop.get("p0_bram_run_root") == active_roots.get("p0_bram_repetitions"), "drop_accounting_summary.p0_bram_run_root must match latest manifest")
    require(errors, drop.get("safe_surrogate_bram_run_root") == active_roots.get("safe_surrogate_bram_repetitions"), "drop_accounting_summary.safe_surrogate_bram_run_root must match latest manifest")
    require(errors, pointer.get("p0_run_root") == active_roots.get("p0_continuous_trace"), "pointer_snapshot_guardrails.p0_run_root must match latest manifest")
    require(errors, pointer.get("safe_surrogate_bram_run_root") == active_roots.get("pointer_snapshot_bram"), "pointer_snapshot_guardrails.safe_surrogate_bram_run_root must match latest manifest pointer snapshot root")
    check_suite_commands(errors, root)
    return errors


def write_fixture(root: Path, hardcoded_suite_path: bool) -> Path:
    current = root / "results/evaluation/genesys2-cva6/current"
    active_roots = {
        "p0_continuous_trace": "results/board/genesys2_trace_validation/20260611-p0-continuous-136bit",
        "p0_bram_repetitions": "results/board/genesys2_trace_validation/20260624-current-p0-cohort",
        "safe_surrogate_bram_repetitions": "results/board/genesys2_trace_validation/20260624-current-safe-surrogate-cohort",
        "safe_surrogate_runtime_map": "results/board/genesys2_trace_validation/20260611-safe-surrogate-runtime-map",
        "pointer_snapshot_bram": "results/board/genesys2_trace_validation/20260612-pointer-snapshot-bram",
        "production_runtime_benchmark": "results/board/genesys2_trace_validation/20260612-production-runtime-benchmark",
    }
    for path in active_roots.values():
        (root / path).mkdir(parents=True, exist_ok=True)
    write_json(
        current / "latest_manifest.json",
        {
            "schema": LATEST_SCHEMA,
            "status": "PASS",
            "canonical_evaluation_root": "results/evaluation/genesys2-cva6/current",
            "policy": {
                "latest_is_authoritative": True,
                "dated_run_roots_are_provenance_only": True,
                "do_not_select_by_chronological_order": True,
            },
            "active_run_roots": active_roots,
        },
    )
    write_json(current / "p0_bram_trace_summary.json", {"run_root": active_roots["p0_bram_repetitions"]})
    write_json(current / "safe_surrogate_bram_trace_summary.json", {"run_root": active_roots["safe_surrogate_bram_repetitions"]})
    write_json(
        current / "drop_accounting_summary.json",
        {
            "p0_run_root": active_roots["p0_continuous_trace"],
            "p0_bram_run_root": active_roots["p0_bram_repetitions"],
            "safe_surrogate_bram_run_root": active_roots["safe_surrogate_bram_repetitions"],
        },
    )
    write_json(
        current / "pointer_snapshot_guardrails.json",
        {
            "p0_run_root": active_roots["p0_continuous_trace"],
            "safe_surrogate_bram_run_root": active_roots["pointer_snapshot_bram"],
        },
    )
    command = ["{python}", "tools/check_genesys2_p0_continuous_trace.py", "--root", "{root}"]
    if hardcoded_suite_path:
        command = [
            "{python}",
            "tools/check_genesys2_p0_continuous_trace.py",
            "--run-root",
            active_roots["p0_continuous_trace"],
        ]
    write_json(
        root / "tools/check_suites.json",
        {
            "suites": [
                {
                    "id": "genesys2-current",
                    "current": True,
                    "legacy": False,
                    "checks": [{"id": "p0-continuous-trace", "command": command}],
                }
            ]
        },
    )
    return current / "latest_manifest.json"


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        manifest = write_fixture(root, hardcoded_suite_path=False)
        errors = check_latest_standard(root, manifest)
        if errors:
            print("[FAIL] latest-standard good fixture failed", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        manifest = write_fixture(root, hardcoded_suite_path=True)
        errors = check_latest_standard(root, manifest)
        if not any("latest_manifest" in error for error in errors):
            print("[FAIL] latest-standard bad fixture did not reject hardcoded dated suite path", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 latest-standard checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check that current Genesys2/CVA6 gates use latest_manifest as the single standard.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--latest-manifest", type=Path, default=DEFAULT_LATEST_MANIFEST)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    errors = check_latest_standard(root, args.latest_manifest)
    if errors:
        print("[FAIL] Genesys2 latest standard is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print("[PASS] Genesys2 latest manifest is the current standard")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
