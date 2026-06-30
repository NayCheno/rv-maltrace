from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    require,
)

import official_image_evidence_common as common
import run_genesys2_aslr_pie_probe as runner


DEFAULT_SUMMARY = common.CURRENT_ROOT / "official_image_aslr_pie_summary.json"


def check_file(root: Path, errors: list[str], row: dict[str, Any], label: str) -> None:
    path = common.repo_path(root, str(row.get("path") or ""))
    require(errors, path.is_file() and row.get("exists") is True, f"{label}: file missing")
    if path.is_file():
        require(errors, row.get("sha256") == common.sha256_file(path), f"{label}: sha256 mismatch")


def check_summary(root: Path, path: Path) -> list[str]:
    data = common.load_json(path)
    errors: list[str] = []
    status = str(data.get("status") or "")
    require(errors, data.get("schema") == runner.SCHEMA, "schema mismatch")
    require(errors, status == "PASS" or status.startswith("BLOCKED_"), "status must be PASS or BLOCKED")
    boundary = data.get("claim_boundary") if isinstance(data.get("claim_boundary"), dict) else {}
    require(errors, boundary.get("static_exec_fixed_base_is_baseline_only") is True, "static baseline boundary missing")
    require(errors, boundary.get("qemu_or_strace_substitution_used") is False, "must be board map evidence")
    require(errors, boundary.get("cycle_level_overhead_claimed") is False, "must not claim cycle overhead")
    require(errors, boundary.get("real_malware_validation_claimed") is False, "must not claim real malware")
    for name, row in (data.get("artifacts") or {}).items():
        if isinstance(row, dict):
            check_file(root, errors, row, f"artifact.{name}")
    variants = data.get("variants") if isinstance(data.get("variants"), dict) else {}
    static = variants.get("static_exec") if isinstance(variants.get("static_exec"), dict) else {}
    dynamic = variants.get("dynamic_pie") if isinstance(variants.get("dynamic_pie"), dict) else {}
    require(errors, int(static.get("pass_count") or 0) >= 2, "static_exec needs repeated baseline captures")
    require(errors, int(static.get("unique_base_count") or 0) == 1, "static_exec baseline should have one fixed base")
    if status == "PASS":
        require(errors, boundary.get("aslr_dynamic_pie_board_claimed") is True, "PASS must claim dynamic PIE ASLR observation")
        require(errors, int(dynamic.get("pass_count") or 0) >= 2, "PASS requires repeated dynamic PIE captures")
        require(errors, int(dynamic.get("unique_base_count") or 0) > 1, "PASS requires varying dynamic PIE bases")
    else:
        require(errors, boundary.get("aslr_dynamic_pie_board_claimed") is False, "BLOCKED must not claim dynamic PIE ASLR")
        require(errors, bool(data.get("blocked_reason")), "BLOCKED summary must include blocked_reason")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="rvmt-aslr-check-") as tmp:
        root = Path(tmp)
        build = root / "build.json"
        build.write_text("{}", encoding="utf-8")
        transfer_a = root / "a.log"
        transfer_b = root / "b.log"
        transfer_a.write_text("a", encoding="utf-8")
        transfer_b.write_text("b", encoding="utf-8")
        summary = root / "summary.json"
        common.write_json(summary, {
            "schema": runner.SCHEMA,
            "status": "BLOCKED_DYNAMIC_PIE_RUNTIME_UNAVAILABLE",
            "blocked_reason": "dynamic unavailable",
            "variants": {
                "static_exec": {"pass_count": 2, "unique_base_count": 1},
                "dynamic_pie": {"pass_count": 0, "unique_base_count": 0},
            },
            "artifacts": {
                "build_manifest": common.file_row(build),
                "static_exec_transfer_log": common.file_row(transfer_a),
                "dynamic_pie_transfer_log": common.file_row(transfer_b),
            },
            "claim_boundary": {
                "aslr_dynamic_pie_board_claimed": False,
                "static_exec_fixed_base_is_baseline_only": True,
                "qemu_or_strace_substitution_used": False,
                "cycle_level_overhead_claimed": False,
                "real_malware_validation_claimed": False,
            },
        })
        errors = check_summary(root, summary)
    if errors:
        print("[FAIL] ASLR checker fixture failed", file=sys.stderr)
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("[PASS] official-image ASLR/PIE checker self-test")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Check official-image ASLR/PIE map evidence.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    path = args.summary if args.summary.is_absolute() else root / args.summary
    if not path.is_file():
        print(f"[FAIL] ASLR/PIE summary missing: {path}", file=sys.stderr)
        return 1
    errors = check_summary(root, path)
    if errors:
        print("[FAIL] ASLR/PIE summary is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] ASLR/PIE summary accepted: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
