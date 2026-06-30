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
import package_genesys2_board_repeatability as packager


DEFAULT_SUMMARY = common.CURRENT_ROOT / "official_image_repeatability_summary.json"


def check_file(root: Path, errors: list[str], row: dict[str, Any], label: str) -> None:
    path = common.repo_path(root, str(row.get("path") or ""))
    require(errors, row.get("exists") is True and path.is_file(), f"{label}: file missing")
    if path.is_file():
        require(errors, row.get("sha256") == common.sha256_file(path), f"{label}: sha256 mismatch")


def check_summary(root: Path, path: Path) -> list[str]:
    data = common.load_json(path)
    errors: list[str] = []
    status = str(data.get("status") or "")
    require(errors, data.get("schema") == packager.SCHEMA, "schema mismatch")
    require(errors, status == "PASS" or status.startswith("BLOCKED_"), "status must be PASS or BLOCKED")
    boundary = data.get("claim_boundary") if isinstance(data.get("claim_boundary"), dict) else {}
    require(errors, boundary.get("cycle_level_overhead_claimed") is False, "must not claim cycle overhead")
    require(errors, boundary.get("real_malware_validation_claimed") is False, "must not claim real malware")
    p0 = data.get("p0_repeatability") if isinstance(data.get("p0_repeatability"), dict) else {}
    official = data.get("official_image_workload_repeatability") if isinstance(data.get("official_image_workload_repeatability"), dict) else {}
    require(errors, p0.get("status") == "PASS", "P0 repeatability baseline must pass")
    check_file(root, errors, p0.get("summary") or {}, "p0 summary")
    check_file(root, errors, official.get("summary") or {}, "official workload summary")
    check_file(root, errors, (data.get("drop_accounting") or {}).get("summary") or {}, "drop summary")
    if status == "PASS":
        require(errors, boundary.get("official_image_repeatability_claimed") is True, "PASS must claim official-image repeatability")
        require(errors, int(official.get("blocked_sample_count") or 0) == 0, "PASS requires no blocked official workload samples")
    else:
        require(errors, boundary.get("official_image_repeatability_claimed") is False, "BLOCKED must not claim official-image repeatability")
        require(errors, boundary.get("bram_ring_overflow_not_promoted") is True, "BLOCKED must preserve overflow boundary")
        require(errors, bool(data.get("blocked_reason")), "BLOCKED summary must include blocked_reason")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="rvmt-repeatability-check-") as tmp:
        root = Path(tmp)
        p0 = root / "p0.json"
        official = root / "official.json"
        drop = root / "drop.json"
        for path in (p0, official, drop):
            path.write_text("{}", encoding="utf-8")
        summary = root / "summary.json"
        common.write_json(summary, {
            "schema": packager.SCHEMA,
            "status": "BLOCKED_OFFICIAL_WORKLOAD_REPEATABILITY_LIMITED_BY_BRAM_RING_DEPTH",
            "blocked_reason": "ring",
            "p0_repeatability": {"status": "PASS", "summary": common.file_row(p0)},
            "official_image_workload_repeatability": {"blocked_sample_count": 1, "summary": common.file_row(official)},
            "drop_accounting": {"summary": common.file_row(drop)},
            "claim_boundary": {
                "official_image_repeatability_claimed": False,
                "bram_ring_overflow_not_promoted": True,
                "cycle_level_overhead_claimed": False,
                "real_malware_validation_claimed": False,
            },
        })
        errors = check_summary(root, summary)
    if errors:
        print("[FAIL] repeatability checker fixture failed", file=sys.stderr)
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("[PASS] official-image repeatability checker self-test")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Check board repeatability/drop-wrap evidence for the official-image plan.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    path = args.summary if args.summary.is_absolute() else root / args.summary
    if not path.is_file():
        print(f"[FAIL] repeatability summary missing: {path}", file=sys.stderr)
        return 1
    errors = check_summary(root, path)
    if errors:
        print("[FAIL] repeatability summary is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] repeatability summary accepted: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
