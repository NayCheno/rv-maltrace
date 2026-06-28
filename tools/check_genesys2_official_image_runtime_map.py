from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path
from typing import Any

import official_image_evidence_common as common
import run_genesys2_official_image_runtime_map as runner


DEFAULT_SUMMARY = common.CURRENT_ROOT / "official_image_runtime_map_summary.json"


def require(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def check_file(root: Path, errors: list[str], row: dict[str, Any], label: str) -> None:
    path = common.repo_path(root, str(row.get("path") or ""))
    require(errors, row.get("exists") is True and path.is_file(), f"{label}: file missing")
    if path.is_file():
        require(errors, row.get("sha256") == common.sha256_file(path), f"{label}: sha256 mismatch")


def check_summary(root: Path, path: Path) -> list[str]:
    data = common.load_json(path)
    errors: list[str] = []
    status = str(data.get("status") or "")
    require(errors, data.get("schema") == runner.SCHEMA, "schema mismatch")
    require(errors, status == "PASS" or status.startswith("BLOCKED_"), "status must be PASS or BLOCKED")
    boundary = data.get("claim_boundary") if isinstance(data.get("claim_boundary"), dict) else {}
    require(errors, boundary.get("qemu_or_strace_substitution_used") is False, "runtime map must be board-derived")
    require(errors, boundary.get("cycle_level_overhead_claimed") is False, "must not claim cycle overhead")
    require(errors, boundary.get("real_malware_validation_claimed") is False, "must not claim real malware")
    exact = data.get("exact_elf") if isinstance(data.get("exact_elf"), dict) else {}
    require(errors, exact.get("build_manifest"), "exact ELF build manifest missing")
    for name, row in (data.get("artifacts") or {}).items():
        if isinstance(row, dict) and name != "proc_snapshots":
            check_file(root, errors, row, f"artifact.{name}")
    for name, row in ((data.get("artifacts") or {}).get("proc_snapshots") or {}).items():
        if isinstance(row, dict):
            check_file(root, errors, row, f"proc.{name}")
    if status == "PASS":
        require(errors, boundary.get("board_runtime_pc_to_proc_map_attribution_claimed") is True, "PASS must claim runtime PC attribution")
        require(errors, exact.get("hash_match") is True, "PASS requires exact ELF hash match")
        require(errors, int((data.get("bram_ring") or {}).get("dropped_count") or 0) == 0, "PASS requires drop=0")
        require(errors, int((data.get("bram_ring") or {}).get("wrap_count") or 0) == 0, "PASS requires wrap=0")
        require(errors, len(data.get("pc_attributions") or []) > 0, "PASS requires PC attributions")
    else:
        require(errors, boundary.get("board_runtime_pc_to_proc_map_attribution_claimed") is False, "BLOCKED must not claim runtime attribution")
        require(errors, bool(data.get("blocked_reason")), "BLOCKED summary must include blocked_reason")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="rvmt-runtime-map-check-") as tmp:
        root = Path(tmp)
        old_root = common.ROOT
        try:
            common.ROOT = root
            summary = root / "summary.json"
            run_root = root / "run"
            run_root.mkdir()
            for name in ("uart.log", "capture.csv", "capture.log", "capture.err.log", "bram_records.jsonl", "bram_summary.json", "runtime_map_transfer.log"):
                (run_root / name).write_text(name, encoding="utf-8")
            proc = run_root / "proc.txt"
            proc.write_text("maps\n", encoding="utf-8")
            common.write_json(summary, {
                "schema": runner.SCHEMA,
                "status": "PASS",
                "exact_elf": {"build_manifest": {"path": "manifest"}, "hash_match": True},
                "bram_ring": {"event_count": 1, "dropped_count": 0, "wrap_count": 0},
                "pc_attributions": [{"pc": "0x100"}],
                "artifacts": {
                    "uart_log": common.file_row(run_root / "uart.log"),
                    "capture_csv": common.file_row(run_root / "capture.csv"),
                    "capture_log": common.file_row(run_root / "capture.log"),
                    "capture_err_log": common.file_row(run_root / "capture.err.log"),
                    "bram_records": common.file_row(run_root / "bram_records.jsonl"),
                    "bram_summary": common.file_row(run_root / "bram_summary.json"),
                    "transfer_log": common.file_row(run_root / "runtime_map_transfer.log"),
                    "proc_snapshots": {"maps": common.file_row(proc)},
                },
                "claim_boundary": {
                    "board_runtime_pc_to_proc_map_attribution_claimed": True,
                    "qemu_or_strace_substitution_used": False,
                    "cycle_level_overhead_claimed": False,
                    "real_malware_validation_claimed": False,
                },
            })
            errors = check_summary(root, summary)
        finally:
            common.ROOT = old_root
    if errors:
        print("[FAIL] runtime-map checker fixture failed", file=sys.stderr)
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("[PASS] official-image runtime-map checker self-test")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Check official-image runtime map attribution evidence.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    path = args.summary if args.summary.is_absolute() else root / args.summary
    if not path.is_file():
        print(f"[FAIL] official-image runtime-map summary missing: {path}", file=sys.stderr)
        return 1
    errors = check_summary(root, path)
    if errors:
        print("[FAIL] official-image runtime-map summary is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] official-image runtime-map summary accepted: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
