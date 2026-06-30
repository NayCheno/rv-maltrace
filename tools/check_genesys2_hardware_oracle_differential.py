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
import run_genesys2_hardware_oracle_differential as runner


DEFAULT_SUMMARY = common.CURRENT_ROOT / "official_image_hardware_oracle_differential_summary.json"


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
    require(errors, boundary.get("qemu_strace_is_validation_oracle_only") is True, "oracle boundary missing")
    require(errors, boundary.get("qemu_or_strace_substitutes_for_hardware_trace") is False, "oracle must not substitute for hardware")
    require(errors, boundary.get("cycle_level_overhead_claimed") is False, "must not claim cycle overhead")
    require(errors, boundary.get("real_malware_validation_claimed") is False, "must not claim real malware")
    hardware = data.get("hardware") if isinstance(data.get("hardware"), dict) else {}
    oracle = data.get("oracle") if isinstance(data.get("oracle"), dict) else {}
    for name in ("p0_summary", "bram_records", "binary"):
        if isinstance(hardware.get(name), dict):
            check_file(root, errors, hardware[name], f"hardware.{name}")
    for name, row in (oracle.get("artifacts") or {}).items():
        if isinstance(row, dict):
            check_file(root, errors, row, f"oracle.{name}")
    if status == "PASS":
        require(errors, boundary.get("hardware_oracle_alignment_claimed") is True, "PASS must claim alignment")
        require(errors, hardware.get("exact_elf_match") is True, "PASS requires exact ELF match")
        require(errors, (data.get("alignment") or {}).get("write_syscall_aligned") is True, "PASS requires write syscall alignment")
    else:
        require(errors, boundary.get("hardware_oracle_alignment_claimed") is False, "BLOCKED must not claim alignment")
        require(errors, bool(data.get("blocked_reason")), "BLOCKED summary must include blocked_reason")
    return errors


def self_test() -> int:
    return runner.self_test()


def main() -> int:
    parser = argparse.ArgumentParser(description="Check same-ELF hardware/QEMU-oracle differential evidence.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    path = args.summary if args.summary.is_absolute() else root / args.summary
    if not path.is_file():
        print(f"[FAIL] hardware/oracle differential summary missing: {path}", file=sys.stderr)
        return 1
    errors = check_summary(root, path)
    if errors:
        print("[FAIL] hardware/oracle differential summary is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] hardware/oracle differential summary accepted: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
