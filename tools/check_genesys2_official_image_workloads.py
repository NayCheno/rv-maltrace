from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    load_json,
    require,
    sha256_file,
)

import package_genesys2_official_image_workloads as packager


DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/official_image_workload_summary.json")


def check_file(root: Path, errors: list[str], row: dict[str, Any], label: str) -> None:
    path = root / str(row.get("path"))
    require(errors, path.is_file(), f"{label}: file missing")
    if path.is_file():
        require(errors, row.get("sha256") == sha256_file(path), f"{label}: sha256 mismatch")


def check_summary(root: Path, path: Path) -> list[str]:
    data = load_json(path)
    errors: list[str] = []
    require(errors, data.get("schema") == packager.SCHEMA, "schema mismatch")
    status = str(data.get("status") or "")
    require(errors, status == "PASS" or status.startswith("BLOCKED_"), "status must be PASS or truthful BLOCKED")
    require(errors, data.get("busybox", {}).get("sha256"), "busybox sha256 missing")
    boundary = data.get("claim_boundary") if isinstance(data.get("claim_boundary"), dict) else {}
    require(errors, boundary.get("official_image_binary_workload_claimed") is (status == "PASS"), "official workload claim boundary mismatch")
    require(errors, boundary.get("busybox_shell_workloads_not_direct_syscall_fixtures") is True, "direct-syscall substitution boundary missing")
    require(errors, boundary.get("real_malware_validation_claimed") is False, "must not claim real malware")
    require(errors, boundary.get("cycle_level_overhead_claimed") is False, "must not claim cycle overhead")
    for name, row in (data.get("artifacts") or {}).items():
        if isinstance(row, dict):
            check_file(root, errors, row, f"artifact.{name}")
    samples = data.get("samples") if isinstance(data.get("samples"), list) else []
    pass_samples = {row.get("sample_id") for row in samples if isinstance(row, dict) and row.get("status") == "PASS"}
    if status == "PASS":
        require(errors, len(pass_samples) >= 7, "at least seven official workloads must pass")
        require(errors, set(data.get("required_core_samples") or []) <= pass_samples, "core official workloads missing")
    else:
        require(errors, bool(data.get("blocked_reason")), "BLOCKED workload summary must include blocked_reason")
        require(errors, boundary.get("bram_ring_depth_limited_workloads_not_promoted") is True, "blocked core workloads must not be promoted")
    for sample in samples:
        if not isinstance(sample, dict) or sample.get("status") != "PASS":
            continue
        require(errors, int(sample.get("pass_repetitions") or 0) >= int(sample.get("minimum_repetitions") or 1), f"{sample.get('sample_id')}: insufficient reps")
        for rep in sample.get("repetitions", []):
            if not isinstance(rep, dict) or rep.get("status") != "PASS":
                if isinstance(rep, dict) and str(rep.get("status")).startswith("BLOCKED_"):
                    ring = rep.get("bram_ring", {})
                    require(
                        errors,
                        int(ring.get("dropped_count") or 0) > 0 or int(ring.get("wrap_count") or 0) > 0,
                        f"{sample.get('sample_id')}/{rep.get('rep')}: BLOCKED rep missing overflow evidence",
                    )
                continue
            require(errors, rep.get("uart", {}).get("capture_rc") == 0, f"{sample.get('sample_id')}/{rep.get('rep')}: capture rc")
            require(errors, rep.get("uart", {}).get("child_rc") == 0, f"{sample.get('sample_id')}/{rep.get('rep')}: child rc")
            ring = rep.get("bram_ring", {})
            require(errors, int(ring.get("event_count") or 0) > 0, f"{sample.get('sample_id')}/{rep.get('rep')}: empty trace")
            require(errors, int(ring.get("dropped_count") or 0) == 0, f"{sample.get('sample_id')}/{rep.get('rep')}: drop")
            require(errors, int(ring.get("wrap_count") or 0) == 0, f"{sample.get('sample_id')}/{rep.get('rep')}: wrap")
            require(errors, int(rep.get("sequence_gap_count") or 0) == 0, f"{sample.get('sample_id')}/{rep.get('rep')}: sequence gap")
            markers = rep.get("markers", {})
            require(errors, int(markers.get("begin_count") or 0) >= 1 and int(markers.get("end_count") or 0) >= 1, f"{sample.get('sample_id')}/{rep.get('rep')}: markers")
            for art_name, art in (rep.get("artifacts") or {}).items():
                if isinstance(art, dict):
                    check_file(root, errors, art, f"{sample.get('sample_id')}/{rep.get('rep')}.{art_name}")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="rvmt-official-workloads-") as tmp:
        root = Path(tmp)
        old_root = packager.ROOT
        old_defaults = (
            packager.DEFAULT_BUILD_MANIFEST,
            packager.DEFAULT_SDCARD_MANIFEST,
            packager.DEFAULT_BITSTREAM,
            packager.DEFAULT_LTX,
        )
        try:
            packager.ROOT = root
            packager.DEFAULT_BUILD_MANIFEST = root / old_defaults[0]
            packager.DEFAULT_SDCARD_MANIFEST = root / old_defaults[1]
            packager.DEFAULT_BITSTREAM = root / old_defaults[2]
            packager.DEFAULT_LTX = root / old_defaults[3]
            current = root / "results/evaluation/genesys2-cva6/current"
            current.mkdir(parents=True)
            for path in (packager.DEFAULT_BUILD_MANIFEST, packager.DEFAULT_SDCARD_MANIFEST, packager.DEFAULT_BITSTREAM, packager.DEFAULT_LTX):
                full = root / path
                full.parent.mkdir(parents=True, exist_ok=True)
                full.write_text("{}\n", encoding="utf-8")
            raw = root / "raw_uart.log"
            raw.write_text("abc  /bin/notbusy\n" + ("0" * 64) + "  /bin/busybox\n", encoding="utf-8")
            packager.write_json(root / packager.DEFAULT_SDCARD_MANIFEST, {"sections": [{"id": "rootfs_identity_hashes"}], "raw_uart_log": {"path": "raw_uart.log"}})
            run_root = root / "run"
            for sample_id, marker in packager.SAMPLES.items():
                rep = run_root / sample_id / "rep_01"
                rep.mkdir(parents=True)
                (rep / "uart.log").write_text(
                    f"RVMT_OFFICIAL_WORKLOAD_CAPTURE_START sample={sample_id} rep=rep_01\n"
                    f"RVMT_OFFICIAL_WORKLOAD_DONE sample={sample_id} child_pid=2 waited=2 rc=0 raw_status=0\n"
                    f"RVMT_OFFICIAL_WORKLOAD_CAPTURE_DONE sample={sample_id} rep=rep_01 rc=0\n",
                    encoding="utf-8",
                )
                for name in ("capture.csv", "capture.log", "capture.err.log"):
                    (rep / name).write_text(name, encoding="utf-8")
                (rep / "bram_records.jsonl").write_text(
                    json.dumps({"evt": "MARKER", "packed_primary": f"0xb{marker:07x}", "sequence_number": 1}) + "\n"
                    + json.dumps({"evt": "SYSCALL_ENTRY", "sequence_number": 2}) + "\n"
                    + json.dumps({"evt": "MARKER", "packed_primary": f"0xe{marker:07x}", "sequence_number": 3}) + "\n",
                    encoding="utf-8",
                )
                packager.write_json(rep / "bram_summary.json", {"status": "PASS", "bram_ring": {"event_count": 3, "dropped_count": 0, "wrap_count": 0}, "event_counts": {"MARKER": 2}})
            (run_root / "launcher_transfer.log").write_text("transfer", encoding="utf-8")
            summary = root / DEFAULT_SUMMARY
            packager.write_json(summary, packager.package_summary(run_root, 1))
            errors = check_summary(root, summary)
            if errors:
                print("[FAIL] self-test rejected fixture", file=sys.stderr)
                for error in errors:
                    print(f"- {error}", file=sys.stderr)
                return 1
        finally:
            packager.ROOT = old_root
            (
                packager.DEFAULT_BUILD_MANIFEST,
                packager.DEFAULT_SDCARD_MANIFEST,
                packager.DEFAULT_BITSTREAM,
                packager.DEFAULT_LTX,
            ) = old_defaults
    print("[PASS] official image workload checker self-test")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Check official CVA6 SD-image BusyBox/shell workload evidence.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    summary = args.summary if args.summary.is_absolute() else root / args.summary
    if not summary.is_file():
        print(f"[FAIL] official workload summary missing: {summary}", file=sys.stderr)
        return 1
    errors = check_summary(root, summary)
    if errors:
        print("[FAIL] official image workload summary is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] official image workload summary accepted: {summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
