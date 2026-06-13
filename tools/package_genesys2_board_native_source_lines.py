from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from ccfa_gate_common import ALL_CCFA_SAMPLES
from check_genesys2_external_closure_intake import EXPECTED_EXTERNAL_SUMMARIES, validate_external_summary
from external_closure_artifacts import (
    ROOT,
    evidence_rows,
    external_record_root,
    load_json,
    repo_path,
    repo_relative,
    sha256_file,
    write_json_artifact,
    write_summary,
    write_text_artifact,
)


RECORD_ID = "board_native_dwarf_source_lines"
DEFAULT_OUT = EXPECTED_EXTERNAL_SUMMARIES[RECORD_ID]["path"]
DEFAULT_DEBUG_READINESS = Path("results/evaluation/genesys2-cva6/current/debug_elf_readiness_summary.json")
DEFAULT_RUN_ROOT = Path("results/board/genesys2_trace_validation/20260613-board-native-dwarf-source-lines")


def as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def row_map(rows: Any) -> dict[str, dict[str, Any]]:
    return {str(row.get("id")): row for row in rows if isinstance(row, dict) and row.get("id")}


def find_decodedline_path(root: Path, readiness_row: dict[str, Any]) -> Path | None:
    explicit = readiness_row.get("readelf_decodedline_path") or readiness_row.get("readelf_debug_line_path")
    if explicit:
        path = repo_path(root, explicit)
        if path.is_file():
            return path
    sections_path = readiness_row.get("readelf_sections_path")
    if sections_path:
        sample_dir = repo_path(root, sections_path).parent
        sample_id = str(readiness_row.get("id"))
        for name in (f"{sample_id}.readelf_decodedline.txt", f"{sample_id}.decodedline.txt", "readelf_decodedline.txt"):
            path = sample_dir / name
            if path.is_file():
                return path
    return None


def maybe_generate_decodedline(root: Path, readiness_row: dict[str, Any], readelf: str) -> Path | None:
    existing = find_decodedline_path(root, readiness_row)
    if existing is not None:
        return existing
    elf_path = repo_path(root, readiness_row.get("debug_elf_path") or "")
    sections_path = repo_path(root, readiness_row.get("readelf_sections_path") or "")
    if not elf_path.is_file() or not sections_path.parent.is_dir():
        return None
    out = sections_path.parent / f"{readiness_row.get('id')}.readelf_decodedline.txt"
    completed = subprocess.run(
        [readelf, "--debug-dump=decodedline", str(elf_path)],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    out.write_text(completed.stdout + ("\n[stderr]\n" + completed.stderr if completed.stderr else ""), encoding="utf-8", newline="\n")
    return out if completed.returncode == 0 and out.stat().st_size > 0 else None


def load_board_rows(root: Path, run_root_arg: Path, board_manifest_arg: Path | None) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    if board_manifest_arg is not None:
        manifest = load_json(repo_path(root, board_manifest_arg))
        rows.update(row_map(manifest.get("samples", [])))
    run_root = repo_path(root, run_root_arg)
    for sample_id in ALL_CCFA_SAMPLES:
        sample_dir = run_root / sample_id
        merged: dict[str, Any] = {"id": sample_id, "sample_dir": repo_relative(root, sample_dir)}
        for candidate in (
            sample_dir / "board_capture_manifest.json",
            sample_dir / "capture_manifest.json",
            sample_dir / "board_capture.json",
        ):
            if candidate.is_file():
                merged.update(load_json(candidate))
                break
        for candidate in (
            sample_dir / "joined_trace_code_map_manifest.json",
            sample_dir / "joined_trace_code_map_summary.json",
            sample_dir / "joined_trace_code_map.json",
            sample_dir / "trace_code_map_join.json",
        ):
            if candidate.is_file():
                joined = load_json(candidate)
                merged["joined_trace_code_map"] = repo_relative(root, candidate)
                merged.update({key: value for key, value in joined.items() if key not in merged or key in {"source_line_rate", "unknown_key_events", "unaccounted_drop"}})
                break
        if len(merged) > 2:
            rows[sample_id] = {**rows.get(sample_id, {}), **merged, "id": sample_id}
    return rows


def package_summary(
    root: Path,
    debug_readiness_arg: Path,
    run_root_arg: Path,
    board_manifest_arg: Path | None,
    generate_decodedline: bool,
    readelf: str,
) -> dict[str, Any]:
    record_root = external_record_root(root, RECORD_ID)
    debug_readiness_path = repo_path(root, debug_readiness_arg)
    debug_readiness = load_json(debug_readiness_path) if debug_readiness_path.is_file() else {}
    readiness_rows = row_map(debug_readiness.get("samples", []))
    board_rows = load_board_rows(root, run_root_arg, board_manifest_arg)
    failures: list[str] = []
    samples: list[dict[str, Any]] = []
    debug_manifest_rows: list[dict[str, Any]] = []
    transcript_parts: list[str] = []
    joined_manifest_rows: list[dict[str, Any]] = []
    capture_manifest_rows: list[dict[str, Any]] = []

    for sample_id in ALL_CCFA_SAMPLES:
        ready = readiness_rows.get(sample_id, {})
        board = board_rows.get(sample_id, {})
        decodedline = maybe_generate_decodedline(root, ready, readelf) if generate_decodedline else find_decodedline_path(root, ready)
        debug_sha = str(ready.get("debug_elf_sha256") or "")
        captured_sha = str(board.get("captured_elf_sha256") or board.get("debug_elf_sha256") or "")
        source_line_rate = as_float(board.get("source_line_rate"), -1.0)
        unknown_key_events = as_int(board.get("unknown_key_events"), 0)
        unaccounted_drop = as_int(board.get("unaccounted_drop"), 0)
        marker_passed = board.get("marker_window_passed", board.get("marker_windows_passed")) is True
        exact_sha = bool(debug_sha) and debug_sha == captured_sha
        debug_sections_present = ready.get("debug_sections_present") is True and ".debug_line" in list(ready.get("debug_section_names") or [])
        readelf_proven = decodedline is not None and decodedline.is_file() and decodedline.stat().st_size > 0
        source_available = source_line_rate >= 0.95
        if not ready:
            failures.append(f"{sample_id}: missing debug ELF readiness row")
        if not board:
            failures.append(f"{sample_id}: missing board capture/joined manifest")
        if not exact_sha:
            failures.append(f"{sample_id}: captured ELF sha256 does not exactly match debug readiness ELF")
        if not readelf_proven:
            failures.append(f"{sample_id}: missing readelf --debug-dump=decodedline transcript")
        if source_line_rate < 0.95:
            failures.append(f"{sample_id}: source_line_rate {source_line_rate} < 0.95")
        if unknown_key_events != 0:
            failures.append(f"{sample_id}: unknown_key_events {unknown_key_events} != 0")
        if unaccounted_drop != 0:
            failures.append(f"{sample_id}: unaccounted_drop {unaccounted_drop} != 0")
        if not marker_passed:
            failures.append(f"{sample_id}: marker window did not pass")

        sample_row = {
            "id": sample_id,
            "genesys2_cva6_board_claimed": bool(board),
            "captured_elf_sha256": captured_sha,
            "captured_elf_sha256_exact_match": exact_sha,
            "debug_sections_present": debug_sections_present,
            "readelf_debug_line_proven": readelf_proven,
            "source_line_attribution_available": source_available,
            "board_trace_source_line_available": source_available and marker_passed and unaccounted_drop == 0,
            "source_line_rate": source_line_rate,
            "unknown_key_events": unknown_key_events,
            "unaccounted_drop": unaccounted_drop,
            "marker_window_passed": marker_passed,
        }
        samples.append(sample_row)
        debug_manifest_rows.append(
            {
                "id": sample_id,
                "debug_elf_path": ready.get("debug_elf_path"),
                "debug_elf_sha256": debug_sha,
                "debug_sections_present": debug_sections_present,
                "readelf_decodedline_path": repo_relative(root, decodedline) if decodedline else None,
            }
        )
        capture_manifest_rows.append({**board, "id": sample_id})
        joined_manifest_rows.append(
            {
                "id": sample_id,
                "joined_trace_code_map": board.get("joined_trace_code_map"),
                "source_line_rate": source_line_rate,
                "unknown_key_events": unknown_key_events,
                "unaccounted_drop": unaccounted_drop,
                "marker_window_passed": marker_passed,
            }
        )
        if decodedline:
            transcript_parts.append(f"===== {sample_id}: {repo_relative(root, decodedline)} =====\n" + decodedline.read_text(encoding="utf-8", errors="replace"))

    aggregate_rate = min([row["source_line_rate"] for row in samples], default=0.0)
    aggregate_unknown = sum(row["unknown_key_events"] for row in samples)
    aggregate_drop = sum(row["unaccounted_drop"] for row in samples)
    marker_windows_passed = all(row["marker_window_passed"] for row in samples)
    status = "PASS" if not failures else "FAIL"
    artifacts = {
        "debug_elf_manifest": write_json_artifact(root, RECORD_ID, "debug_elf_manifest", {"source": repo_relative(root, debug_readiness_path), "samples": debug_manifest_rows}),
        "readelf_debug_line_transcript": write_text_artifact(
            root,
            RECORD_ID,
            "readelf_debug_line_transcript",
            "\n\n".join(transcript_parts) if transcript_parts else "MISSING readelf --debug-dump=decodedline transcripts",
        ),
        "board_capture_manifest": write_json_artifact(root, RECORD_ID, "board_capture_manifest", {"run_root": repo_relative(root, repo_path(root, run_root_arg)), "samples": capture_manifest_rows}),
        "joined_trace_code_map_manifest": write_json_artifact(root, RECORD_ID, "joined_trace_code_map_manifest", {"samples": joined_manifest_rows}),
    }
    return {
        "schema": "rvmt.genesys2.board_native_source_lines.v1",
        "status": status,
        "evidence_artifacts": evidence_rows(root, artifacts),
        "claim_boundary": {
            "real_malware_validation_claimed": False,
            "board_native_source_line_attribution_claimed": status == "PASS",
            "sidecar_source_lines_substituted": False,
            "captured_elf_sha256_exact_match": status == "PASS",
        },
        "aggregate": {
            "sample_count": len(samples),
            "source_line_rate": aggregate_rate,
            "unknown_key_events": aggregate_unknown,
            "unaccounted_drop": aggregate_drop,
            "marker_windows_passed": marker_windows_passed,
        },
        "samples": samples,
        "failed_attempts": failures,
        "record_root": repo_relative(root, record_root),
        "validation_commands": [
            "uv run python tools/package_genesys2_board_native_source_lines.py --run-root <board-run-root> --board-manifest <manifest>",
            "uv run python tools/check_genesys2_board_native_source_lines.py --root .",
        ],
    }


def write_fixture(root: Path) -> tuple[Path, Path]:
    debug_summary = root / "debug_readiness.json"
    run_root = root / "board_run"
    rows: list[dict[str, Any]] = []
    for index, sample_id in enumerate(ALL_CCFA_SAMPLES, start=1):
        sample_dir = root / "debug" / sample_id
        sample_dir.mkdir(parents=True, exist_ok=True)
        elf = sample_dir / f"{sample_id}.debug.riscv64"
        elf.write_text(f"ELF fixture {sample_id}\n", encoding="utf-8")
        decodedline = sample_dir / f"{sample_id}.readelf_decodedline.txt"
        decodedline.write_text(f"Decoded dump of debug contents of section .debug_line for {sample_id}\n", encoding="utf-8")
        elf_sha = sha256_file(elf)
        rows.append(
            {
                "id": sample_id,
                "debug_elf_path": repo_relative(root, elf),
                "debug_elf_sha256": elf_sha,
                "debug_sections_present": True,
                "debug_section_names": [".debug_info", ".debug_line"],
                "readelf_decodedline_path": repo_relative(root, decodedline),
            }
        )
        board_dir = run_root / sample_id
        board_dir.mkdir(parents=True, exist_ok=True)
        (board_dir / "board_capture_manifest.json").write_text(
            json.dumps(
                {
                    "id": sample_id,
                    "captured_elf_sha256": elf_sha,
                    "capture_path": f"capture_{index}.jsonl",
                    "marker_window_passed": True,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        (board_dir / "joined_trace_code_map_summary.json").write_text(
            json.dumps({"source_line_rate": 0.99, "unknown_key_events": 0, "unaccounted_drop": 0, "marker_window_passed": True}, indent=2) + "\n",
            encoding="utf-8",
        )
    debug_summary.write_text(json.dumps({"samples": rows}, indent=2) + "\n", encoding="utf-8")
    return debug_summary, run_root


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        debug_summary, run_root = write_fixture(root)
        summary = package_summary(root, debug_summary, run_root, None, False, "readelf")
        errors = validate_external_summary(RECORD_ID, summary, root)
        if errors:
            print("[FAIL] board native source-line PASS fixture rejected", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        bad_dir = run_root / ALL_CCFA_SAMPLES[0]
        bad = load_json(bad_dir / "joined_trace_code_map_summary.json")
        bad["source_line_rate"] = 0.5
        (bad_dir / "joined_trace_code_map_summary.json").write_text(json.dumps(bad) + "\n", encoding="utf-8")
        bad_summary = package_summary(root, debug_summary, run_root, None, False, "readelf")
        if not validate_external_summary(RECORD_ID, bad_summary, root):
            print("[FAIL] low source-line-rate fixture accepted", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 board-native source-line packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package board-native DWARF source-line evidence for Genesys2 external closure intake.")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--debug-readiness", type=Path, default=DEFAULT_DEBUG_READINESS)
    parser.add_argument("--run-root", type=Path, default=DEFAULT_RUN_ROOT)
    parser.add_argument("--board-manifest", type=Path)
    parser.add_argument("--generate-readelf-decodedline", action="store_true")
    parser.add_argument("--readelf", default="riscv64-linux-gnu-readelf")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    summary = package_summary(root, args.debug_readiness, args.run_root, args.board_manifest, args.generate_readelf_decodedline, args.readelf)
    out = write_summary(root, args.out, summary)
    errors = validate_external_summary(RECORD_ID, summary, root)
    status = "PASS" if not errors else "FAIL"
    print(f"[{status}] wrote board-native source-line summary to {out}")
    for error in errors:
        print(f"- {error}")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
