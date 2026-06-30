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
    repo_path,
    require,
    sha256_file,
    write_json,
)


DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/host_vivado_check_summary.json")
SCHEMA = "rvmt.ndss.host_vivado_check.v1"
PASS_STATUS = "PASS_HOST_VIVADO_PREFLIGHT"


def check_manifest(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    require(errors, data.get("schema") == SCHEMA, f"schema must be {SCHEMA}")
    require(errors, data.get("status") == PASS_STATUS, f"status must be {PASS_STATUS}")
    require(errors, data.get("command") == "uv run rvmt ndss:host-vivado-check", "command must record rvmt host Vivado entrypoint")
    require(errors, data.get("returncode") == 0, "returncode must be 0")
    require(errors, data.get("expected_part") == "xc7k325tffg900-2", "expected Genesys2 part mismatch")
    require(errors, data.get("expected_board_part") == "digilentinc.com:genesys2:part0:1.1", "expected Genesys2 board part mismatch")

    vivado = as_dict(data.get("vivado"))
    require(errors, isinstance(vivado.get("path"), str) and bool(vivado.get("path")), "vivado.path missing")
    require(errors, vivado.get("exists") is True, "vivado executable existence must be recorded true")
    markers = as_dict(data.get("markers"))
    require(errors, markers.get("RVMT_PART_OK") == data.get("expected_part"), "Vivado part marker missing or wrong")
    require(errors, markers.get("RVMT_BOARD_OK") == data.get("expected_board_part"), "Vivado board marker missing or wrong")
    require(errors, isinstance(data.get("vivado_version"), str) and bool(data.get("vivado_version")), "vivado_version missing")

    repos = as_list(data.get("board_repo_paths"))
    require(errors, bool(repos), "board_repo_paths missing")
    for index, row in enumerate(repos):
        repo = as_dict(row)
        path_value = repo.get("path")
        require(errors, isinstance(path_value, str) and bool(path_value), f"board repo path {index} missing")
        if isinstance(path_value, str) and path_value:
            require(errors, repo_path(root, path_value).exists(), f"board repo path missing: {path_value}")
            require(errors, repo.get("exists") is True, f"board repo path exists flag false: {path_value}")

    log_value = data.get("log")
    require(errors, isinstance(log_value, str) and bool(log_value), "log path missing")
    if isinstance(log_value, str) and log_value:
        log = repo_path(root, log_value)
        require(errors, log.is_file(), f"Vivado check log missing: {log_value}")
        if log.is_file():
            require(errors, data.get("log_sha256") == sha256_file(log), "log_sha256 mismatch")
            require(errors, int(data.get("log_size_bytes") or -1) == log.stat().st_size, "log_size_bytes mismatch")
            text = log.read_text(encoding="utf-8", errors="replace")
            require(errors, "RVMT_PART_OK=xc7k325tffg900-2" in text, "log missing part marker")
            require(errors, "RVMT_BOARD_OK=digilentinc.com:genesys2:part0:1.1" in text, "log missing board marker")

    boundary = as_dict(data.get("claim_boundary"))
    require(errors, boundary.get("host_vivado_preflight_executed") is True, "host_vivado_preflight_executed boundary missing")
    require(errors, boundary.get("vivado_synthesis_or_implementation_run") is False, "must not claim synthesis/implementation")
    require(errors, boundary.get("bitstream_rebuilt") is False, "must not claim bitstream rebuild")
    require(errors, boundary.get("genesys2_programmed") is False, "must not claim board programming")
    require(errors, boundary.get("board_runtime_evidence_claimed") is False, "must not claim board runtime evidence")
    non_claims = " ".join(str(item).lower() for item in as_list(data.get("non_claims")))
    require(errors, "does not run synthesis" in non_claims, "non_claims must reject synthesis")
    require(errors, "board programming" in non_claims, "non_claims must reject board programming")
    commands = " ".join(str(item) for item in as_list(data.get("validation_commands")))
    require(errors, "rvmt ndss:host-vivado-check" in commands, "validation command missing rvmt host Vivado entrypoint")
    require(errors, "check_ndss_host_vivado_check.py --root ." in commands, "validation command missing checker")
    require(errors, "bitstream:build-trace-marker" in commands, "validation command missing trace-marker rebuild follow-up")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="rvmt-host-vivado-check-") as tmp:
        root = Path(tmp)
        log = root / "results/evaluation/genesys2-cva6/current/host_vivado_check.log"
        log.parent.mkdir(parents=True)
        log.write_text(
            "RVMT_VIVADO_VERSION=2025.2\n"
            "RVMT_PART_OK=xc7k325tffg900-2\n"
            "RVMT_BOARD_OK=digilentinc.com:genesys2:part0:1.1\n",
            encoding="utf-8",
        )
        board_repo = root / "vendor/vivado-boards/new/board_files"
        board_repo.mkdir(parents=True)
        row = {
            "schema": SCHEMA,
            "status": PASS_STATUS,
            "command": "uv run rvmt ndss:host-vivado-check",
            "returncode": 0,
            "vivado": {"path": "D:/Application/vivado/2025.2/Vivado/bin/vivado.bat", "exists": True},
            "vivado_version": "2025.2",
            "board": "genesys2",
            "expected_part": "xc7k325tffg900-2",
            "expected_board_part": "digilentinc.com:genesys2:part0:1.1",
            "board_repo_paths": [{"path": "vendor/vivado-boards/new/board_files", "exists": True}],
            "markers": {
                "RVMT_VIVADO_VERSION": "2025.2",
                "RVMT_PART_OK": "xc7k325tffg900-2",
                "RVMT_BOARD_OK": "digilentinc.com:genesys2:part0:1.1",
            },
            "log": "results/evaluation/genesys2-cva6/current/host_vivado_check.log",
            "log_sha256": sha256_file(log),
            "log_size_bytes": log.stat().st_size,
            "claim_boundary": {
                "host_vivado_preflight_executed": True,
                "vivado_synthesis_or_implementation_run": False,
                "bitstream_rebuilt": False,
                "genesys2_programmed": False,
                "board_runtime_evidence_claimed": False,
            },
            "non_claims": [
                "This host Vivado preflight checks tool availability, device part, and board part only.",
                "It does not run synthesis, implementation, bitstream generation, board programming, or board runtime capture.",
            ],
            "validation_commands": [
                "uv run rvmt ndss:host-vivado-check",
                "uv run python tools/check_ndss_host_vivado_check.py --root .",
                "uv run rvmt bitstream:build-trace-marker",
            ],
        }
        errors = check_manifest(row, root)
        if errors:
            print("[FAIL] good host Vivado fixture rejected", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        row["claim_boundary"]["bitstream_rebuilt"] = True
        if not check_manifest(row, root):
            print("[FAIL] bad host Vivado fixture accepted", file=sys.stderr)
            return 1
    print("[PASS] NDSS host Vivado checker self-test")
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check host-side Vivado preflight evidence.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    summary = repo_path(root, args.summary)
    if not summary.is_file():
        print(f"[FAIL] missing host Vivado summary: {summary}", file=sys.stderr)
        return 1
    try:
        errors = check_manifest(load_json(summary), root)
    except Exception as exc:
        print(f"[FAIL] host Vivado checker error: {exc}", file=sys.stderr)
        return 1
    if errors:
        print("[FAIL] host Vivado summary is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] host Vivado summary accepted: {summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
