from __future__ import annotations

import argparse
import datetime as dt
import os
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any

from experiment_common import (
    repo_path,
    repo_rel,
    sha256_file,
    write_json,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/host_vivado_check_summary.json")
DEFAULT_LOG = Path("results/evaluation/genesys2-cva6/current/host_vivado_check.log")
SCHEMA = "rvmt.ndss.host_vivado_check.v1"
PASS_STATUS = "PASS_HOST_VIVADO_PREFLIGHT"
BOARD_DEFAULTS = {
    "genesys2": ("xc7k325tffg900-2", "digilentinc.com:genesys2:part0:1.1"),
}


def load_config(root: Path) -> dict[str, Any]:
    pyproject = root / "pyproject.toml"
    if not pyproject.is_file():
        return {}
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    tool = data.get("tool", {}) if isinstance(data, dict) else {}
    config = tool.get("rv-maltrace", {}) if isinstance(tool, dict) else {}
    return config if isinstance(config, dict) else {}


def resolve_path(root: Path, value: Any) -> Path:
    path = Path(str(value))
    return path if path.is_absolute() else root / path


def tcl_braced(value: str) -> str:
    return "{" + value.replace("}", "\\}") + "}"


def as_posix_path(path: Path) -> str:
    return str(path).replace("\\", "/")


def marker_map(output: str) -> dict[str, str]:
    markers: dict[str, str] = {}
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("RVMT_") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        markers[key] = value
    return markers


def vivado_command(config: dict[str, Any], root: Path, vivado_override: Path | None) -> Path:
    if vivado_override is not None:
        return resolve_path(root, vivado_override)
    return resolve_path(root, config.get("vivado", "vivado"))


def board_settings(config: dict[str, Any]) -> tuple[str, str, str]:
    board = str(config.get("board", "genesys2"))
    default_part, default_board = BOARD_DEFAULTS.get(board, ("", ""))
    part = str(config.get("xilinx_part", default_part))
    board_part = str(config.get("xilinx_board", default_board))
    return board, part, board_part


def board_repo_paths(root: Path, config: dict[str, Any]) -> list[Path]:
    paths = config.get("vivado_board_repo_paths", [])
    if not isinstance(paths, list):
        return []
    return [resolve_path(root, value) for value in paths]


def build_script(part: str, board_part: str, repos: list[Path]) -> str:
    repo_line = ""
    if repos:
        repo_line = "set_param board.repoPaths [list " + " ".join(tcl_braced(as_posix_path(path)) for path in repos) + "]"
    return "\n".join(
        [
            f"set rvmt_part {tcl_braced(part)}",
            f"set rvmt_board {tcl_braced(board_part)}",
            "set rvmt_failed 0",
            "puts \"RVMT_VIVADO_VERSION=[version -short]\"",
            repo_line,
            "if {[llength [get_parts -quiet $rvmt_part]] == 0} {",
            "  puts \"RVMT_MISSING_PART=$rvmt_part\"",
            "  set rvmt_failed 1",
            "} else {",
            "  puts \"RVMT_PART_OK=$rvmt_part\"",
            "}",
            "if {[llength [get_board_parts -quiet $rvmt_board]] == 0} {",
            "  puts \"RVMT_MISSING_BOARD=$rvmt_board\"",
            "  set rvmt_failed 1",
            "} else {",
            "  puts \"RVMT_BOARD_OK=$rvmt_board\"",
            "}",
            "if {$rvmt_failed} { exit 12 }",
        ]
    )


def run_preflight(root: Path, args: argparse.Namespace) -> dict[str, Any]:
    config = load_config(root)
    vivado = vivado_command(config, root, args.vivado)
    board, part, board_part = board_settings(config)
    repos = board_repo_paths(root, config)
    log = repo_path(root, args.log)

    common: dict[str, Any] = {
        "schema": SCHEMA,
        "generated_utc": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat(),
        "canonical_evaluation_root": "results/evaluation/genesys2-cva6/current",
        "command": "uv run rvmt ndss:host-vivado-check",
        "vivado": {
            "path": as_posix_path(vivado),
            "exists": vivado.is_file() if vivado.suffix else None,
        },
        "board": board,
        "expected_part": part,
        "expected_board_part": board_part,
        "board_repo_paths": [
            {
                "path": repo_rel(root, path),
                "exists": path.exists(),
            }
            for path in repos
        ],
        "log": repo_rel(root, log),
        "claim_boundary": {
            "host_vivado_preflight_executed": False,
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
            "uv run python tools/check_genesys2_bitstream_artifacts.py --root .",
        ],
    }

    if args.dry_run:
        common["status"] = "DRY_RUN"
        return common
    if not vivado.is_file():
        common["status"] = "BLOCKED_HOST_VIVADO_NOT_FOUND"
        common["blocked_reason"] = f"Vivado executable not found: {vivado}"
        return common
    if not part or not board_part:
        common["status"] = "BLOCKED_HOST_VIVADO_CONFIG_INCOMPLETE"
        common["blocked_reason"] = "Missing Xilinx part or board part setting"
        return common

    script = build_script(part, board_part, repos)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".tcl", delete=False) as handle:
        handle.write(script)
        tcl_path = Path(handle.name)
    cmd = [str(vivado), "-mode", "batch", "-nojournal", "-nolog", "-notrace", "-source", str(tcl_path)]
    env = os.environ.copy()
    env["PATH"] = os.pathsep.join([str(vivado.parent), env.get("PATH", "")])
    try:
        completed = subprocess.run(
            cmd,
            cwd=str(root),
            env=env,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=args.timeout_sec,
        )
    except subprocess.TimeoutExpired as exc:
        parts = [f"Vivado preflight timed out after {args.timeout_sec} seconds."]
        if exc.stdout:
            parts.append(str(exc.stdout))
        if exc.stderr:
            parts.append(str(exc.stderr))
        output = "\n".join(parts) + "\n"
        completed = None
    except OSError as exc:
        output = f"failed to start Vivado: {exc}\n"
        completed = None
    finally:
        try:
            tcl_path.unlink()
        except OSError:
            pass

    output = output if completed is None else "\n".join(part for part in (completed.stdout, completed.stderr) if part)
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text(output, encoding="utf-8", newline="\n")
    markers = marker_map(output)
    status = PASS_STATUS
    blocked_reason = None
    returncode = None if completed is None else completed.returncode
    if completed is None:
        status = "BLOCKED_HOST_VIVADO_UNAVAILABLE"
        blocked_reason = output.strip()
    elif completed.returncode != 0:
        status = "FAIL_HOST_VIVADO_PREFLIGHT_FAILED"
        blocked_reason = f"Vivado exited {completed.returncode}"
    if markers.get("RVMT_PART_OK") != part or markers.get("RVMT_BOARD_OK") != board_part:
        if status == PASS_STATUS:
            status = "FAIL_HOST_VIVADO_PREFLIGHT_FAILED"
            blocked_reason = "Vivado did not report the expected part and board markers"

    row = {
        **common,
        "status": status,
        "blocked_reason": blocked_reason,
        "returncode": returncode,
        "vivado_version": markers.get("RVMT_VIVADO_VERSION"),
        "markers": markers,
        "log_sha256": sha256_file(log),
        "log_size_bytes": log.stat().st_size,
    }
    row["claim_boundary"]["host_vivado_preflight_executed"] = completed is not None
    return row


def self_test() -> int:
    output = "RVMT_VIVADO_VERSION=2025.2\nRVMT_PART_OK=xc7k325tffg900-2\nRVMT_BOARD_OK=digilentinc.com:genesys2:part0:1.1\n"
    markers = marker_map(output)
    if markers.get("RVMT_VIVADO_VERSION") != "2025.2":
        print("[FAIL] Vivado marker parser missed version", file=sys.stderr)
        return 1
    script = build_script("part", "board", [Path("vendor/vivado-boards/new/board_files")])
    for token in ("get_parts", "get_board_parts", "RVMT_PART_OK", "RVMT_BOARD_OK"):
        if token not in script:
            print(f"[FAIL] Vivado script missing token {token}", file=sys.stderr)
            return 1
    print("[PASS] NDSS host Vivado preflight runner self-test")
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a host-side Vivado availability/part preflight and write current evidence.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG)
    parser.add_argument("--vivado", type=Path, help="Override Vivado batch executable.")
    parser.add_argument("--timeout-sec", type=int, default=600)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    summary = repo_path(root, args.summary)
    data = run_preflight(root, args)
    if not args.dry_run:
        write_json(summary, data)
    print(f"[{data['status']}] wrote {summary}")
    if data.get("blocked_reason"):
        print(f"[BLOCKED] {data['blocked_reason']}")
    return 0 if data.get("status") == PASS_STATUS else 2


if __name__ == "__main__":
    raise SystemExit(main())
