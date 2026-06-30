from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    load_json,
    repo_path,
    repo_rel,
    require,
    sha256_file,
    write_json,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOG = Path("results/board/genesys2_trace_validation/20260624-live-kernel-config-export/uart.log")
DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/live_kernel_config_export_summary.json")
DEFAULT_CONFIG = Path("results/evaluation/genesys2-cva6/current/live_kernel_config.txt")
SCHEMA = "rvmt.genesys2.live_kernel_config_export.v1"
PASS_STATUS = "PASS_LIVE_KERNEL_CONFIG_EXPORTED"
BLOCKED_MISSING_STATUS = "BLOCKED_LIVE_KERNEL_CONFIG_UNAVAILABLE"
BLOCKED_OPTIONS_STATUS = "BLOCKED_LIVE_KERNEL_CONFIG_COUNTER_OPTIONS_MISSING"
FAIL_INCOMPLETE_STATUS = "FAIL_INCOMPLETE_UART_CAPTURE"
ACCEPTED_STATUSES = {PASS_STATUS, BLOCKED_MISSING_STATUS, BLOCKED_OPTIONS_STATUS}
REQUIRED_OPTIONS = {
    "CONFIG_PERF_EVENTS": {"y"},
    "CONFIG_IKCONFIG": {"y"},
    "CONFIG_IKCONFIG_PROC": {"y"},
}
PMU_OPTION_GROUP = {
    "CONFIG_RISCV_PMU": {"y", "m"},
    "CONFIG_RISCV_PMU_SBI": {"y", "m"},
    "CONFIG_HW_PERF_EVENTS": {"y", "m"},
}


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8", newline="\n")


def artifact_row(root: Path, path: Path) -> dict[str, Any]:
    return {
        "path": repo_rel(root, path),
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
    }


def parse_config_symbols(text: str) -> dict[str, str]:
    symbols: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        match = re.match(r"^(CONFIG_[A-Za-z0-9_]+)=(.*)$", line)
        if match:
            symbols[match.group(1)] = match.group(2).strip()
            continue
        not_set = re.match(r"^#\s+(CONFIG_[A-Za-z0-9_]+)\s+is not set$", line)
        if not_set:
            symbols[not_set.group(1)] = "not_set"
    return symbols


def option_audit(config_text: str) -> dict[str, Any]:
    symbols = parse_config_symbols(config_text)
    required = {key: symbols.get(key) for key in REQUIRED_OPTIONS}
    missing_required = [
        key for key, allowed in REQUIRED_OPTIONS.items() if symbols.get(key) not in allowed
    ]
    pmu_options = {key: symbols.get(key) for key in PMU_OPTION_GROUP}
    pmu_ok = any(symbols.get(key) in allowed for key, allowed in PMU_OPTION_GROUP.items())
    return {
        "required_options": required,
        "pmu_options": pmu_options,
        "missing_required_options": missing_required,
        "pmu_option_group_satisfied": pmu_ok,
        "satisfies_counter_config": not missing_required and pmu_ok,
    }


def clean_lines(text: str) -> list[str]:
    return [line.strip() for line in text.replace("\r", "").splitlines()]


def parse_export_log(log: Path) -> dict[str, Any]:
    text = log.read_text(encoding="utf-8", errors="replace").replace("\r", "")
    lines = clean_lines(text)
    missing_paths = [
        line.split(maxsplit=1)[1]
        for line in lines
        if line.startswith("RVMT_KERNEL_CONFIG_MISSING ")
    ]
    found_paths = [
        line.split(maxsplit=1)[1]
        for line in lines
        if line.startswith("RVMT_KERNEL_CONFIG_FOUND ")
    ]
    selected_path: str | None = None
    content: list[str] = []
    in_content = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("RVMT_KERNEL_CONFIG_CONTENT_BEGIN "):
            selected_path = line.split(maxsplit=1)[1]
            content = []
            in_content = True
            continue
        if line.startswith("RVMT_KERNEL_CONFIG_CONTENT_END "):
            in_content = False
            continue
        if in_content:
            content.append(raw_line.rstrip("\r"))
    config_text = "\n".join(content).strip() + ("\n" if content else "")
    return {
        "markers": {
            "begin": any(line == "RVMT_LIVE_KERNEL_CONFIG_EXPORT_BEGIN" for line in lines),
            "done": any(line == "RVMT_LIVE_KERNEL_CONFIG_EXPORT_DONE" for line in lines),
        },
        "root_shell": any("uid=0(root)" in line for line in lines),
        "kernel": next((line.split(maxsplit=2)[2] for line in lines if line.startswith("Linux ") and len(line.split()) >= 3), None),
        "missing_paths": sorted(dict.fromkeys(missing_paths)),
        "found_paths": sorted(dict.fromkeys(found_paths)),
        "selected_path": selected_path,
        "config_text": config_text,
        "config_line_count": len(config_text.splitlines()),
    }


def summarize_export(root: Path, log: Path, summary: Path, live_config: Path) -> dict[str, Any]:
    parsed = parse_export_log(log)
    config_text = str(parsed["config_text"])
    audit = option_audit(config_text) if config_text else option_audit("")
    if not parsed["markers"]["begin"] or not parsed["markers"]["done"]:
        status = FAIL_INCOMPLETE_STATUS
        blocked_reason = "UART log is missing live kernel-config export begin/done markers"
    elif not config_text:
        status = BLOCKED_MISSING_STATUS
        blocked_reason = "live board exposes no readable kernel config at /proc/config.gz, /boot/config-$(uname -r), or /lib/modules/$(uname -r)/build/.config"
    elif not audit["satisfies_counter_config"]:
        status = BLOCKED_OPTIONS_STATUS
        blocked_reason = "live kernel config was exported but does not satisfy perf/PMU/IKCONFIG counter-path requirements"
    else:
        status = PASS_STATUS
        blocked_reason = None

    live_config_row: dict[str, Any] | None = None
    if config_text:
        write_text(live_config, config_text)
        live_config_row = artifact_row(root, live_config)
    data: dict[str, Any] = {
        "schema": SCHEMA,
        "status": status,
        "run_log": artifact_row(root, log),
        "live_config": live_config_row,
        "diagnostics": {
            "markers": parsed["markers"],
            "root_shell": parsed["root_shell"],
            "kernel": parsed["kernel"],
            "candidate_paths_missing": parsed["missing_paths"],
            "candidate_paths_found": parsed["found_paths"],
            "selected_config_path": parsed["selected_path"],
            "config_line_count": parsed["config_line_count"],
            "option_audit": audit,
        },
        "claim_boundary": {
            "live_kernel_config_export_claimed": status == PASS_STATUS,
            "source_level_kernel_config_claimed": False,
            "sd_card_image_rebuild_claimed": False,
            "board_cycle_source_claimed": False,
            "cycle_level_overhead_claimed": False,
            "qemu_or_strace_substitution_allowed": False,
        },
        "validation_commands": [
            "uv run rvmt ndss:live-kernel-config-export --port COM7 --baud 115200",
            "uv run python tools/check_genesys2_live_kernel_config_export.py --root .",
            "uv run python tools/check_genesys2_live_kernel_config_export.py --root . --require-pass",
            "uv run rvmt ndss:linux-counter-preflight",
        ],
        "non_claims": [
            "A BLOCKED summary does not create or substitute a live kernel config artifact.",
            "A PASS live kernel config export proves only the readable live config file and required counter options, not a usable board cycle source.",
            "QEMU, strace, source-level defconfigs, and Buildroot defconfigs cannot substitute for this live board export.",
        ],
    }
    if blocked_reason:
        data["blocked_reason"] = blocked_reason
    write_json(summary, data)
    return data


def check_row_hash(errors: list[str], root: Path, row: dict[str, Any], label: str) -> None:
    path_value = row.get("path")
    require(errors, isinstance(path_value, str) and bool(path_value), f"{label}: path missing")
    if not isinstance(path_value, str):
        return
    path = repo_path(root, path_value)
    require(errors, path.is_file(), f"{label}: file missing: {path_value}")
    if path.is_file():
        require(errors, row.get("sha256") == sha256_file(path), f"{label}: sha256 mismatch")
        require(errors, row.get("size_bytes") == path.stat().st_size, f"{label}: size_bytes mismatch")


def validate_summary(root: Path, data: dict[str, Any], *, require_pass: bool = False) -> list[str]:
    errors: list[str] = []
    status = data.get("status")
    require(errors, data.get("schema") == SCHEMA, "schema mismatch")
    if require_pass:
        require(errors, status == PASS_STATUS, f"status must be {PASS_STATUS} under --require-pass, got {status}")
    else:
        require(errors, status in ACCEPTED_STATUSES, f"status is not accepted: {status}")
    run_log = data.get("run_log") if isinstance(data.get("run_log"), dict) else {}
    check_row_hash(errors, root, run_log, "run_log")
    diagnostics = data.get("diagnostics") if isinstance(data.get("diagnostics"), dict) else {}
    markers = diagnostics.get("markers") if isinstance(diagnostics.get("markers"), dict) else {}
    require(errors, markers.get("begin") is True, "begin marker missing")
    require(errors, markers.get("done") is True, "done marker missing")
    require(errors, diagnostics.get("root_shell") is True, "root shell evidence missing")
    audit = diagnostics.get("option_audit") if isinstance(diagnostics.get("option_audit"), dict) else {}
    boundary = data.get("claim_boundary") if isinstance(data.get("claim_boundary"), dict) else {}
    require(errors, boundary.get("source_level_kernel_config_claimed") is False, "must not claim source-level config as live export")
    require(errors, boundary.get("sd_card_image_rebuild_claimed") is False, "must not claim SD-card rebuild")
    require(errors, boundary.get("board_cycle_source_claimed") is False, "must not claim board cycle source")
    require(errors, boundary.get("cycle_level_overhead_claimed") is False, "must not claim cycle-level overhead")
    require(errors, boundary.get("qemu_or_strace_substitution_allowed") is False, "must reject QEMU/strace substitution")

    live_config = data.get("live_config")
    if status == PASS_STATUS:
        require(errors, boundary.get("live_kernel_config_export_claimed") is True, "PASS must claim live kernel config export")
        require(errors, isinstance(live_config, dict), "PASS must include live_config artifact row")
        if isinstance(live_config, dict):
            check_row_hash(errors, root, live_config, "live_config")
        require(errors, audit.get("satisfies_counter_config") is True, "PASS requires counter config options")
    elif status == BLOCKED_MISSING_STATUS:
        require(errors, boundary.get("live_kernel_config_export_claimed") is False, "BLOCKED missing must not claim live export")
        require(errors, live_config is None, "BLOCKED missing must not include live_config artifact row")
        require(errors, not diagnostics.get("candidate_paths_found"), "BLOCKED missing cannot have found config paths")
        require(errors, bool(diagnostics.get("candidate_paths_missing")), "BLOCKED missing must record missing candidate paths")
    elif status == BLOCKED_OPTIONS_STATUS:
        require(errors, boundary.get("live_kernel_config_export_claimed") is False, "BLOCKED options must not claim usable live export")
        require(errors, isinstance(live_config, dict), "BLOCKED options must include exported live_config artifact row")
        if isinstance(live_config, dict):
            check_row_hash(errors, root, live_config, "live_config")
        require(errors, audit.get("satisfies_counter_config") is False, "BLOCKED options must fail counter config audit")

    commands = " ".join(str(item) for item in data.get("validation_commands", []))
    for needle in (
        "rvmt ndss:live-kernel-config-export",
        "check_genesys2_live_kernel_config_export.py --root . --require-pass",
        "rvmt ndss:linux-counter-preflight",
    ):
        require(errors, needle in commands, f"validation command missing: {needle}")
    non_claims = " ".join(str(item).lower() for item in data.get("non_claims", []))
    require(errors, "qemu, strace" in non_claims, "non_claims must reject QEMU/strace substitution")
    require(errors, "not a usable board cycle source" in non_claims, "non_claims must preserve cycle-source boundary")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="rvmt-live-kernel-config-") as tmp:
        root = Path(tmp)
        log = root / DEFAULT_LOG
        summary = root / DEFAULT_SUMMARY
        config = root / DEFAULT_CONFIG
        log.parent.mkdir(parents=True, exist_ok=True)
        missing_log = "\n".join(
            [
                "RVMT_LIVE_KERNEL_CONFIG_EXPORT_BEGIN",
                "uid=0(root) gid=0(root)",
                "Linux buildroot 6.19.6 #1 Tue Jun 9 06:02:04 UTC 2026 riscv64 GNU/Linux",
                "RVMT_KERNEL_CONFIG_MISSING /proc/config.gz",
                "RVMT_KERNEL_CONFIG_MISSING /boot/config-6.19.6",
                "RVMT_KERNEL_CONFIG_MISSING /lib/modules/6.19.6/build/.config",
                "RVMT_LIVE_KERNEL_CONFIG_EXPORT_DONE",
            ]
        )
        write_text(log, missing_log + "\n")
        missing = summarize_export(root, log, summary, config)
        if missing.get("status") != BLOCKED_MISSING_STATUS:
            print("[FAIL] expected missing live config to block", file=sys.stderr)
            return 1
        if validate_summary(root, missing):
            print("[FAIL] missing summary did not validate", file=sys.stderr)
            return 1

        good_config = "\n".join(
            [
                "CONFIG_PERF_EVENTS=y",
                "CONFIG_IKCONFIG=y",
                "CONFIG_IKCONFIG_PROC=y",
                "CONFIG_RISCV_PMU_SBI=y",
            ]
        )
        write_text(
            log,
            "\n".join(
                [
                    "RVMT_LIVE_KERNEL_CONFIG_EXPORT_BEGIN",
                    "uid=0(root) gid=0(root)",
                    "RVMT_KERNEL_CONFIG_FOUND /proc/config.gz",
                    "RVMT_KERNEL_CONFIG_CONTENT_BEGIN /proc/config.gz",
                    good_config,
                    "RVMT_KERNEL_CONFIG_CONTENT_END /proc/config.gz",
                    "RVMT_LIVE_KERNEL_CONFIG_EXPORT_DONE",
                ]
            )
            + "\n",
        )
        passed = summarize_export(root, log, summary, config)
        if passed.get("status") != PASS_STATUS:
            print("[FAIL] expected complete live config to pass", file=sys.stderr)
            print(json.dumps(passed, indent=2), file=sys.stderr)
            return 1
        if validate_summary(root, passed, require_pass=True):
            print("[FAIL] pass summary did not validate", file=sys.stderr)
            return 1

        bad_config = "CONFIG_PERF_EVENTS=y\nCONFIG_IKCONFIG=y\nCONFIG_IKCONFIG_PROC=y\n"
        write_text(
            log,
            "\n".join(
                [
                    "RVMT_LIVE_KERNEL_CONFIG_EXPORT_BEGIN",
                    "uid=0(root) gid=0(root)",
                    "RVMT_KERNEL_CONFIG_FOUND /proc/config.gz",
                    "RVMT_KERNEL_CONFIG_CONTENT_BEGIN /proc/config.gz",
                    bad_config,
                    "RVMT_KERNEL_CONFIG_CONTENT_END /proc/config.gz",
                    "RVMT_LIVE_KERNEL_CONFIG_EXPORT_DONE",
                ]
            )
            + "\n",
        )
        blocked_options = summarize_export(root, log, summary, config)
        if blocked_options.get("status") != BLOCKED_OPTIONS_STATUS:
            print("[FAIL] expected missing PMU option to block", file=sys.stderr)
            return 1
        if validate_summary(root, blocked_options):
            print("[FAIL] blocked-options summary did not validate", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 live kernel config export checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check live Genesys2/CVA6 kernel config export evidence.")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--require-pass", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    summary = repo_path(root, args.summary)
    data = load_json(summary)
    errors = validate_summary(root, data, require_pass=args.require_pass)
    if errors:
        print("[FAIL] live kernel config export summary is not acceptable", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(f"[PASS] live kernel config export accepted: {summary} status={data.get('status')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
