from __future__ import annotations

import argparse
import re
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    load_json,
    repo_rel,
    require,
    sha256_file,
    write_json,
)


DEFAULT_LOG = Path("results/board/genesys2_trace_validation/20260623-cycle-source-diagnostics/uart.log")
DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/cycle_source_diagnostics_summary.json")
SUMMARY_SCHEMA = "rvmt.genesys2.cycle_source_diagnostics.v1"
PERF_RELATED_CONFIG_PREFIXES = (
    "CONFIG_PERF",
    "CONFIG_HW_PERF",
    "CONFIG_HAVE_PERF",
    "CONFIG_GENERIC_PERF",
    "CONFIG_RISCV_PMU",
    "CONFIG_RISCV",
    "CONFIG_PMU",
)


def rel_or_abs(root: Path, value: str) -> Path:
    candidate = Path(value)
    return candidate if candidate.is_absolute() else root / candidate


def artifact_row(root: Path, path: Path) -> dict[str, Any]:
    return {
        "path": repo_rel(root, path),
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
    }


def extract_lines(text: str, pattern: str) -> list[str]:
    regex = re.compile(pattern, re.IGNORECASE)
    return [line.strip() for line in text.splitlines() if regex.search(line)]


def lines_with_prefix(text: str, prefix: str) -> list[str]:
    return [line.strip()[len(prefix) :].strip() for line in text.splitlines() if line.strip().startswith(prefix)]


def parse_config_symbols(text: str) -> dict[str, str]:
    symbols: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        match = re.match(r"^(CONFIG_[A-Za-z0-9_]+)=(.*)$", stripped)
        if match:
            symbols[match.group(1)] = match.group(2).strip()
            continue
        not_set = re.match(r"^#\s+(CONFIG_[A-Za-z0-9_]+)\s+is not set$", stripped)
        if not_set:
            symbols[not_set.group(1)] = "not_set"
    return symbols


def config_enabled(symbols: dict[str, str], name: str) -> bool | None:
    if name not in symbols:
        return None
    return symbols[name] in {"y", "m"}


def parse_diagnostics_log(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace").replace("\r", "")
    uname_match = re.search(r"^Linux\s+\S+\s+(?P<kernel>\S+).*$", text, re.MULTILINE)
    isa_match = re.search(r"^isa\s*:\s*(?P<isa>\S+)", text, re.MULTILINE)
    hart_isa_match = re.search(r"^hart isa\s*:\s*(?P<isa>\S+)", text, re.MULTILINE)
    cpuinfo_isa = (isa_match or hart_isa_match).group("isa") if (isa_match or hart_isa_match) else None
    event_sources_missing = "/sys/bus/event_source/devices: No such file or directory" in text
    event_source_wildcard_only = "RVMT_EVENT_SOURCE /sys/bus/event_source/devices/*" in text
    event_source_lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip().startswith("RVMT_EVENT_SOURCE ") and not line.strip().endswith("devices/*")
    ]
    sbi_lines = extract_lines(text, r"\bSBI\b")
    pmu_lines = extract_lines(text, r"\bPMU\b")
    perf_lines = extract_lines(text, r"\bperf\b")
    illegal_cycle_traps = extract_lines(text, r"cycle_counter_s.*unhandled signal 4")
    config_lines = [
        line.strip()
        for line in text.splitlines()
        if re.match(
            r"^(#\s+)?CONFIG_(PERF|HW_PERF|HAVE_PERF|GENERIC_PERF|RISCV.*PMU|RISCV_PMU|PMU|DEBUG_INFO|KALLSYMS)",
            line.strip(),
        )
    ]
    config_symbols = parse_config_symbols("\n".join(config_lines))
    perf_related_config = {
        key: value
        for key, value in sorted(config_symbols.items())
        if key.startswith(PERF_RELATED_CONFIG_PREFIXES) or "PMU" in key or "PERF" in key
    }
    dtb_pmu_paths = lines_with_prefix(text, "RVMT_DTB_PMU_PATH ")
    dtb_perf_paths = lines_with_prefix(text, "RVMT_DTB_PERF_PATH ")
    dtb_pmu_values = lines_with_prefix(text, "RVMT_DTB_PMU_VALUE ")
    module_paths = lines_with_prefix(text, "RVMT_MODULE_PATH ")
    module_dirs = lines_with_prefix(text, "RVMT_MODULE_DIR ")
    module_dirs_missing = lines_with_prefix(text, "RVMT_MODULE_DIR_MISSING ")
    kernel_config_paths = lines_with_prefix(text, "RVMT_KERNEL_CONFIG_PATH ")
    kernel_config_missing = lines_with_prefix(text, "RVMT_KERNEL_CONFIG_MISSING ")
    perf_events_enabled = config_enabled(config_symbols, "CONFIG_PERF_EVENTS")
    riscv_pmu_sbi_enabled = config_enabled(config_symbols, "CONFIG_RISCV_PMU_SBI")
    riscv_pmu_enabled = config_enabled(config_symbols, "CONFIG_RISCV_PMU")
    hw_perf_events_enabled = config_enabled(config_symbols, "CONFIG_HW_PERF_EVENTS")
    return {
        "markers": {
            "begin": "RVMT_CYCLE_DIAG_BEGIN" in text,
            "done": "RVMT_CYCLE_DIAG_DONE" in text,
        },
        "kernel": uname_match.group("kernel") if uname_match else None,
        "root_shell": "uid=0(root)" in text,
        "cpuinfo_isa": cpuinfo_isa,
        "cpuinfo_has_zicntr": "zicntr" in (cpuinfo_isa or ""),
        "cpuinfo_has_zihpm": "zihpm" in (cpuinfo_isa or ""),
        "perf_event_paranoid_path_exists": "perf_event_paranoid" in text
        and "No such file or directory" not in text
        and "can't open '/proc/sys/kernel/perf_event_paranoid'" not in text,
        "linux_perf_event_sources_observed": bool(event_source_lines) and not event_sources_missing,
        "linux_perf_event_sources_missing": event_sources_missing or event_source_wildcard_only,
        "sbi_lines": sbi_lines,
        "sbi_pmu_extension_observed": any("PMU" in line.upper() for line in sbi_lines),
        "pmu_lines": pmu_lines,
        "perf_lines": perf_lines,
        "config_lines": config_lines,
        "kernel_config_paths": kernel_config_paths,
        "kernel_config_missing_paths": kernel_config_missing,
        "kernel_config_accessible": bool(kernel_config_paths),
        "kernel_config_perf_related": perf_related_config,
        "kernel_perf_events_enabled": perf_events_enabled,
        "kernel_hw_perf_events_enabled": hw_perf_events_enabled,
        "kernel_riscv_pmu_enabled": riscv_pmu_enabled,
        "kernel_riscv_pmu_sbi_enabled": riscv_pmu_sbi_enabled,
        "dtb_pmu_paths": dtb_pmu_paths,
        "dtb_perf_paths": dtb_perf_paths,
        "dtb_pmu_compatible_values": dtb_pmu_values,
        "dtb_pmu_node_observed": bool(dtb_pmu_paths or dtb_perf_paths or dtb_pmu_values),
        "kernel_module_dirs": module_dirs,
        "kernel_module_dirs_missing": module_dirs_missing,
        "kernel_perf_pmu_module_paths": module_paths,
        "previous_user_rdcycle_illegal_traps": illegal_cycle_traps,
    }


def optional_summary_row(root: Path, path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    data = load_json(path)
    return {
        **artifact_row(root, path),
        "schema": data.get("schema"),
        "status": data.get("status"),
    }


def summarize_diagnostics(root: Path, log: Path, summary: Path) -> dict[str, Any]:
    parsed = parse_diagnostics_log(log)
    counter_access = optional_summary_row(root, root / "results/evaluation/genesys2-cva6/current/counter_access_matrix_summary.json")
    cycle_source = optional_summary_row(root, root / "results/evaluation/genesys2-cva6/current/cycle_source_probe_summary.json")
    missing_perf = parsed["linux_perf_event_sources_missing"] and not parsed["sbi_pmu_extension_observed"]
    perf_syscall_unavailable = bool(cycle_source and cycle_source.get("status") == "BLOCKED_BOARD_KERNEL_PERF_CYCLES_UNAVAILABLE")
    if not parsed["markers"]["begin"] or not parsed["markers"]["done"]:
        status = "FAIL_INCOMPLETE_UART_DIAGNOSTIC"
        blocked_reason = "diagnostic UART log is missing begin/done markers"
    elif missing_perf:
        status = "BLOCKED_BOARD_KERNEL_PMU_AND_USER_CYCLE_UNAVAILABLE"
        blocked_reason = (
            "live board exposes zicntr/zihpm in /proc/cpuinfo but has no Linux perf event source, "
            "no observed SBI PMU extension, and prior user rdcycle probes trap as illegal instructions"
        )
    else:
        status = "PASS"
        blocked_reason = None
    enablement_preflight = {
        "kernel_config_accessible": parsed["kernel_config_accessible"],
        "kernel_perf_events_enabled": parsed["kernel_perf_events_enabled"],
        "kernel_hw_perf_events_enabled": parsed["kernel_hw_perf_events_enabled"],
        "kernel_riscv_pmu_enabled": parsed["kernel_riscv_pmu_enabled"],
        "kernel_riscv_pmu_sbi_enabled": parsed["kernel_riscv_pmu_sbi_enabled"],
        "dtb_pmu_node_observed": parsed["dtb_pmu_node_observed"],
        "sbi_pmu_extension_observed": parsed["sbi_pmu_extension_observed"],
        "linux_perf_event_source_observed": parsed["linux_perf_event_sources_observed"],
        "perf_event_open_unavailable_observed": perf_syscall_unavailable,
        "user_rdcycle_illegal_trap_observed": bool(parsed["previous_user_rdcycle_illegal_traps"]),
        "required_for_kernel_perf_cycle_path": [
            "Kernel must expose perf_event_open and /sys/bus/event_source/devices.",
            "Firmware/device tree must expose a RISC-V PMU path, typically through SBI PMU plus a PMU DT node or matching kernel driver.",
            "The board-side cycle-source probe must pass with monotonic-positive PERF_COUNT_HW_CPU_CYCLES rows.",
        ],
        "required_for_user_rdcycle_path": [
            "M-mode firmware must delegate cycle counter access to S-mode when needed.",
            "S-mode kernel policy must enable user cycle CSR access or provide an equivalent controlled export.",
            "The counter-access matrix must pass with monotonic-positive rdcycle rows.",
        ],
    }
    data: dict[str, Any] = {
        "schema": SUMMARY_SCHEMA,
        "status": status,
        "run_log": artifact_row(root, log),
        "diagnostics": parsed,
        "enablement_preflight": enablement_preflight,
        "related_summaries": {
            "counter_access_matrix": counter_access,
            "cycle_source_probe": cycle_source,
        },
        "claim_boundary": {
            "board_cycle_source_claimed": False,
            "cycle_level_overhead_claimed": False,
            "production_runtime_slowdown_claimed": False,
            "board_cpu_declares_zicntr": parsed["cpuinfo_has_zicntr"],
            "board_cpu_declares_zihpm": parsed["cpuinfo_has_zihpm"],
            "sbi_pmu_extension_observed": parsed["sbi_pmu_extension_observed"],
            "linux_perf_event_source_observed": parsed["linux_perf_event_sources_observed"],
            "diagnostic_only": True,
        },
        "non_claims": [
            "This diagnostic does not measure workload overhead and does not claim a usable board cycle source.",
            "Linux/QEMU/perf diagnostics are environment evidence only; they are not hardware trace semantics.",
            "A PASS diagnostic would only mean cycle-source infrastructure was observed, not that trace-on/off overhead was measured.",
        ],
        "next_steps": [
            "Enable OpenSBI or kernel PMU/counter delegation for cycle counters, or add a board-specific SBI/kernel cycle export.",
            "If using kernel perf, enable CONFIG_PERF_EVENTS plus the RISC-V PMU/SBI PMU path and verify a PMU event source appears under /sys/bus/event_source/devices.",
            "If using user rdcycle, enable the M-mode/S-mode counter delegation path and verify rdcycle rows in the counter-access matrix.",
            "Rerun ndss:counter-access-matrix and require tools/check_genesys2_counter_access_matrix.py --require-pass before any cycle claim.",
            "Rerun ndss:cycle-source-probe and require tools/check_genesys2_cycle_source_probe.py --require-pass if using kernel perf cycles.",
        ],
    }
    if blocked_reason:
        data["blocked_reason"] = blocked_reason
    write_json(summary, data)
    return data


def check_artifact(errors: list[str], root: Path, summary: dict[str, Any], name: str) -> Path | None:
    row = summary.get(name) if isinstance(summary.get(name), dict) else {}
    value = row.get("path")
    if not value:
        errors.append(f"artifact missing: {name}")
        return None
    path = rel_or_abs(root, str(value))
    if not path.is_file():
        errors.append(f"artifact file missing: {name}: {value}")
        return None
    require(errors, row.get("sha256") == sha256_file(path), f"artifact sha256 mismatch: {name}")
    return path


def check_summary(root: Path, path: Path) -> list[str]:
    errors: list[str] = []
    data = load_json(path)
    require(errors, data.get("schema") == SUMMARY_SCHEMA, f"schema must be {SUMMARY_SCHEMA}")
    status = str(data.get("status") or "")
    require(errors, status == "PASS" or status.startswith("BLOCKED_"), f"status must be PASS or truthful BLOCKED, got {status}")
    run_log = check_artifact(errors, root, data, "run_log")
    if run_log is not None:
        parsed = parse_diagnostics_log(run_log)
        require(errors, parsed == data.get("diagnostics"), "diagnostics must match run_log parse")
    diagnostics = data.get("diagnostics") if isinstance(data.get("diagnostics"), dict) else {}
    markers = diagnostics.get("markers") if isinstance(diagnostics.get("markers"), dict) else {}
    require(errors, markers.get("begin") is True and markers.get("done") is True, "diagnostic log must include begin/done markers")
    boundary = data.get("claim_boundary") if isinstance(data.get("claim_boundary"), dict) else {}
    preflight = data.get("enablement_preflight") if isinstance(data.get("enablement_preflight"), dict) else {}
    require(errors, boundary.get("board_cycle_source_claimed") is False, "diagnostic must not claim board cycle source")
    require(errors, boundary.get("cycle_level_overhead_claimed") is False, "diagnostic must not claim cycle-level overhead")
    require(errors, boundary.get("production_runtime_slowdown_claimed") is False, "diagnostic must not claim runtime slowdown")
    require(errors, boundary.get("diagnostic_only") is True, "diagnostic_only boundary must be true")
    require(errors, isinstance(preflight.get("required_for_kernel_perf_cycle_path"), list), "preflight must list kernel perf cycle requirements")
    require(errors, isinstance(preflight.get("required_for_user_rdcycle_path"), list), "preflight must list user rdcycle requirements")
    if status.startswith("BLOCKED_"):
        require(errors, bool(data.get("blocked_reason")), "BLOCKED diagnostic must include blocked_reason")
    if diagnostics.get("linux_perf_event_sources_missing") is True:
        require(errors, boundary.get("linux_perf_event_source_observed") is False, "missing perf event source must not be marked observed")
    related = data.get("related_summaries") if isinstance(data.get("related_summaries"), dict) else {}
    for name, row in related.items():
        if row is None:
            continue
        if not isinstance(row, dict):
            errors.append(f"related summary row must be object or null: {name}")
            continue
        value = row.get("path")
        if not value:
            errors.append(f"related summary missing path: {name}")
            continue
        related_path = rel_or_abs(root, str(value))
        if not related_path.is_file():
            errors.append(f"related summary file missing: {name}: {value}")
            continue
        require(errors, row.get("sha256") == sha256_file(related_path), f"related summary sha256 mismatch: {name}")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="rvmt-cycle-diagnostics-") as tmp:
        root = Path(tmp)
        log = root / DEFAULT_LOG
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(
            "RVMT_CYCLE_DIAG_BEGIN\n"
            "Linux buildroot 6.19.6 #1 Tue Jun  9 06:02:04 UTC 2026 riscv64 GNU/Linux\n"
            "uid=0(root) gid=0(root)\n"
            "isa\t\t: rv64imafdc_zicntr_zicsr_zifencei_zihpm\n"
            "RVMT_KERNEL_CONFIG_PATH /proc/config.gz\n"
            "# CONFIG_PERF_EVENTS is not set\n"
            "CONFIG_RISCV_PMU_SBI=y\n"
            "cat: can't open '/proc/sys/kernel/perf_event_paranoid': No such file or directory\n"
            "ls: /sys/bus/event_source/devices: No such file or directory\n"
            "RVMT_DTB_PMU_MISSING /proc/device-tree/pmu/compatible\n"
            "RVMT_MODULE_DIR_MISSING /lib/modules/6.19.6\n"
            "[    0.000000] SBI specification v3.0 detected\n"
            "[    0.000000] SBI TIME extension detected\n"
            "[   98.652443] cycle_counter_s[118]: unhandled signal 4 code 0x1\n"
            "RVMT_CYCLE_DIAG_DONE\n",
            encoding="utf-8",
            newline="\n",
        )
        current = root / "results/evaluation/genesys2-cva6/current"
        current.mkdir(parents=True, exist_ok=True)
        for filename, status in (
            ("counter_access_matrix_summary.json", "BLOCKED_BOARD_CYCLE_COUNTER_UNAVAILABLE_NONCYCLE_TIME_AVAILABLE"),
            ("cycle_source_probe_summary.json", "BLOCKED_BOARD_KERNEL_PERF_CYCLES_UNAVAILABLE"),
        ):
            write_json(current / filename, {"schema": "fixture", "status": status})
        summary = root / DEFAULT_SUMMARY
        data = summarize_diagnostics(root, log, summary)
        if data.get("status") != "BLOCKED_BOARD_KERNEL_PMU_AND_USER_CYCLE_UNAVAILABLE":
            print("[FAIL] cycle diagnostics self-test expected BLOCKED status")
            return 1
        errors = check_summary(root, summary)
        if errors:
            print("[FAIL] cycle diagnostics checker self-test")
            for error in errors:
                print(f"- {error}")
            return 1
    print("[PASS] cycle diagnostics checker self-test")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Check a Genesys2/CVA6 board cycle-source diagnostics summary.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG)
    parser.add_argument("--package", action="store_true", help="Parse --log and write --summary before checking.")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    summary = args.summary if args.summary.is_absolute() else root / args.summary
    log = args.log if args.log.is_absolute() else root / args.log
    if args.package:
        if not log.is_file():
            print(f"[FAIL] cycle diagnostics log missing: {log}")
            return 1
        data = summarize_diagnostics(root, log, summary)
        print(f"[{data['status']}] wrote {summary}")
    if not summary.is_file():
        print(f"[BLOCKED_HOST_GENESYS2_REQUIRED] cycle diagnostics summary missing: {summary}")
        return 0
    errors = check_summary(root, summary)
    if errors:
        print("[FAIL] cycle diagnostics summary is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    data = load_json(summary)
    print(f"[PASS] cycle diagnostics summary accepted: {summary} status={data.get('status')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
