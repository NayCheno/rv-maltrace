from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
STATUS = "SYNTHETIC_ARG_MEM_GUARDRAILS_PASS_SIDE_CHANNEL_CLOSURE_HARDWARE_POINTER_DEFERRED"
DEFAULT_EVIDENCE_ROOT = Path("docs/07-evaluation-evidence/evidence") / RUN_ID
DEFAULT_SIM_RESULTS = Path("docs/07-evaluation-evidence/reports/sim_results.md")
DEFAULT_TRACE_PROFILES = Path("src/rv_maltrace/trace_profiles.py")
DEFAULT_TRACE_PKG = Path("rtl/trace/trace_pkg.sv")
DEFAULT_TRACE_TOP = Path("rtl/trace/trace_top.sv")
DEFAULT_BOARD_MINIMAL_TOP = Path("rtl/trace/trace_board_minimal_top.sv")
DEFAULT_ROUTES = Path("experiments/linux_behavior/semantic_enrichment_routes.json")
DEFAULT_STRATEGY = Path("experiments/linux_behavior/semantic_enrichment_strategy.json")
DEFAULT_SIDE_CHANNEL = DEFAULT_EVIDENCE_ROOT / "board_syscall_side_channel_smoke.json"
NON_CLAIMS = [
    "no 35T hardware user-pointer snapshot PASS claim",
    "no default ARG_MEM enablement claim",
    "no complete syscall argument reconstruction claim",
    "no real malware detection claim",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def repo_path(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def rel(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def parse_sim_rows(markdown: str) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for line in markdown.splitlines():
        if not line.startswith("| `"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 9:
            continue
        name = cells[0].strip("`")
        try:
            arg_mem = int(cells[8])
        except ValueError:
            arg_mem = 0
        rows[name] = {"status": cells[1], "arg_mem": arg_mem, "notes": cells[-1]}
    return rows


def block_for_profile(text: str, profile_name: str) -> str:
    match = re.search(rf'"{re.escape(profile_name)}"\s*:\s*TraceProfile\((.*?)\n\s*\),', text, re.DOTALL)
    return match.group(1) if match else ""


def no_arg_mem_enabled_in_35t_profiles(text: str) -> bool:
    for profile in ("p0a_syscall_drop", "p0b_trap_drop", "p0c_syscall_trap_drop"):
        block = block_for_profile(text, profile)
        if not block:
            return False
        if "enable_arg_mem=True" in re.sub(r"\s+", "", block):
            return False
    return True


def route_statuses(routes: dict[str, Any]) -> dict[str, str]:
    value = routes.get("routes", [])
    if not isinstance(value, list):
        return {}
    return {str(row.get("id")): str(row.get("status")) for row in value if isinstance(row, dict)}


def build_report(repo_root: Path, evidence_root_arg: Path) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    sim_path = repo_path(repo_root, DEFAULT_SIM_RESULTS)
    profiles_path = repo_path(repo_root, DEFAULT_TRACE_PROFILES)
    trace_pkg_path = repo_path(repo_root, DEFAULT_TRACE_PKG)
    trace_top_path = repo_path(repo_root, DEFAULT_TRACE_TOP)
    board_top_path = repo_path(repo_root, DEFAULT_BOARD_MINIMAL_TOP)
    routes_path = repo_path(repo_root, DEFAULT_ROUTES)
    strategy_path = repo_path(repo_root, DEFAULT_STRATEGY)
    side_channel_path = evidence_root / "board_syscall_side_channel_smoke.json"

    sim_rows = parse_sim_rows(sim_path.read_text(encoding="utf-8"))
    profiles = profiles_path.read_text(encoding="utf-8")
    trace_pkg = trace_pkg_path.read_text(encoding="utf-8")
    trace_top = trace_top_path.read_text(encoding="utf-8")
    board_top = board_top_path.read_text(encoding="utf-8")
    routes = load_json(routes_path)
    strategy = load_json(strategy_path)
    side_channel = load_json(side_channel_path)
    route_states = route_statuses(routes)
    p2_block = block_for_profile(profiles, "p2_pointer_snapshot")
    p2_compact = re.sub(r"\s+", "", p2_block)

    strict_follow_up = side_channel.get("strict_validation_follow_up", {})
    checks = {
        "sim_pointer_string_pass": sim_rows.get("pointer_string", {}).get("status") == "PASS"
        and sim_rows.get("pointer_string", {}).get("arg_mem", 0) > 0,
        "sim_pointer_guardrails_pass": sim_rows.get("pointer_guardrails", {}).get("status") == "PASS"
        and sim_rows.get("pointer_guardrails", {}).get("arg_mem", 0) > 0,
        "rtl_arg_mem_tap_instantiated": "arg_mem_tap" in trace_top and "filtered_arg_mem_valid" in trace_top,
        "trace_mem_default_none": "TRACE_MEM_MODE_DEFAULT = TRACE_MEM_MODE_NONE" in trace_pkg,
        "board_minimal_mem_mode_none": "trace_mem_mode_i(TRACE_MEM_MODE_NONE)" in board_top,
        "p2_profile_gated_but_disabled": "enable_arg_mem=False" in p2_compact and 'arg_mem_policy="gated"' in p2_compact,
        "small_capacity_35t_profiles_arg_mem_disabled": no_arg_mem_enabled_in_35t_profiles(profiles),
        "routes_remain_deferred": routes.get("status") == "DEFERRED_POST_FPGA"
        and routes.get("current_trace_mem_mode") == "TRACE_MEM_MODE_NONE"
        and route_states.get("selective_memory_snapshot") == "DEFERRED_POST_FPGA",
        "strategy_keeps_pointer_snapshot_optional": strategy.get("current_mvp_policy") == "NO_EBPF_NO_KERNEL_HELPER_NO_MEMORY_SNAPSHOT",
        "side_channel_semantic_closure_present": side_channel.get("status") == "STRICT_BOARD_VALIDATION_PASS_AFTER_SIDE_CHANNEL_BOOT"
        and strict_follow_up.get("fd_path_flow") == "PASS"
        and strict_follow_up.get("process_tree") == "PASS",
    }
    status = STATUS if all(checks.values()) else "FAIL"
    return {
        "schema": "rvmt.35t.pointer_semantics_preflight.v1",
        "run_id": RUN_ID,
        "generated_utc": utc_now(),
        "status": status,
        "checks": checks,
        "evidence": {
            "sim_results": rel(sim_path, repo_root),
            "trace_profiles": rel(profiles_path, repo_root),
            "trace_pkg": rel(trace_pkg_path, repo_root),
            "trace_top": rel(trace_top_path, repo_root),
            "board_minimal_top": rel(board_top_path, repo_root),
            "semantic_routes": rel(routes_path, repo_root),
            "semantic_strategy": rel(strategy_path, repo_root),
            "side_channel": rel(side_channel_path, repo_root),
        },
        "synthetic_arg_mem_tests": {
            "pointer_string": sim_rows.get("pointer_string"),
            "pointer_guardrails": sim_rows.get("pointer_guardrails"),
        },
        "current_35t_pointer_semantics": {
            "hardware_user_pointer_snapshot": "DEFERRED",
            "trace_mem_mode": routes.get("current_trace_mem_mode"),
            "small_capacity_profiles": "ARG_MEM_DISABLED",
            "side_channel_scope": "fd/path and process representative closure only",
        },
        "interpretation": [
            "synthetic ARG_MEM simulation covers pointer string and guardrail behavior",
            "the current 35T small-capacity evidence does not enable hardware user-pointer memory snapshots",
            "board syscall side-channel evidence closes representative fd/path and process-tree semantics without changing the hardware pointer claim",
            "P3 remains bounded until gated selective memory snapshot or trusted helper alignment is implemented and measured",
        ],
        "non_claims": NON_CLAIMS,
        "failures": [key for key, ok in checks.items() if not ok],
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# 35T Pointer Semantics Preflight: {report['run_id']}",
        "",
        f"Status: {report['status']}",
        "",
        "## Checks",
        "",
    ]
    for key, ok in report["checks"].items():
        lines.append(f"- {key}: {'PASS' if ok else 'FAIL'}")
    lines += ["", "## Evidence", ""]
    for key, value in report["evidence"].items():
        lines.append(f"- {key}: `{value}`")
    lines += ["", "## Current 35T Pointer Semantics", ""]
    for key, value in report["current_35t_pointer_semantics"].items():
        lines.append(f"- {key}: {value}")
    lines += ["", "## Interpretation", ""]
    lines.extend(f"- {item}" for item in report["interpretation"])
    lines += ["", "## Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    lines += ["", "## Non-claims", ""]
    lines.extend(f"- {item}" for item in report["non_claims"])
    return "\n".join(lines) + "\n"


def write_outputs(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    (evidence_root / "pointer_semantics_preflight.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (evidence_root / "pointer_semantics_preflight.md").write_text(
        render_markdown(report),
        encoding="utf-8",
        newline="\n",
    )


def write_fixture(root: Path) -> None:
    for path in [
        DEFAULT_SIM_RESULTS,
        DEFAULT_TRACE_PROFILES,
        DEFAULT_TRACE_PKG,
        DEFAULT_TRACE_TOP,
        DEFAULT_BOARD_MINIMAL_TOP,
        DEFAULT_ROUTES,
        DEFAULT_STRATEGY,
        DEFAULT_SIDE_CHANNEL,
    ]:
        (root / path).parent.mkdir(parents=True, exist_ok=True)
    (root / DEFAULT_SIM_RESULTS).write_text(
        "| Test | Status | Events | Retire | Branch | Jump | Syscall Entry | Syscall Ret | Arg Mem | Trap | Priv | Drop | Notes |\n"
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |\n"
        "| `pointer_string` | PASS | 13 | 2 | 0 | 0 | 1 | 1 | 5 | 1 | 3 | 0 | pointer string |\n"
        "| `pointer_guardrails` | PASS | 46 | 6 | 0 | 0 | 5 | 5 | 14 | 5 | 11 | 0 | guardrails |\n",
        encoding="utf-8",
    )
    (root / DEFAULT_TRACE_PROFILES).write_text(
        'TRACE_PROFILES = {\n'
        '    "p2_pointer_snapshot": TraceProfile(\n'
        '        name="p2_pointer_snapshot",\n'
        "        enable_arg_mem=False,\n"
        '        arg_mem_policy="gated",\n'
        "    ),\n"
        '    "p0a_syscall_drop": TraceProfile(\n'
        '        name="p0a_syscall_drop",\n'
        "    ),\n"
        '    "p0b_trap_drop": TraceProfile(\n'
        '        name="p0b_trap_drop",\n'
        "    ),\n"
        '    "p0c_syscall_trap_drop": TraceProfile(\n'
        '        name="p0c_syscall_trap_drop",\n'
        "    ),\n"
        "}\n",
        encoding="utf-8",
    )
    (root / DEFAULT_TRACE_PKG).write_text("TRACE_MEM_MODE_DEFAULT = TRACE_MEM_MODE_NONE\n", encoding="utf-8")
    (root / DEFAULT_TRACE_TOP).write_text("arg_mem_tap filtered_arg_mem_valid\n", encoding="utf-8")
    (root / DEFAULT_BOARD_MINIMAL_TOP).write_text("trace_mem_mode_i(TRACE_MEM_MODE_NONE)\n", encoding="utf-8")
    (root / DEFAULT_ROUTES).write_text(
        json.dumps(
            {
                "status": "DEFERRED_POST_FPGA",
                "current_trace_mem_mode": "TRACE_MEM_MODE_NONE",
                "routes": [{"id": "selective_memory_snapshot", "status": "DEFERRED_POST_FPGA"}],
            }
        ),
        encoding="utf-8",
    )
    (root / DEFAULT_STRATEGY).write_text(
        json.dumps({"current_mvp_policy": "NO_EBPF_NO_KERNEL_HELPER_NO_MEMORY_SNAPSHOT"}),
        encoding="utf-8",
    )
    (root / DEFAULT_SIDE_CHANNEL).write_text(
        json.dumps(
            {
                "status": "STRICT_BOARD_VALIDATION_PASS_AFTER_SIDE_CHANNEL_BOOT",
                "strict_validation_follow_up": {"fd_path_flow": "PASS", "process_tree": "PASS"},
            }
        ),
        encoding="utf-8",
    )


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        report = build_report(root, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != STATUS:
            print("[FAIL] expected complete pointer preflight fixture to pass", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
        write_outputs(report, root / DEFAULT_EVIDENCE_ROOT)
        if not (root / DEFAULT_EVIDENCE_ROOT / "pointer_semantics_preflight.md").exists():
            print("[FAIL] missing markdown output", file=sys.stderr)
            return 1

    regressions = [
        (DEFAULT_SIM_RESULTS, "pointer_string` | FAIL", "sim_pointer_string_pass"),
        (DEFAULT_TRACE_PKG, "TRACE_MEM_MODE_DEFAULT = TRACE_MEM_MODE_RANGE", "trace_mem_default_none"),
        (DEFAULT_BOARD_MINIMAL_TOP, "trace_mem_mode_i(TRACE_MEM_MODE_RANGE)", "board_minimal_mem_mode_none"),
        (DEFAULT_STRATEGY, '{"current_mvp_policy":"HELPER_REQUIRED"}', "strategy_keeps_pointer_snapshot_optional"),
    ]
    for path, replacement, failed_check in regressions:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root)
            target = root / path
            text = target.read_text(encoding="utf-8")
            if path == DEFAULT_SIM_RESULTS:
                text = text.replace("pointer_string` | PASS", replacement)
            else:
                text = replacement
            target.write_text(text, encoding="utf-8")
            report = build_report(root, DEFAULT_EVIDENCE_ROOT)
            if failed_check not in report["failures"]:
                print(f"[FAIL] missed pointer preflight regression: {failed_check}", file=sys.stderr)
                return 1
    print("[PASS] 35T pointer semantics preflight self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check bounded 35T pointer-semantics evidence without overclaiming hardware pointer capture.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    repo_root = args.repo_root.resolve()
    evidence_root = repo_path(repo_root, args.evidence_root).resolve()
    try:
        report = build_report(repo_root, args.evidence_root)
        if not args.no_write:
            write_outputs(report, evidence_root)
    except Exception as exc:
        print(f"check_35t_pointer_semantics_preflight: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T pointer semantics preflight")
    for failure in report["failures"]:
        print(f"failure: {failure}", file=sys.stderr)
    return 0 if report["status"] == STATUS else 1


if __name__ == "__main__":
    raise SystemExit(main())
