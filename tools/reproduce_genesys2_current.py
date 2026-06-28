from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


QUICK_COMMANDS = [
    ["tools/check_genesys2_reproducibility_manifest.py", "--root", "{root}"],
    ["tools/check_genesys2_artifact_package.py", "--root", "{root}"],
    ["tools/check_genesys2_raw_artifact_release.py", "--root", "{root}"],
    ["tools/check_genesys2_semantic_provenance.py", "--root", "{root}"],
    ["tools/check_genesys2_local_code_analysis_fixtures.py", "--root", "{root}"],
    ["tools/check_trace_correctness_directed.py", "--root", "{root}"],
    ["tools/check_genesys2_tracer_visibility_baseline.py", "--root", "{root}"],
    ["tools/check_genesys2_cycle_diagnostics.py", "--root", "{root}"],
    ["tools/check_genesys2_official_image_capability_matrix.py", "--root", "{root}"],
    ["tools/check_genesys2_official_image_workloads.py", "--root", "{root}"],
    ["tools/check_genesys2_official_image_runtime_map.py", "--root", "{root}"],
    ["tools/check_genesys2_fork_exec_ownership.py", "--root", "{root}"],
    ["tools/check_genesys2_aslr_pie_probe.py", "--root", "{root}"],
    ["tools/check_genesys2_board_repeatability.py", "--root", "{root}"],
    ["tools/check_genesys2_hardware_oracle_differential.py", "--root", "{root}"],
    ["tools/check_genesys2_jtag_ram_boot_probe.py", "--root", "{root}"],
    ["tools/check_genesys2_artifact_integrity.py", "--root", "{root}"],
]

LOCAL_COMMANDS = [
    *QUICK_COMMANDS,
    ["tools/check_ccfa_case_study_manifest.py", "--root", "{root}"],
    ["tools/check_ccfa_current_quality.py", "--root", "{root}"],
    ["tools/check_genesys2_bitstream_artifacts.py", "--root", "{root}"],
]

FULL_COMMANDS = [
    ["-m", "compileall", "tools", "src/rv_maltrace"],
    ["tools/run_check_suite.py", "--suite", "genesys2-current"],
    ["tools/run_check_suite.py", "--suite", "genesys2-artifacts"],
    ["tools/run_check_suite.py", "--suite", "genesys2-self-test"],
    ["tools/run_check_suite.py", "--suite", "ccfa-gate-self-test"],
]


def expand(command: list[str], root: Path) -> list[str]:
    return [sys.executable, *[str(root) if token == "{root}" else token for token in command]]


def display(command: list[str], root: Path) -> str:
    return "uv run python " + " ".join(str(root) if token == "{root}" else token for token in command)


def commands(mode: str) -> list[list[str]]:
    if mode == "quick":
        return QUICK_COMMANDS
    if mode == "local":
        return LOCAL_COMMANDS
    if mode == "full":
        return FULL_COMMANDS
    raise ValueError(f"unsupported reproduction mode: {mode}")


def run_commands(root: Path, mode: str, dry_run: bool) -> int:
    failed: list[str] = []
    selected = commands(mode)
    for index, command in enumerate(selected, start=1):
        print(f"[RUN {index}/{len(selected)}] {display(command, root)}", flush=True)
        if dry_run:
            continue
        result = subprocess.run(expand(command, root), cwd=root)
        if result.returncode != 0:
            failed.append(" ".join(command))
            print(f"[FAIL] reproduction command exited {result.returncode}", file=sys.stderr, flush=True)
        else:
            print("[PASS] reproduction command", flush=True)
    if failed:
        print("[FAIL] Genesys2/CVA6 current reproduction failed", file=sys.stderr)
        for command in failed:
            print(f"- {command}", file=sys.stderr)
        return 1
    print("[PASS] Genesys2/CVA6 current reproduction command set")
    return 0


def self_test() -> int:
    quick = "\n".join(display(command, Path(".")) for command in commands("quick"))
    local = "\n".join(display(command, Path(".")) for command in commands("local"))
    full = "\n".join(display(command, Path(".")) for command in commands("full"))
    required = [
        "tools/check_genesys2_reproducibility_manifest.py --root .",
        "tools/check_genesys2_artifact_package.py --root .",
        "tools/check_genesys2_raw_artifact_release.py --root .",
        "tools/check_genesys2_semantic_provenance.py --root .",
        "tools/check_genesys2_local_code_analysis_fixtures.py --root .",
        "tools/check_trace_correctness_directed.py --root .",
        "tools/check_genesys2_tracer_visibility_baseline.py --root .",
        "tools/check_genesys2_cycle_diagnostics.py --root .",
        "tools/check_genesys2_official_image_capability_matrix.py --root .",
        "tools/check_genesys2_official_image_workloads.py --root .",
        "tools/check_genesys2_official_image_runtime_map.py --root .",
        "tools/check_genesys2_fork_exec_ownership.py --root .",
        "tools/check_genesys2_aslr_pie_probe.py --root .",
        "tools/check_genesys2_board_repeatability.py --root .",
        "tools/check_genesys2_hardware_oracle_differential.py --root .",
        "tools/check_genesys2_jtag_ram_boot_probe.py --root .",
        "tools/check_genesys2_artifact_integrity.py --root .",
        "tools/check_ccfa_case_study_manifest.py --root .",
        "tools/check_ccfa_current_quality.py --root .",
        "tools/check_genesys2_bitstream_artifacts.py --root .",
        "-m compileall tools src/rv_maltrace",
        "tools/run_check_suite.py --suite genesys2-current",
        "tools/run_check_suite.py --suite genesys2-artifacts",
        "tools/run_check_suite.py --suite genesys2-self-test",
        "tools/run_check_suite.py --suite ccfa-gate-self-test",
    ]
    combined = "\n".join([quick, local, full])
    missing = [item for item in required if item not in combined]
    if missing:
        print("[FAIL] reproduction self-test missing commands", file=sys.stderr)
        for item in missing:
            print(f"- {item}", file=sys.stderr)
        return 1
    if "genesys2-current" in quick:
        print("[FAIL] quick reproduction should avoid the strict external-closure gate", file=sys.stderr)
        return 1
    if "genesys2-artifacts" in quick:
        print("[FAIL] quick reproduction should avoid artifact inventory", file=sys.stderr)
        return 1
    if "check_genesys2_bitstream_artifacts.py" not in local:
        print("[FAIL] local reproduction should include bitstream artifact checks", file=sys.stderr)
        return 1
    print("[PASS] Genesys2/CVA6 reproduction script self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Reproduce the current controlled Genesys2/CVA6 evidence gates from a fresh clone.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--quick", action="store_true", help="Run the lightweight manifest/package checks. This is the default.")
    parser.add_argument("--local", action="store_true", help="Run local CCF-A evidence-package checks without board/Vivado reruns.")
    parser.add_argument("--full", action="store_true", help="Run the strict aggregate suites, including the current external-closure gate.")
    parser.add_argument("--dry-run", action="store_true", help="Print commands without executing them.")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    selected_modes = [name for name, enabled in (("quick", args.quick), ("local", args.local), ("full", args.full)) if enabled]
    if len(selected_modes) > 1:
        print("[FAIL] choose only one of --quick, --local, or --full", file=sys.stderr)
        return 2
    mode = selected_modes[0] if selected_modes else "quick"
    return run_commands(root, mode=mode, dry_run=args.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
