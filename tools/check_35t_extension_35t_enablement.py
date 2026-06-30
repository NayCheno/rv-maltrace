from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

from experiment_common import (
    load_json,
    rel,
    repo_path,
    write_json,
)


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
SCHEMA = "rvmt.35t.extension_35t_enablement_preflight.v1"
STATUS = "EXTENSION_35T_ENABLEMENT_PREFLIGHT_PASS_GATING_DEFERRED"
DEFAULT_EXTENSION_PLAN = Path("experiments/linux_behavior/malware_like/extension_plan.json")
DEFAULT_RUNNER = Path("board/artix7_35t/linux/rvmt_exp_runner.c")
DEFAULT_ROOTFS_SCRIPT = Path("docker/litex/build-artix7-linux-images.sh")
DEFAULT_EXPERIMENT = Path("tools/experiment_35t.py")
DEFAULT_TARGET_SMOKE = Path("docs/07-evaluation-evidence/evidence") / RUN_ID / "synthetic_extension_target_smoke.json"
DEFAULT_EVIDENCE_ROOT = Path("docs/07-evaluation-evidence/evidence") / RUN_ID
EXPECTED_CANDIDATE_COUNT = 13
EXPECTED_NON_NETWORK_CANDIDATE_COUNT = 11
OPTIONAL_NETWORK_IDS = ("loopback_network_client", "mirai_c2_loopback_probe")
NON_CLAIMS = [
    "no CVA6 board claim",
    "no real malware detection claim",
    "no mature detector claim",
    "no classifier accuracy claim",
    "no complete semantic reconstruction claim",
    "no expanded 35T coverage claim",
    "no 35T execution or gate pass claim",
]


def candidate_rows(plan: dict[str, Any]) -> list[dict[str, Any]]:
    rows = plan.get("candidates", [])
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def non_network_candidate_ids(candidates: list[dict[str, Any]]) -> list[str]:
    return sorted(str(row.get("id")) for row in candidates if row.get("id") and row.get("network_required") is not True)


def network_candidate_ids(candidates: list[dict[str, Any]]) -> list[str]:
    return sorted(str(row.get("id")) for row in candidates if row.get("id") and row.get("network_required") is True)


def runner_candidate_map(runner_text: str) -> dict[str, dict[str, Any]]:
    pattern = re.compile(
        r'\{\s*"malware_like_synthetic"\s*,\s*"([^"]+)"\s*,\s*"(/usr/bin/[^"]+)"\s*,\s*NULL\s*,\s*([01])\s*\}'
    )
    return {
        match.group(1): {
            "argv0": match.group(2),
            "default_enabled": match.group(3) == "1",
        }
        for match in pattern.finditer(runner_text)
    }


def decode_first_json(stdout: str) -> dict[str, Any]:
    decoder = json.JSONDecoder()
    value, _ = decoder.raw_decode(stdout.lstrip())
    if not isinstance(value, dict):
        raise ValueError("dry-run output did not start with a JSON object")
    return value


def run_experiment_dry_run(repo_root: Path, args: list[str], timeout_seconds: float = 120.0) -> dict[str, Any]:
    command = [
        sys.executable,
        "tools/experiment_35t.py",
        "--stage",
        "board",
        "--dry-run",
        "--trace-records",
        "512",
        "--trace-profile-policy",
        "35t_small_capacity",
        "--runtime-order",
        "abba",
        "--reps",
        "1",
        *args,
    ]
    completed = subprocess.run(
        command,
        cwd=repo_root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout_seconds,
        check=False,
    )
    config: dict[str, Any] = {}
    if completed.returncode == 0:
        config = decode_first_json(completed.stdout)
    return {
        "argv": command,
        "exit_code": completed.returncode,
        "stdout": completed.stdout,
        "stderr_tail": completed.stderr[-2000:],
        "config": config,
    }


def build_report(
    repo_root: Path,
    *,
    extension_plan_arg: Path = DEFAULT_EXTENSION_PLAN,
    runner_arg: Path = DEFAULT_RUNNER,
    rootfs_script_arg: Path = DEFAULT_ROOTFS_SCRIPT,
    experiment_arg: Path = DEFAULT_EXPERIMENT,
    target_smoke_arg: Path = DEFAULT_TARGET_SMOKE,
    dry_run_func: Callable[[Path, list[str]], dict[str, Any]] = run_experiment_dry_run,
) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    extension_plan_path = repo_path(repo_root, extension_plan_arg).resolve()
    runner_path = repo_path(repo_root, runner_arg).resolve()
    rootfs_script_path = repo_path(repo_root, rootfs_script_arg).resolve()
    experiment_path = repo_path(repo_root, experiment_arg).resolve()
    target_smoke_path = repo_path(repo_root, target_smoke_arg).resolve()

    plan = load_json(extension_plan_path)
    candidates = candidate_rows(plan)
    candidate_ids = sorted(str(row.get("id")) for row in candidates if row.get("id"))
    selected_ids = non_network_candidate_ids(candidates)
    network_ids = network_candidate_ids(candidates)
    runner_text = runner_path.read_text(encoding="utf-8")
    rootfs_script = rootfs_script_path.read_text(encoding="utf-8")
    experiment_text = experiment_path.read_text(encoding="utf-8")
    runner_map = runner_candidate_map(runner_text)
    target_smoke = load_json(target_smoke_path) if target_smoke_path.exists() else {}

    explicit_args = ["--include-extension-samples", *[item for sample_id in selected_ids for item in ("--sample", sample_id)]]
    explicit_dry_run = dry_run_func(repo_root, explicit_args)
    default_dry_run = dry_run_func(repo_root, [])
    explicit_config = explicit_dry_run.get("config", {})
    default_config = default_dry_run.get("config", {})
    explicit_stdout = str(explicit_dry_run.get("stdout", ""))
    default_samples = [str(item) for item in default_config.get("samples", [])] if isinstance(default_config, dict) else []
    explicit_samples = [str(item) for item in explicit_config.get("samples", [])] if isinstance(explicit_config, dict) else []

    runner_declared = {candidate_id: runner_map.get(candidate_id) for candidate_id in candidate_ids}
    checks = {
        "plan_schema": plan.get("schema") == "rvmt.synthetic_suite_extension_plan.v1",
        "candidate_count_expected": len(candidate_ids) == EXPECTED_CANDIDATE_COUNT,
        "non_network_candidates_selected": len(selected_ids) == EXPECTED_NON_NETWORK_CANDIDATE_COUNT and not set(selected_ids).intersection(network_ids),
        "network_candidates_remain_optional": network_ids == sorted(OPTIONAL_NETWORK_IDS),
        "plan_default_disabled": plan.get("default_enabled") is False
        and all(row.get("default_enabled") is False for row in candidates),
        "runner_declares_all_candidates": all(candidate_id in runner_map for candidate_id in candidate_ids),
        "runner_candidates_default_disabled": all(
            runner_map.get(candidate_id, {}).get("default_enabled") is False for candidate_id in candidate_ids
        ),
        "runner_base_class_selection_still_default_only": "sample->default_enabled && strcmp(argv[i], sample->sample_class) == 0"
        in runner_text,
        "rootfs_build_compiles_extension_programs": "extension_programs/*.c" in rootfs_script,
        "experiment_supports_explicit_extensions": "--include-extension-samples" in experiment_text,
        "target_smoke_passed": target_smoke.get("status") == "TARGET_COMPILE_SMOKE_PASS_35T_GATING_DEFERRED",
        "default_dry_run_passed": default_dry_run.get("exit_code") == 0,
        "default_dry_run_excludes_extensions": not set(default_samples).intersection(candidate_ids),
        "explicit_dry_run_passed": explicit_dry_run.get("exit_code") == 0,
        "explicit_dry_run_selects_non_network_extensions": set(explicit_samples) == set(selected_ids),
        "explicit_dry_run_network_disabled": explicit_config.get("network") == "disabled" if isinstance(explicit_config, dict) else False,
        "explicit_dry_run_commands_reference_selected_ids": all(sample_id in explicit_stdout for sample_id in selected_ids),
        "no_board_execution_attempted": "--dry-run" in explicit_dry_run.get("argv", [])
        and "--dry-run" in default_dry_run.get("argv", []),
        "no_expanded_35t_claim": True,
    }
    failures = [key for key, ok in checks.items() if not ok]
    status = STATUS if not failures else "FAIL"
    return {
        "schema": SCHEMA,
        "run_id": RUN_ID,
        "status": status,
        "scope": "Artix-7 35T / LiteX / VexRiscv",
        "claim_level": "35T hardware-trace-assisted synthetic malware-like behavior audit prototype",
        "current_condition": (
            "synthetic extension candidates are present in the 35T runner table, default-disabled, compiled by "
            "the Artix-7 rootfs build script, and selectable through explicit experiment dry-run commands; no "
            "extension candidate has been executed on the 35T board or passed the gate"
        ),
        "checks": checks,
        "extension_plan": rel(extension_plan_path, repo_root),
        "runner": rel(runner_path, repo_root),
        "rootfs_build_script": rel(rootfs_script_path, repo_root),
        "experiment_tool": rel(experiment_path, repo_root),
        "target_smoke": rel(target_smoke_path, repo_root),
        "candidate_ids": candidate_ids,
        "selected_non_network_candidate_ids": selected_ids,
        "network_optional_candidate_ids": network_ids,
        "runner_declared_candidates": runner_declared,
        "dry_runs": {
            "default": {
                "argv": default_dry_run.get("argv"),
                "exit_code": default_dry_run.get("exit_code"),
                "samples": default_samples,
                "stderr_tail": default_dry_run.get("stderr_tail"),
            },
            "explicit_non_network_extensions": {
                "argv": explicit_dry_run.get("argv"),
                "exit_code": explicit_dry_run.get("exit_code"),
                "samples": explicit_samples,
                "network": explicit_config.get("network") if isinstance(explicit_config, dict) else None,
                "stderr_tail": explicit_dry_run.get("stderr_tail"),
                "stdout_command_excerpt": "\n".join(
                    line for line in explicit_stdout.splitlines() if line.startswith("+ send:")
                )[-4000:],
            },
        },
        "remaining_work": [
            "build or refresh the 35T rootfs image that includes the extension binaries",
            "run selected extension candidates on the Artix-7 35T board with trace-off/trace-on ordering",
            "analyze the resulting trace artifacts and apply marker, attribution, DROP, capacity, and strong-evidence gates",
            "keep loopback-network extensions disabled unless explicit loopback-only fixtures are selected",
        ],
        "interpretation": [
            "this preflight closes the runner/rootfs/CLI enablement gap for explicit non-network extension candidates",
            "the default 13-sample 35T matrix remains unchanged because extension candidates are default-disabled",
            "this is still not expanded 35T coverage evidence and cannot replace a board gate run",
        ],
        "non_claims": NON_CLAIMS,
        "failures": failures,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# 35T Extension Enablement Preflight: {report['run_id']}",
        "",
        f"Status: {report['status']}",
        "",
        f"Current condition: {report['current_condition']}",
        "",
        "## Checks",
        "",
    ]
    for key, ok in report["checks"].items():
        lines.append(f"- {key}: {'PASS' if ok else 'FAIL'}")
    lines += ["", "## Selected Non-network Candidates", ""]
    lines.extend(f"- `{item}`" for item in report["selected_non_network_candidate_ids"])
    lines += ["", "## Optional Network Candidates", ""]
    lines.extend(f"- `{item}`" for item in report["network_optional_candidate_ids"] or ["none"])
    lines += ["", "## Dry-run Command Excerpt", ""]
    excerpt = report["dry_runs"]["explicit_non_network_extensions"]["stdout_command_excerpt"]
    lines.append("```text")
    lines.append(excerpt or "none")
    lines.append("```")
    lines += ["", "## Remaining Work", ""]
    lines.extend(f"- {item}" for item in report["remaining_work"])
    lines += ["", "## Interpretation", ""]
    lines.extend(f"- {item}" for item in report["interpretation"])
    lines += ["", "## Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    lines += ["", "## Non-claims", ""]
    lines.extend(f"- {item}" for item in report["non_claims"])
    return "\n".join(lines) + "\n"


def write_outputs(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    write_json(evidence_root / "extension_35t_enablement_preflight.json", report)
    (evidence_root / "extension_35t_enablement_preflight.md").write_text(
        render_markdown(report),
        encoding="utf-8",
        newline="\n",
    )


def write_fixture(root: Path) -> None:
    source_root = root / "experiments/linux_behavior/malware_like/extension_programs"
    source_root.mkdir(parents=True, exist_ok=True)
    candidates = []
    candidate_ids = [f"candidate_{index}" for index in range(EXPECTED_NON_NETWORK_CANDIDATE_COUNT)] + list(OPTIONAL_NETWORK_IDS)
    for candidate_id in candidate_ids:
        source = source_root / f"{candidate_id}.c"
        source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
        network_required = candidate_id in OPTIONAL_NETWORK_IDS
        candidates.append(
            {
                "id": candidate_id,
                "status": "IMPLEMENTED_SOURCE_OPTIONAL_LOOPBACK" if network_required else "IMPLEMENTED_SOURCE",
                "source": rel(source, root),
                "default_enabled": False,
                "network_required": network_required,
            }
        )
    write_json(
        root / DEFAULT_EXTENSION_PLAN,
        {
            "schema": "rvmt.synthetic_suite_extension_plan.v1",
            "default_enabled": False,
            "candidates": candidates,
        },
    )
    runner_rows = "\n".join(
        f'    {{"malware_like_synthetic", "{row["id"]}", "/usr/bin/{row["id"]}", NULL, 0}},' for row in candidates
    )
    (root / DEFAULT_RUNNER).parent.mkdir(parents=True, exist_ok=True)
    (root / DEFAULT_RUNNER).write_text(
        "static const sample_spec_t samples[] = {\n"
        + runner_rows
        + "\n};\n"
        + "sample->default_enabled && strcmp(argv[i], sample->sample_class) == 0\n",
        encoding="utf-8",
    )
    (root / DEFAULT_ROOTFS_SCRIPT).parent.mkdir(parents=True, exist_ok=True)
    (root / DEFAULT_ROOTFS_SCRIPT).write_text("for source in extension_programs/*.c; do true; done\n", encoding="utf-8")
    (root / DEFAULT_EXPERIMENT).parent.mkdir(parents=True, exist_ok=True)
    (root / DEFAULT_EXPERIMENT).write_text("--include-extension-samples\n", encoding="utf-8")
    write_json(root / DEFAULT_TARGET_SMOKE, {"status": "TARGET_COMPILE_SMOKE_PASS_35T_GATING_DEFERRED"})


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        plan = load_json(root / DEFAULT_EXTENSION_PLAN)
        candidates = candidate_rows(plan)
        selected = non_network_candidate_ids(candidates)

        def fake_dry_run(_repo_root: Path, args: list[str]) -> dict[str, Any]:
            include_extensions = "--include-extension-samples" in args
            samples = selected if include_extensions else ["hello", "file_scan"]
            stdout = json.dumps({"samples": samples, "network": "disabled"}) + "\n"
            stdout += "+ send: /usr/bin/rvmt_exp_runner 0xf0004000 512 1 abba " + " ".join(samples) + "\n"
            return {"argv": ["fake", "--dry-run", *args], "exit_code": 0, "stdout": stdout, "stderr_tail": "", "config": decode_first_json(stdout)}

        report = build_report(root, dry_run_func=fake_dry_run)
        if report["status"] != STATUS:
            print("[FAIL] expected extension enablement fixture to pass", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
        write_outputs(report, root / DEFAULT_EVIDENCE_ROOT)
        if not (root / DEFAULT_EVIDENCE_ROOT / "extension_35t_enablement_preflight.md").is_file():
            print("[FAIL] missing markdown output", file=sys.stderr)
            return 1
    print("[PASS] 35T extension enablement preflight self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check explicit 35T enablement path for synthetic extension candidates.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--extension-plan", type=Path, default=DEFAULT_EXTENSION_PLAN)
    parser.add_argument("--runner", type=Path, default=DEFAULT_RUNNER)
    parser.add_argument("--rootfs-script", type=Path, default=DEFAULT_ROOTFS_SCRIPT)
    parser.add_argument("--experiment", type=Path, default=DEFAULT_EXPERIMENT)
    parser.add_argument("--target-smoke", type=Path, default=DEFAULT_TARGET_SMOKE)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    repo_root = args.repo_root.resolve()
    try:
        report = build_report(
            repo_root,
            extension_plan_arg=args.extension_plan,
            runner_arg=args.runner,
            rootfs_script_arg=args.rootfs_script,
            experiment_arg=args.experiment,
            target_smoke_arg=args.target_smoke,
        )
        if not args.no_write:
            write_outputs(report, repo_path(repo_root, args.evidence_root))
    except Exception as exc:
        print(f"check_35t_extension_35t_enablement: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T extension enablement preflight")
    for failure in report["failures"]:
        print(f"failure: {failure}", file=sys.stderr)
    return 0 if report["status"] == STATUS else 1


if __name__ == "__main__":
    raise SystemExit(main())
