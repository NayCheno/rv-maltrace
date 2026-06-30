from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    file_record,
    load_json,
    repo_path,
    utc_now,
    write_json,
)


SURROGATE_RUN_ID = "35t-surrogate-darthra-p0a-r512-abba-r5-20260524"
DEFAULT_EVIDENCE_ROOT = Path("docs/07-evaluation-evidence/evidence/35t-surrogate-boot-provenance-20260524")
BOARD_ROOT = Path("results/board/artix7_35t_litex")
RESULTS_BASE = Path("results/experiments/35t")
SCHEMA = "rvmt.35t.surrogate_boot_provenance.v1"
PASS_STATUS = "SURROGATE_BOOT_PROVENANCE_PASS"
DEFERRED_STATUS = "SURROGATE_BOOT_PROVENANCE_DEFERRED_RUN_SCOPED_LOG_MISSING"
FAIL_STATUS = "FAIL"
MARKERS = {
    "serialboot_upload_summary": "serialboot upload summary",
    "jumped_to_kernel": "jumped to",
    "linux_version": "Linux version",
    "rvmt_linux_user_pass": "RVMT_LINUX_USER_PASS",
}
SNAPSHOT_FILES = (
    "README.md",
    "surrogate_boot_provenance.json",
    "surrogate_boot_provenance.md",
    "boot_capture_runbook.md",
)



def marker_checks(path: Path) -> dict[str, bool]:
    if not path.is_file():
        return {key: False for key in MARKERS}
    text = path.read_text(encoding="utf-8", errors="replace")
    return {key: needle in text for key, needle in MARKERS.items()}


def boot_log_record(path: Path, repo_root: Path, *, relation: str) -> dict[str, Any]:
    checks = marker_checks(path)
    return {
        "relation": relation,
        "path": rel(path, repo_root),
        "present": path.is_file(),
        "checks": checks,
        "status": "PASS" if path.is_file() and all(checks.values()) else "MISSING_OR_INCOMPLETE",
        "hash": file_record(path, repo_root) if path.is_file() else None,
    }


def recent_session_candidates(repo_root: Path, run_id: str) -> list[dict[str, Any]]:
    root = repo_root / BOARD_ROOT
    if not root.is_dir():
        return []
    rows: list[dict[str, Any]] = []
    for path in sorted(root.glob("*/06_linux_boot/uart_linux_boot.log")):
        if run_id in path.as_posix():
            continue
        record = boot_log_record(path, repo_root, relation="session_candidate_not_run_scoped")
        if record["status"] == "PASS":
            rows.append(record)
    return sorted(rows, key=lambda row: row["path"], reverse=True)[:5]


def build_report(repo_root_arg: Path, run_id: str) -> dict[str, Any]:
    repo_root = repo_root_arg.resolve()
    failures: list[str] = []
    run_root = repo_root / RESULTS_BASE / run_id
    run_config = run_root / "run_config.json"
    raw_uart = run_root / "board" / "raw_uart.log"
    run_scoped_boot = repo_root / BOARD_ROOT / run_id / "06_linux_boot" / "uart_linux_boot.log"

    run_artifact_checks = {
        "run_root_exists": run_root.is_dir(),
        "run_config_exists": run_config.is_file(),
        "board_raw_uart_exists": raw_uart.is_file(),
    }
    failures.extend(f"run_artifact:{key}" for key, ok in run_artifact_checks.items() if not ok)

    run_scoped = boot_log_record(run_scoped_boot, repo_root, relation="run_scoped")
    candidates = recent_session_candidates(repo_root, run_id)
    blockers: list[str] = []
    if run_scoped["status"] != "PASS":
        blockers.append("run-scoped surrogate Linux boot log is missing or incomplete")
    if not candidates and run_scoped["status"] != "PASS":
        failures.append("boot_provenance:no_passing_session_boot_candidate")

    status = FAIL_STATUS if failures else PASS_STATUS if run_scoped["status"] == "PASS" else DEFERRED_STATUS
    return {
        "schema": SCHEMA,
        "status": status,
        "generated_utc": utc_now(),
        "run_id": run_id,
        "claim": "surrogate run-scoped Linux boot provenance",
        "run_artifacts": {
            "checks": run_artifact_checks,
            "run_config": file_record(run_config, repo_root) if run_config.is_file() else None,
            "board_raw_uart": file_record(raw_uart, repo_root) if raw_uart.is_file() else None,
        },
        "run_scoped_boot": run_scoped,
        "session_boot_candidates": candidates,
        "blockers": blockers,
        "next_capture_target": rel(run_scoped_boot, repo_root),
        "interpretation": (
            "The surrogate board run artifacts are present. A run-scoped Linux boot log is still deferred "
            "unless run_scoped_boot.status is PASS; session boot candidates are supporting context only."
        ),
        "failures": failures,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# 35T Surrogate Boot Provenance",
        "",
        f"Status: {report['status']}",
        "",
        f"Run: `{report['run_id']}`",
        "",
        "## Run-scoped Boot",
        "",
        f"- Path: `{report['run_scoped_boot']['path']}`",
        f"- Status: {report['run_scoped_boot']['status']}",
        "",
        "## Session Candidates",
        "",
    ]
    for row in report["session_boot_candidates"]:
        lines.append(f"- `{row['path']}`: {row['status']}")
    if not report["session_boot_candidates"]:
        lines.append("- none")
    lines += ["", "## Blockers", ""]
    lines.extend(f"- {item}" for item in report["blockers"] or ["none"])
    lines += ["", "## Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    return "\n".join(lines) + "\n"


def render_runbook(report: dict[str, Any]) -> str:
    return (
        "# Surrogate Boot Capture Runbook\n\n"
        "Capture a run-scoped Linux boot log before or with the surrogate board validation run:\n\n"
        "```powershell\n"
        f"# target log: {report['next_capture_target']}\n"
        "# reboot/load the Artix-7 35T Linux image used by the surrogate rootfs\n"
        "# preserve the full UART boot transcript including serialboot summary, kernel jump, Linux version, and RVMT_LINUX_USER_PASS\n"
        "```\n\n"
        "After capture, rerun:\n\n"
        "```powershell\n"
        "uv run python tools/check_35t_surrogate_boot_provenance.py --no-write\n"
        "```\n"
    )


def snapshot_manifest(repo_root: Path, evidence_root: Path) -> dict[str, Any]:
    rows = []
    for name in SNAPSHOT_FILES:
        path = evidence_root / name
        if path.is_file():
            rows.append({"artifact": name, "committed_path": rel(path, repo_root), **file_record(path, repo_root)})
    return {
        "schema": "rvmt.35t.surrogate_boot_provenance_snapshot.v1",
        "status": "PASS",
        "generated_utc": utc_now(),
        "committed_artifacts": rows,
    }


def write_outputs(report: dict[str, Any], repo_root: Path, evidence_root_arg: Path) -> None:
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    evidence_root.mkdir(parents=True, exist_ok=True)
    write_json(evidence_root / "surrogate_boot_provenance.json", report)
    (evidence_root / "surrogate_boot_provenance.md").write_text(render_markdown(report), encoding="utf-8", newline="\n")
    (evidence_root / "boot_capture_runbook.md").write_text(render_runbook(report), encoding="utf-8", newline="\n")
    (evidence_root / "README.md").write_text(
        "# 35T Surrogate Boot Provenance\n\n"
        f"Status: {report['status']}\n\n"
        "This package records whether the surrogate run has a run-scoped Linux boot log. "
        "A deferred status is an explicit evidence gap, not a surrogate behavior failure.\n",
        encoding="utf-8",
        newline="\n",
    )
    write_json(evidence_root / "evidence_manifest.json", snapshot_manifest(repo_root, evidence_root))


def self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        log = root / "uart_linux_boot.log"
        log.write_text("serialboot upload summary\njumped to 0x40f00000\nLinux version 6.9.0\nRVMT_LINUX_USER_PASS\n", encoding="utf-8")
        if not all(marker_checks(log).values()):
            raise AssertionError("boot marker parser failed")
        missing = root / "missing.log"
        if any(marker_checks(missing).values()):
            raise AssertionError("missing boot log should not pass markers")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--run-id", default=SURROGATE_RUN_ID)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--strict-run-scoped", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        print("SELF_TEST_PASS")
        return 0
    repo_root = args.repo_root.resolve()
    report = build_report(repo_root, args.run_id)
    if not args.no_write:
        write_outputs(report, repo_root, args.evidence_root)
    print(report["status"])
    print(f"evidence_root={rel(repo_path(repo_root, args.evidence_root).resolve(), repo_root)}")
    if report["failures"] or (args.strict_run_scoped and report["status"] != PASS_STATUS):
        for failure in report["failures"] or report["blockers"]:
            print(f"FAIL {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
