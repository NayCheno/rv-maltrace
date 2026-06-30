from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    load_json,
    repo_rel_from,
    sha256_file,
    write_json,
)

from audit_behavior import audit, load_rule_definitions


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CURRENT_ROOT = Path("results/evaluation/genesys2-cva6/current")
DEFAULT_OUT = DEFAULT_CURRENT_ROOT / "benign_control_summary.json"
DEFAULT_RUN_ROOT = Path("build/benign_control")
DEFAULT_MANIFEST = Path("experiments/linux_behavior/benign/manifest.json")
DEFAULT_RULES = Path("experiments/linux_behavior/behavior_audit_rules.json")
BENIGN_SOURCE = Path("board/artix7_35t/linux/rvmt_benign_workload.c")
BENIGN_BINARY = "rvmt_benign_workload"
NON_NETWORK_SAMPLES = ("hello", "ls", "cat", "cp", "sha256sum")
ALLOWED_BENIGN_RULE_OVERLAP = {
    "ls": {"many_file_scan"},
    "sha256sum": {"direct_syscall_file_access", "obfuscated_syscall_sequence"},
}
TRACE_SYSCALLS = "openat,getdents64,read,write,close,exit_group"


repo_rel = repo_rel_from(ROOT)


def sha256_if_file(path: Path) -> str | None:
    return sha256_file(path) if path.is_file() else None


def samples_by_id(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = manifest.get("samples")
    if not isinstance(rows, list):
        return {}
    return {str(row.get("id")): row for row in rows if isinstance(row, dict) and row.get("id")}


def docker_script(run_root: Path) -> str:
    out = run_root.as_posix()
    binary = f"{out}/{BENIGN_BINARY}"
    lines = [
        "set -euo pipefail",
        f"mkdir -p {out}",
        f"gcc -static -O2 -Wall -Wextra -o {binary} {BENIGN_SOURCE.as_posix()}",
        f"gcc --version | head -n 1 > {out}/gcc.version.txt",
        f"strace --version | head -n 1 > {out}/strace.version.txt",
    ]
    for sample in NON_NETWORK_SAMPLES:
        sample_dir = f"{out}/{sample}"
        lines.extend(
            [
                f"mkdir -p {sample_dir}",
                "set +e",
                f"RVMT_FIXTURE_ROOT=experiments/linux_behavior/benign/fixtures "
                f"strace -qq -s 256 -e trace={TRACE_SYSCALLS} -o {sample_dir}/host.strace.log "
                f"{binary} {sample} > {sample_dir}/stdout.txt 2> {sample_dir}/stderr.txt",
                "rc=$?",
                "set -e",
                f"printf '%s\\n' \"$rc\" > {sample_dir}/returncode.txt",
            ]
        )
    return "\n".join(lines) + "\n"


def run_docker(run_root: Path) -> subprocess.CompletedProcess[str]:
    command = [
        "docker",
        "compose",
        "-f",
        "docker-compose.toolchain.yml",
        "run",
        "--rm",
        "linux-behavior",
        "bash",
        "-lc",
        docker_script(run_root),
    ]
    return subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)


STRACE_RE = re.compile(r"^(?P<name>[A-Za-z0-9_]+)\((?P<args>.*)\)\s+=\s+(?P<ret>.+)$")


def parse_return(value: str) -> str | None:
    value = value.strip()
    if value == "?":
        return None
    match = re.match(r"(-?\d+)", value)
    if not match:
        return None
    return match.group(1)


def parse_strace(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_no, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("+++"):
            continue
        match = STRACE_RE.match(line)
        if not match:
            continue
        name = match.group("name")
        if name == "exit_group":
            continue
        rows.append(
            {
                "seq": len(rows),
                "name": name,
                "return_value": parse_return(match.group("ret")),
                "strace_line": line,
                "strace_line_no": line_no,
                "confidence": "local_linux_strace_control",
            }
        )
    return rows


def make_semantic(sample_id: str, strace_log: Path, rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema": "rvmt.behavior.semantic.v1",
        "source": repo_rel(strace_log),
        "sample_id": sample_id,
        "sample_class": "benign",
        "provenance": "repository benign wrapper under linux-behavior Docker",
        "syscall_sequence": rows,
        "trap_context_transitions": [],
        "non_claims": [
            "This is local Linux benign-control behavior evidence, not Genesys2 board trace evidence.",
            "This is not real-malware validation or malware detection accuracy.",
        ],
    }


def make_graph(sample_id: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    nodes = [
        {"id": f"syscall:{index}", "kind": "syscall", "label": row.get("name"), "seq": index}
        for index, row in enumerate(rows)
    ]
    edges = [
        {"source": f"syscall:{index}", "target": f"syscall:{index + 1}", "kind": "next"}
        for index in range(max(0, len(rows) - 1))
    ]
    return {
        "schema": "rvmt.behavior.graph.v1",
        "sample_id": sample_id,
        "sample_class": "benign",
        "nodes": nodes,
        "edges": edges,
        "real_malware": False,
        "non_claims": [
            "Benign control graph is local Linux behavior evidence, not a Genesys2 board trace claim.",
            "Benign overlap with malware-like rules is tracked separately from false positives.",
        ],
    }


def benign_audit_manifest(sample_id: str) -> dict[str, Any]:
    return {
        "sample_class": "benign",
        "samples": [{"id": sample_id, "class": "benign", "expected_behavior": []}],
    }


def sample_row(
    sample_id: str,
    manifest_row: dict[str, Any],
    sample_dir: Path,
    rules: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    strace_log = sample_dir / "host.strace.log"
    rows = parse_strace(strace_log)
    semantic = make_semantic(sample_id, strace_log, rows)
    graph = make_graph(sample_id, rows)
    audit_result = audit(semantic, graph, rules, benign_audit_manifest(sample_id), sample_id)
    matched = {str(item) for item in audit_result.get("unexpected_matched_behavior", [])}
    allowed = sorted(matched & ALLOWED_BENIGN_RULE_OVERLAP.get(sample_id, set()))
    unexpected = sorted(matched - set(allowed))
    false_positive = bool(unexpected)
    semantic_path = sample_dir / "semantic_events.json"
    graph_path = sample_dir / "behavior_graph.json"
    audit_path = sample_dir / "behavior_audit.json"
    write_json(semantic_path, semantic)
    write_json(graph_path, graph)
    write_json(audit_path, audit_result)
    rc_path = sample_dir / "returncode.txt"
    rc = int(rc_path.read_text(encoding="utf-8").strip()) if rc_path.is_file() else -1
    observed = [str(row.get("name")) for row in rows if row.get("name")]
    expected_syscalls = [str(item) for item in manifest_row.get("expected_syscalls", [])]
    coverage = {name: name in observed for name in expected_syscalls}
    return {
        "sample_id": sample_id,
        "sample_class": "benign",
        "status": "PASS" if rc == 0 and all(coverage.values()) and not false_positive else "FAIL",
        "source": manifest_row.get("source"),
        "command": manifest_row.get("command"),
        "network_required": manifest_row.get("network_required"),
        "default_enabled": manifest_row.get("default_enabled"),
        "expected_syscalls": expected_syscalls,
        "observed_syscalls": observed,
        "expected_syscall_coverage": coverage,
        "expected_behavior": manifest_row.get("expected_behavior", []),
        "returncode": rc,
        "strace_log": repo_rel(strace_log),
        "stdout": repo_rel(sample_dir / "stdout.txt"),
        "stderr": repo_rel(sample_dir / "stderr.txt"),
        "semantic_events": repo_rel(semantic_path),
        "behavior_graph": repo_rel(graph_path),
        "behavior_audit": repo_rel(audit_path),
        "matched_rules": sorted(matched),
        "allowed_benign_rule_overlap": allowed,
        "unexpected_matched_rules": unexpected,
        "false_positive": false_positive,
    }


def package_summary(current_root: Path, run_root: Path, docker_result: subprocess.CompletedProcess[str] | None) -> dict[str, Any]:
    manifest = load_json(ROOT / DEFAULT_MANIFEST)
    rules = load_rule_definitions(ROOT / DEFAULT_RULES)
    manifest_rows = samples_by_id(manifest)
    samples = [sample_row(sample_id, manifest_rows[sample_id], run_root / sample_id, rules) for sample_id in NON_NETWORK_SAMPLES]
    unexpected_count = sum(1 for row in samples if row.get("false_positive") is True)
    status = "PASS"
    if docker_result is not None and docker_result.returncode != 0:
        status = "FAIL"
    if any(row.get("status") != "PASS" for row in samples):
        status = "FAIL"
    if unexpected_count:
        status = "FAIL"
    return {
        "schema": "rvmt.genesys2.benign_control_summary.v1",
        "status": status,
        "canonical_evaluation_root": repo_rel(current_root),
        "run_root": repo_rel(run_root),
        "source_manifest": DEFAULT_MANIFEST.as_posix(),
        "rules": DEFAULT_RULES.as_posix(),
        "wrapper_source": BENIGN_SOURCE.as_posix(),
        "wrapper_binary": repo_rel(run_root / BENIGN_BINARY),
        "wrapper_source_sha256": sha256_if_file(ROOT / BENIGN_SOURCE),
        "wrapper_binary_sha256": sha256_if_file(run_root / BENIGN_BINARY),
        "toolchain": {
            "docker_service": "linux-behavior",
            "compiler": (run_root / "gcc.version.txt").read_text(encoding="utf-8").splitlines()[0].strip()
            if (run_root / "gcc.version.txt").is_file()
            else None,
            "strace": (run_root / "strace.version.txt").read_text(encoding="utf-8").splitlines()[0].strip()
            if (run_root / "strace.version.txt").is_file()
            else None,
        },
        "aggregate": {
            "sample_count": len(samples),
            "non_network_sample_count": sum(1 for row in samples if row.get("network_required") is False),
            "unexpected_false_positive_count": unexpected_count,
            "allowed_overlap_count": sum(len(row.get("allowed_benign_rule_overlap", [])) for row in samples),
            "benign_false_positive_rate": unexpected_count / len(samples) if samples else 1.0,
        },
        "samples": samples,
        "claim_boundary": {
            "local_linux_behavior_control": True,
            "genesys2_board_trace_claimed": False,
            "real_malware_validation_claimed": False,
            "malware_detection_accuracy_claimed": False,
            "allowed_benign_overlap_is_not_false_positive": True,
        },
        "docker": {
            "returncode": docker_result.returncode if docker_result is not None else 0,
            "stdout_tail": (docker_result.stdout if docker_result is not None else "").splitlines()[-20:],
            "stderr_tail": (docker_result.stderr if docker_result is not None else "").splitlines()[-20:],
        },
        "validation_commands": [
            "uv run python tools/package_benign_control_summary.py",
            "uv run python tools/check_benign_control_summary.py --root .",
        ],
        "non_claims": [
            "Benign control evidence is local Linux behavior evidence, not Genesys2/CVA6 board trace evidence.",
            "Benign false-positive rate here is a controlled safe-workload audit metric, not real-malware detection accuracy.",
            "Allowed benign rule overlap, such as directory-scan shape in ls, is tracked separately and not counted as an unexpected false positive.",
        ],
    }


def self_test() -> int:
    text = 'openat(AT_FDCWD, "/tmp", O_RDONLY|O_CLOEXEC|O_DIRECTORY) = 3\ngetdents64(3, 0x1, 1024) = 112\nexit_group(0) = ?\n'
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "trace.log"
        path.write_text(text, encoding="utf-8")
        rows = parse_strace(path)
    if [row["name"] for row in rows] != ["openat", "getdents64"]:
        print("[FAIL] benign control strace parser self-test failed", file=sys.stderr)
        return 1
    print("[PASS] benign control packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package local benign-control behavior evidence.")
    parser.add_argument("--current-root", type=Path, default=DEFAULT_CURRENT_ROOT)
    parser.add_argument("--run-root", type=Path, default=DEFAULT_RUN_ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        docker_result = run_docker(args.run_root)
        summary = package_summary(args.current_root, args.run_root, docker_result)
        write_json(args.out, summary)
    except Exception as exc:
        print(f"package_benign_control_summary: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{summary['status']}] wrote benign control summary to {args.out}")
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
