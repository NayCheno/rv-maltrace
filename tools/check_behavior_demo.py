from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    load_json,
    resolve,
)


DEFAULT_MANIFEST = Path("experiments/linux_behavior/malware_like/manifest.json")
DEFAULT_FIXTURE_DIR = Path("sim/golden/demo_behavior")
DEFAULT_RENDER_TOOL = Path("tools/render_behavior_demo.py")
DEFAULT_CLI = Path("src/rv_maltrace/cli.py")
DEFAULT_UV_DOC = Path("docs/10-process/uv_workflow.md")
DEFAULT_DOC = Path("docs/04-runtime-linux/behavior_demo.md")
DEFAULT_README = Path("README.md")
DEFAULT_COMPOSE = Path("docker-compose.toolchain.yml")
DEFAULT_DOCKERFILE = Path("docker/linux-behavior/Dockerfile")

EXPECTED_SAMPLES = (
    "anti_debug_like",
    "file_scan",
    "dynamic_executable_memory",
    "illegal_trap",
)


def run_python(root: Path, args: list[str]) -> tuple[int, str, str]:
    completed = subprocess.run([sys.executable, *args], cwd=root, text=True, capture_output=True)
    return completed.returncode, completed.stdout, completed.stderr


def check_manifest(path: Path) -> list[str]:
    manifest = load_json(path)
    samples = manifest.get("samples", [])
    errors: list[str] = []
    if not isinstance(samples, list):
        return [f"{path}: samples must be a list"]
    by_id = {sample.get("id"): sample for sample in samples if isinstance(sample, dict)}
    for sample_id in EXPECTED_SAMPLES:
        sample = by_id.get(sample_id)
        if sample is None:
            errors.append(f"{path}: missing sample {sample_id}")
            continue
        if sample.get("class") != "malware_like_synthetic":
            errors.append(f"{path}: {sample_id}.class must be malware_like_synthetic")
        if sample.get("real_malware") is not False:
            errors.append(f"{path}: {sample_id}.real_malware must be false")
        if not sample.get("expected_behavior"):
            errors.append(f"{path}: {sample_id}.expected_behavior must be non-empty")
    return errors


def check_fixture_dir(path: Path) -> list[str]:
    errors: list[str] = []
    for sample_id in EXPECTED_SAMPLES:
        fixture = path / f"{sample_id}.trace.jsonl"
        if not fixture.exists():
            errors.append(f"missing fixture trace: {fixture}")
            continue
        text = fixture.read_text(encoding="utf-8")
        if "SYSCALL_ENTRY" not in text:
            errors.append(f"{fixture}: must contain at least one SYSCALL_ENTRY")
        if "malware detected" in text.lower():
            errors.append(f"{fixture}: must not contain detection claims")
    return errors


def check_cli(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    for token in (
        '"demo:behavior": "demo:behavior"',
        '"demo:groundtruth": "demo:groundtruth"',
        '"sim:cva6-full-soc-tohost": "sim:cva6-full-soc-tohost"',
        "task_demo_behavior",
        "task_demo_groundtruth",
        "task_sim_cva6_full_soc_tohost",
        "--sample",
        "--backend",
        "--trace",
        "--run-id",
    ):
        if token not in text:
            errors.append(f"{path}: missing CLI token {token}")
    return errors


def check_render_tool(root: Path, path: Path) -> list[str]:
    if not path.exists():
        return [f"missing render tool: {path}"]
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    for token in (
        "timeline.html",
        "graph.html",
        "scorecard.md",
        "Matched malware-like behavior rule",
        "not malware detection quality evidence",
        "--self-test",
    ):
        if token not in text:
            errors.append(f"{path}: missing render token {token}")
    if errors:
        return errors
    returncode, stdout, stderr = run_python(root, [str(path), "--self-test"])
    if returncode:
        errors.append(f"{path}: self-test failed: {stderr.strip() or stdout.strip()}")
    return errors


def check_docs(paths: list[Path]) -> list[str]:
    errors: list[str] = []
    required = (
        "demo:behavior",
        "demo:groundtruth",
        "sim:cva6-full-soc-tohost",
        "tools/check_behavior_demo.py",
        "results/demo/<run-id>/<sample-id>/",
        "not malware detection quality evidence",
    )
    for path in paths:
        if not path.exists():
            errors.append(f"missing doc: {path}")
            continue
        text = path.read_text(encoding="utf-8")
        for token in required:
            if token not in text:
                errors.append(f"{path}: missing required demo text {token}")
    readme = paths[-1]
    if readme.exists() and "uv run rvmt demo:behavior --sample anti_debug_like --backend fixture" not in readme.read_text(encoding="utf-8"):
        errors.append(f"{readme}: missing short demo entry command")
    return errors


def check_docker(compose: Path, dockerfile: Path) -> list[str]:
    errors: list[str] = []
    if not dockerfile.exists():
        errors.append(f"missing Linux behavior Dockerfile: {dockerfile}")
    else:
        text = dockerfile.read_text(encoding="utf-8")
        for token in (
            "qemu-user",
            "strace",
            "gcc-riscv64-linux-gnu",
            "libc6-dev-riscv64-cross",
            "binutils-riscv64-linux-gnu",
            "python3",
        ):
            if token not in text:
                errors.append(f"{dockerfile}: missing package token {token}")
    if not compose.exists():
        errors.append(f"missing compose file: {compose}")
    else:
        text = compose.read_text(encoding="utf-8")
        for token in ("linux-behavior:", "docker/linux-behavior/Dockerfile"):
            if token not in text:
                errors.append(f"{compose}: missing Linux behavior service token {token}")
    return errors


def check_fixture_pipeline(root: Path, fixture_dir: Path, manifest: Path) -> list[str]:
    errors: list[str] = []
    for sample_id in EXPECTED_SAMPLES:
        with tempfile.TemporaryDirectory() as tmp:
            out_root = Path(tmp)
            trace = fixture_dir / f"{sample_id}.trace.jsonl"
            semantic_dir = out_root / "semantic"
            audit_dir = out_root / "audit"
            visual_dir = out_root / "visual"
            commands = (
                ["tools/recover_behavior.py", "--trace", str(trace), "--out-dir", str(semantic_dir)],
                [
                    "tools/audit_behavior.py",
                    "--semantic",
                    str(semantic_dir / "semantic_events.json"),
                    "--graph",
                    str(semantic_dir / "behavior_graph.json"),
                    "--manifest",
                    str(manifest),
                    "--sample-id",
                    sample_id,
                    "--out-dir",
                    str(audit_dir),
                ],
                [
                    "tools/render_behavior_demo.py",
                    "--trace",
                    str(trace),
                    "--semantic",
                    str(semantic_dir / "semantic_events.json"),
                    "--graph",
                    str(semantic_dir / "behavior_graph.json"),
                    "--audit",
                    str(audit_dir / "behavior_audit.json"),
                    "--manifest",
                    str(manifest),
                    "--sample-id",
                    sample_id,
                    "--out-dir",
                    str(visual_dir),
                ],
            )
            for command in commands:
                returncode, stdout, stderr = run_python(root, command)
                if returncode:
                    errors.append(f"{sample_id}: command failed {' '.join(command)}: {stderr.strip() or stdout.strip()}")
                    break
            if errors and errors[-1].startswith(f"{sample_id}:"):
                continue
            scorecard = (visual_dir / "scorecard.md").read_text(encoding="utf-8")
            if "Matched malware-like behavior rule:" not in scorecard:
                errors.append(f"{sample_id}: scorecard missing matched rule line")
            if "malware detected: yes" in scorecard.lower():
                errors.append(f"{sample_id}: scorecard contains forbidden detection claim")
            audit = load_json(audit_dir / "behavior_audit.json")
            matched_expected = audit.get("matched_expected_behavior")
            weak_matched_expected = audit.get("weak_matched_expected_behavior")
            if not matched_expected and not weak_matched_expected:
                errors.append(f"{sample_id}: fixture did not match expected behavior")
    return errors


def run_checks(root: Path) -> list[str]:
    manifest = resolve(root, DEFAULT_MANIFEST)
    fixture_dir = resolve(root, DEFAULT_FIXTURE_DIR)
    paths = {
        "manifest": manifest,
        "fixture_dir": fixture_dir,
        "cli": resolve(root, DEFAULT_CLI),
        "render": resolve(root, DEFAULT_RENDER_TOOL),
        "uv_doc": resolve(root, DEFAULT_UV_DOC),
        "doc": resolve(root, DEFAULT_DOC),
        "readme": resolve(root, DEFAULT_README),
        "compose": resolve(root, DEFAULT_COMPOSE),
        "dockerfile": resolve(root, DEFAULT_DOCKERFILE),
    }
    errors: list[str] = []
    for label, path in paths.items():
        if label == "fixture_dir":
            if not path.is_dir():
                errors.append(f"missing fixture directory: {path}")
        elif not path.exists():
            errors.append(f"missing {label}: {path}")
    if errors:
        return errors
    errors.extend(check_manifest(paths["manifest"]))
    errors.extend(check_fixture_dir(paths["fixture_dir"]))
    errors.extend(check_cli(paths["cli"]))
    errors.extend(check_render_tool(root, paths["render"]))
    errors.extend(check_docs([paths["uv_doc"], paths["doc"], paths["readme"]]))
    errors.extend(check_docker(paths["compose"], paths["dockerfile"]))
    errors.extend(check_fixture_pipeline(root, paths["fixture_dir"], paths["manifest"]))
    return errors


def write_fixture(root: Path) -> None:
    (root / "src/rv_maltrace").mkdir(parents=True)
    (root / "tools").mkdir()
    (root / DEFAULT_UV_DOC).parent.mkdir(parents=True)
    (root / DEFAULT_DOC).parent.mkdir(parents=True)
    (root / "sim/golden/demo_behavior").mkdir(parents=True)
    (root / "experiments/linux_behavior/malware_like").mkdir(parents=True)
    (root / "docker/linux-behavior").mkdir(parents=True)
    (root / DEFAULT_CLI).write_text(
        '"demo:behavior": "demo:behavior"\n"demo:groundtruth": "demo:groundtruth"\n'
        '"sim:cva6-full-soc-tohost": "sim:cva6-full-soc-tohost"\n'
        "task_demo_behavior\ntask_demo_groundtruth\ntask_sim_cva6_full_soc_tohost\n"
        "--sample\n--backend\n--trace\n--run-id\n",
        encoding="utf-8",
    )
    shutil.copyfile(Path(__file__).resolve().with_name("render_behavior_demo.py"), root / DEFAULT_RENDER_TOOL)
    (root / DEFAULT_MANIFEST).write_text(
        json.dumps(
            {
                "samples": [
                    {
                        "id": sample_id,
                        "class": "malware_like_synthetic",
                        "real_malware": False,
                        "expected_behavior": ["anti_analysis_indicator" if sample_id == "anti_debug_like" else "illegal_instruction_trap"],
                    }
                    for sample_id in EXPECTED_SAMPLES
                ]
            }
        ),
        encoding="utf-8",
    )
    for sample_id in EXPECTED_SAMPLES:
        (root / DEFAULT_FIXTURE_DIR / f"{sample_id}.trace.jsonl").write_text(
            '{"cycle":1,"evt":"SYSCALL_ENTRY","pc":"0x1000","a7":"0x75","priv":"U"}\n',
            encoding="utf-8",
        )
    doc_text = (
        "demo:behavior\n"
        "demo:groundtruth\n"
        "sim:cva6-full-soc-tohost\n"
        "tools/check_behavior_demo.py\n"
        "results/demo/<run-id>/<sample-id>/\n"
        "not malware detection quality evidence\n"
        "uv run rvmt demo:behavior --sample anti_debug_like --backend fixture\n"
    )
    (root / DEFAULT_UV_DOC).write_text(doc_text, encoding="utf-8")
    (root / DEFAULT_DOC).write_text(doc_text, encoding="utf-8")
    (root / DEFAULT_README).write_text(doc_text, encoding="utf-8")
    (root / DEFAULT_DOCKERFILE).write_text(
        "FROM ubuntu:24.04\nRUN apt-get update && apt-get install -y qemu-user strace gcc-riscv64-linux-gnu libc6-dev-riscv64-cross binutils-riscv64-linux-gnu python3\n",
        encoding="utf-8",
    )
    (root / DEFAULT_COMPOSE).write_text("services:\n  linux-behavior:\n    build:\n      dockerfile: docker/linux-behavior/Dockerfile\n", encoding="utf-8")


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        errors = []
        errors.extend(check_manifest(root / DEFAULT_MANIFEST))
        errors.extend(check_fixture_dir(root / DEFAULT_FIXTURE_DIR))
        errors.extend(check_cli(root / DEFAULT_CLI))
        errors.extend(check_render_tool(root, root / DEFAULT_RENDER_TOOL))
        errors.extend(check_docs([root / DEFAULT_UV_DOC, root / DEFAULT_DOC, root / DEFAULT_README]))
        errors.extend(check_docker(root / DEFAULT_COMPOSE, root / DEFAULT_DOCKERFILE))
        if errors:
            for error in errors:
                print(f"[FAIL] self-test false positive: {error}", file=sys.stderr)
            return 1
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        (root / DEFAULT_CLI).write_text("missing demo tasks\n", encoding="utf-8")
        if not any("missing CLI token" in error for error in check_cli(root / DEFAULT_CLI)):
            print("[FAIL] self-test missed CLI token regression", file=sys.stderr)
            return 1
    print("[PASS] behavior demo checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check RV-MalTrace behavior demo evidence-bundle support.")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = Path.cwd()
    errors = run_checks(root)
    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    print("[PASS] RV-MalTrace behavior demo support is specified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
