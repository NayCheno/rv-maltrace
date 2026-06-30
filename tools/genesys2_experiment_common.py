from __future__ import annotations

import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from experiment_common import load_json, repo_path, repo_rel, require, sha256_file, write_json


FREESTANDING_GCC_FLAGS = (
    "-O2 -static -nostdlib -ffreestanding -fno-builtin "
    "-fno-stack-protector -msmall-data-limit=0 -Wall -Wextra "
    "-Wl,--build-id=none -Wl,-e,_start"
)
HOSTED_STATIC_GCC_FLAGS = "-O2 -static -s -Wall -Wextra -Wl,--build-id=none"


@dataclass(frozen=True)
class ProbeBuildSpec:
    schema: str
    binary_name: str
    gcc_flags: str
    extra_manifest_fields: dict[str, Any] = field(default_factory=dict)


def rel_or_abs(root: Path, value: str | Path) -> Path:
    return repo_path(root, value)


def artifact_row(root: Path, path: Path) -> dict[str, Any]:
    return {
        "path": repo_rel(root, path),
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
    }


def check_artifact(errors: list[str], root: Path, summary: dict[str, Any], name: str) -> Path | None:
    artifacts = summary.get("artifacts") if isinstance(summary.get("artifacts"), dict) else {}
    row = artifacts.get(name) if isinstance(artifacts.get(name), dict) else {}
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


def run(command: list[str], *, cwd: Path, dry_run: bool) -> None:
    print("+ " + " ".join(command))
    if dry_run:
        return
    subprocess.run(command, cwd=cwd, check=True)


def docker_compose_command(compose_file: Path, service: str, shell_command: str) -> list[str]:
    docker = shutil.which("docker") or "docker"
    return [
        docker,
        "compose",
        "-f",
        compose_file.as_posix(),
        "run",
        "--rm",
        "--build",
        service,
        "bash",
        "-lc",
        shell_command,
    ]


def probe_build_shell_command(
    source: Path,
    out_root: Path,
    binary: Path,
    build_log: Path,
    readelf: Path,
    compiler_version: Path,
    *,
    gcc_flags: str,
) -> str:
    return " && ".join(
        [
            f"mkdir -p {out_root.as_posix()}",
            (
                f"riscv64-linux-gnu-gcc {gcc_flags} "
                f"-o {binary.as_posix()} {source.as_posix()} > {build_log.as_posix()} 2>&1"
            ),
            f"riscv64-linux-gnu-readelf -h -S {binary.as_posix()} > {readelf.as_posix()}",
            f"riscv64-linux-gnu-gcc --version | head -n 1 > {compiler_version.as_posix()}",
        ]
    )


def build_probe_elf(
    root: Path,
    *,
    source: Path,
    out_root: Path,
    compose_file: Path,
    service: str,
    dry_run: bool,
    spec: ProbeBuildSpec,
) -> int:
    binary = out_root / spec.binary_name
    build_log = out_root / "build.log"
    readelf = out_root / "readelf.txt"
    compiler_version = out_root / "compiler_version.txt"
    manifest = out_root / "build_manifest.json"

    shell_command = probe_build_shell_command(
        source,
        out_root,
        binary,
        build_log,
        readelf,
        compiler_version,
        gcc_flags=spec.gcc_flags,
    )
    run(docker_compose_command(compose_file, service, shell_command), cwd=root, dry_run=dry_run)
    if dry_run:
        print(f"[DRY-RUN] would write {manifest}")
        return 0
    for path in (binary, build_log, readelf, compiler_version):
        if not path.is_file():
            raise FileNotFoundError(f"expected build artifact missing: {path}")
    row = {
        "schema": spec.schema,
        "status": "PASS",
        "source": repo_rel(root, source),
        "source_sha256": sha256_file(source),
        "binary": repo_rel(root, binary),
        "binary_sha256": sha256_file(binary),
        "build_log": repo_rel(root, build_log),
        "build_log_sha256": sha256_file(build_log),
        "readelf": repo_rel(root, readelf),
        "readelf_sha256": sha256_file(readelf),
        "compiler_version": repo_rel(root, compiler_version),
        "compiler_version_sha256": sha256_file(compiler_version),
        **spec.extra_manifest_fields,
        "docker_service": service,
        "compile_command_scope": "Docker linux-behavior service; host does not need a RISC-V compiler",
    }
    write_json(manifest, row)
    print(f"[PASS] built {binary} sha256={row['binary_sha256']}")
    print(f"[PASS] wrote {manifest}")
    return 0


def make_run_artifacts(
    root: Path,
    source: Path,
    binary: Path,
    build_manifest: Path,
    transfer_log: Path,
    run_log: Path,
) -> dict[str, Any]:
    artifacts = {
        "source": artifact_row(root, source),
        "binary": artifact_row(root, binary),
        "build_manifest": artifact_row(root, build_manifest),
        "run_log": artifact_row(root, run_log),
    }
    if transfer_log.is_file():
        artifacts["transfer_log"] = artifact_row(root, transfer_log)
    return artifacts


def load_checked_build_artifacts(build_manifest: Path, *, label: str) -> tuple[Path, Path]:
    if not build_manifest.is_file():
        raise FileNotFoundError(f"build manifest missing: {build_manifest}")
    build_data = load_json(build_manifest)
    source = Path(str(build_data["source"]))
    binary = Path(str(build_data["binary"]))
    if not source.is_file() or sha256_file(source) != build_data.get("source_sha256"):
        raise RuntimeError(f"source hash mismatch in {label} build manifest")
    if not binary.is_file() or sha256_file(binary) != build_data.get("binary_sha256"):
        raise RuntimeError(f"binary hash mismatch in {label} build manifest")
    return source, binary


def transfer_binary(
    root: Path,
    *,
    port: str,
    baud: int,
    binary: Path,
    target: str,
    transfer_log: Path,
) -> None:
    run(
        [
            sys.executable,
            "tools/serial_base64_transfer.py",
            "--port",
            port,
            "--baud",
            str(baud),
            "--source",
            str(binary),
            "--target",
            target,
            "--log",
            str(transfer_log),
            "--chunk-read",
            "0.25",
            "--final-read",
            "3.0",
            "--disable-echo",
        ],
        cwd=root,
        dry_run=False,
    )


def capture_board_command(
    root: Path,
    *,
    port: str,
    baud: int,
    run_log: Path,
    board_command: str,
    post_read: str,
) -> None:
    run(
        [
            sys.executable,
            "tools/serial_direct_command_capture.py",
            "--port",
            port,
            "--baud",
            str(baud),
            "--out",
            str(run_log),
            "--pre-read",
            "0.2",
            "--post-read",
            post_read,
            board_command,
        ],
        cwd=root,
        dry_run=False,
    )


def report_summary_exit(summary: dict[str, Any], summary_path: Path, *, pass_message: str) -> int:
    status = str(summary.get("status"))
    print(f"[{status}] wrote {summary_path}")
    if status == "PASS":
        print(pass_message)
        return 0
    if status.startswith("BLOCKED_"):
        print(f"[{status}] {summary.get('blocked_reason')}")
        return 2
    print(f"[{status}] {summary.get('blocked_reason')}", file=sys.stderr)
    return 1
