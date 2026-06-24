from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = Path("board/trace_validation/programs/cycle_source_probe.c")
DEFAULT_OUT_ROOT = Path("build/board/genesys2_cycle_source_probe")
DEFAULT_MANIFEST = DEFAULT_OUT_ROOT / "build_manifest.json"


def repo_rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


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


def build_shell_command(source: Path, out_root: Path, binary: Path, build_log: Path, readelf: Path, compiler_version: Path) -> str:
    return " && ".join(
        [
            f"mkdir -p {out_root.as_posix()}",
            (
                "riscv64-linux-gnu-gcc -O2 -static -nostdlib -ffreestanding -fno-builtin "
                "-fno-stack-protector -msmall-data-limit=0 -Wall -Wextra -Wl,--build-id=none -Wl,-e,_start "
                f"-o {binary.as_posix()} {source.as_posix()} > {build_log.as_posix()} 2>&1"
            ),
            f"riscv64-linux-gnu-readelf -h -S {binary.as_posix()} > {readelf.as_posix()}",
            f"riscv64-linux-gnu-gcc --version | head -n 1 > {compiler_version.as_posix()}",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the Genesys2/CVA6 kernel-perf cycle-source probe ELF inside Docker.")
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--out-root", type=Path, default=DEFAULT_OUT_ROOT)
    parser.add_argument("--compose-file", type=Path, default=Path("docker-compose.toolchain.yml"))
    parser.add_argument("--service", default="linux-behavior")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    source = args.source
    out_root = args.out_root
    binary = out_root / "cycle_source_probe.riscv64"
    build_log = out_root / "build.log"
    readelf = out_root / "readelf.txt"
    compiler_version = out_root / "compiler_version.txt"
    manifest = out_root / "build_manifest.json"

    if not source.is_file():
        parser.error(f"source missing: {source}")
    shell_command = build_shell_command(source, out_root, binary, build_log, readelf, compiler_version)
    run(docker_compose_command(args.compose_file, args.service, shell_command), cwd=ROOT, dry_run=args.dry_run)
    if args.dry_run:
        print(f"[DRY-RUN] would write {manifest}")
        return 0
    for path in (binary, build_log, readelf, compiler_version):
        if not path.is_file():
            raise FileNotFoundError(f"expected build artifact missing: {path}")
    row = {
        "schema": "rvmt.genesys2.cycle_source_probe_build.v1",
        "status": "PASS",
        "source": repo_rel(source),
        "source_sha256": sha256_file(source),
        "binary": repo_rel(binary),
        "binary_sha256": sha256_file(binary),
        "build_log": repo_rel(build_log),
        "build_log_sha256": sha256_file(build_log),
        "readelf": repo_rel(readelf),
        "readelf_sha256": sha256_file(readelf),
        "compiler_version": repo_rel(compiler_version),
        "compiler_version_sha256": sha256_file(compiler_version),
        "cycle_source": "kernel_perf_hw_cycles",
        "docker_service": args.service,
        "compile_command_scope": "Docker linux-behavior service; host does not need a RISC-V compiler",
    }
    write_json(manifest, row)
    print(f"[PASS] built {binary} sha256={row['binary_sha256']}")
    print(f"[PASS] wrote {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
