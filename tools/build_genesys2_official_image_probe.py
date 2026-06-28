from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = Path("board/trace_validation/programs/official_image_probe.c")
DEFAULT_OUT_ROOT = Path("build/board/genesys2_official_image_probe")
DEFAULT_MANIFEST = DEFAULT_OUT_ROOT / "build_manifest.json"


VARIANTS = {
    "static_exec": "-O2 -static -s -Wall -Wextra -Wl,--build-id=none",
    "static_pie": "-O2 -static-pie -s -Wall -Wextra -Wl,--build-id=none",
    "dynamic_pie": "-O2 -fPIE -pie -s -Wall -Wextra -Wl,--build-id=none",
}


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


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def build_shell(source: Path, out_root: Path) -> str:
    commands = [f"mkdir -p {shell_quote(out_root.as_posix())}"]
    for variant, flags in VARIANTS.items():
        binary = out_root / f"official_image_probe_{variant}.riscv64"
        build_log = out_root / f"{variant}.build.log"
        readelf = out_root / f"{variant}.readelf.txt"
        commands.append(
            " ".join(
                [
                    "set +e;",
                    "riscv64-linux-gnu-gcc",
                    flags,
                    "-o",
                    shell_quote(binary.as_posix()),
                    shell_quote(source.as_posix()),
                    ">",
                    shell_quote(build_log.as_posix()),
                    "2>&1;",
                    "rc=$?;",
                    "if [ $rc -eq 0 ]; then riscv64-linux-gnu-readelf -h -l -S",
                    shell_quote(binary.as_posix()),
                    ">",
                    shell_quote(readelf.as_posix()),
                    "2>&1; fi;",
                    "echo $rc >",
                    shell_quote((out_root / f"{variant}.returncode.txt").as_posix()),
                    "; set -e",
                ]
            )
        )
    commands.append(f"riscv64-linux-gnu-gcc --version | head -n 1 > {shell_quote((out_root / 'compiler_version.txt').as_posix())}")
    return " && ".join(commands)


def run(command: list[str], *, cwd: Path, dry_run: bool) -> None:
    print("+ " + " ".join(command))
    if dry_run:
        return
    subprocess.run(command, cwd=cwd, check=True)


def variant_row(source: Path, out_root: Path, variant: str) -> dict[str, Any]:
    binary = out_root / f"official_image_probe_{variant}.riscv64"
    build_log = out_root / f"{variant}.build.log"
    readelf = out_root / f"{variant}.readelf.txt"
    rc_file = out_root / f"{variant}.returncode.txt"
    rc = int(rc_file.read_text(encoding="utf-8").strip()) if rc_file.is_file() else 127
    row: dict[str, Any] = {
        "variant": variant,
        "status": "PASS" if rc == 0 and binary.is_file() else "BLOCKED_BUILD_FAILED",
        "compile_flags": VARIANTS[variant],
        "returncode": rc,
        "source": repo_rel(source),
        "source_sha256": sha256_file(source),
        "build_log": repo_rel(build_log) if build_log.is_file() else None,
        "build_log_sha256": sha256_file(build_log) if build_log.is_file() else None,
        "binary": repo_rel(binary) if binary.is_file() else None,
        "binary_sha256": sha256_file(binary) if binary.is_file() else None,
        "readelf": repo_rel(readelf) if readelf.is_file() else None,
        "readelf_sha256": sha256_file(readelf) if readelf.is_file() else None,
    }
    return row


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the Genesys2 official-image probe ELF variants.")
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--out-root", type=Path, default=DEFAULT_OUT_ROOT)
    parser.add_argument("--compose-file", type=Path, default=Path("docker-compose.toolchain.yml"))
    parser.add_argument("--service", default="linux-behavior")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if not args.source.is_file():
        parser.error(f"source missing: {args.source}")
    run(docker_compose_command(args.compose_file, args.service, build_shell(args.source, args.out_root)), cwd=ROOT, dry_run=args.dry_run)
    if args.dry_run:
        return 0
    compiler = args.out_root / "compiler_version.txt"
    variants = {name: variant_row(args.source, args.out_root, name) for name in VARIANTS}
    manifest = {
        "schema": "rvmt.genesys2.official_image_probe_build.v1",
        "status": "PASS" if variants["static_exec"]["status"] == "PASS" else "FAIL_STATIC_EXEC_BUILD",
        "source": repo_rel(args.source),
        "source_sha256": sha256_file(args.source),
        "compiler_version": repo_rel(compiler) if compiler.is_file() else None,
        "compiler_version_sha256": sha256_file(compiler) if compiler.is_file() else None,
        "variants": variants,
        "claim_boundary": {
            "build_only": True,
            "board_execution_claimed": False,
        },
    }
    write_json(DEFAULT_MANIFEST if args.out_root == DEFAULT_OUT_ROOT else args.out_root / "build_manifest.json", manifest)
    print(f"[{manifest['status']}] wrote {args.out_root / 'build_manifest.json'}")
    for name, row in variants.items():
        print(f"[{row['status']}] {name} {row.get('binary') or row.get('build_log')}")
    return 0 if manifest["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
