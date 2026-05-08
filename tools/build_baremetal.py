from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROGRAMS_DIR = ROOT / "sim" / "programs"
COMMON_DIR = PROGRAMS_DIR / "common"
DEFAULT_TOOL_PREFIX = "riscv-none-elf-"


def discover_programs() -> list[str]:
    return sorted(
        path.name
        for path in PROGRAMS_DIR.iterdir()
        if path.is_dir() and path.name != "common" and (any(path.glob("*.c")) or any(path.glob("*.S")))
    )


def resolve_tool(name: str, prefix: str) -> str:
    configured = f"{prefix}{name}"
    resolved = shutil.which(configured)
    return resolved or configured


def run(cmd: list[str], *, cwd: Path, dry_run: bool) -> None:
    print("+ " + " ".join(cmd))
    if dry_run:
        return
    completed = subprocess.run(cmd, cwd=str(cwd))
    if completed.returncode:
        raise RuntimeError(f"command failed with exit code {completed.returncode}: {' '.join(cmd)}")


def build_program(name: str, out_dir: Path, prefix: str, cflags: list[str], dry_run: bool) -> None:
    program_dir = PROGRAMS_DIR / name
    if not program_dir.exists():
        raise RuntimeError(f"unknown program: {name}")

    cc = resolve_tool("gcc", prefix)
    objdump = resolve_tool("objdump", prefix)
    objcopy = resolve_tool("objcopy", prefix)
    target_dir = out_dir / name
    if not dry_run:
        target_dir.mkdir(parents=True, exist_ok=True)

    sources = [
        COMMON_DIR / "crt0.S",
        COMMON_DIR / "finish.S",
        COMMON_DIR / "trap_vector.S",
        *sorted(program_dir.glob("*.S")),
        *sorted(program_dir.glob("*.c")),
    ]
    elf = target_dir / f"{name}.elf"
    dump = target_dir / f"{name}.dump"
    binary = target_dir / f"{name}.bin"
    linker = COMMON_DIR / "linker.ld"
    cmd = [
        cc,
        "-march=rv64gc",
        "-mabi=lp64d",
        "-nostdlib",
        "-ffreestanding",
        "-Wl,--no-relax",
        f"-T{linker}",
        *cflags,
        *(str(source) for source in sources),
        "-o",
        str(elf),
    ]
    run(cmd, cwd=ROOT, dry_run=dry_run)
    run([objdump, "-d", str(elf)], cwd=ROOT, dry_run=dry_run)
    if not dry_run:
        dump.write_text(
            subprocess.check_output([objdump, "-d", str(elf)], cwd=str(ROOT), encoding="utf-8", errors="replace"),
            encoding="utf-8",
            newline="\n",
        )
    run([objcopy, "-O", "binary", str(elf), str(binary)], cwd=ROOT, dry_run=dry_run)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build bare-metal RISC-V test programs.")
    parser.add_argument("--all", action="store_true", help="Build every program under sim/programs.")
    parser.add_argument("--program", action="append", default=[], help="Program name to build. May be repeated.")
    parser.add_argument("--out-dir", type=Path, default=ROOT / "build" / "baremetal")
    parser.add_argument("--tool-prefix", default=DEFAULT_TOOL_PREFIX)
    parser.add_argument("--cflag", action="append", default=[])
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    programs = discover_programs() if args.all else sorted(set(args.program))
    if not programs:
        parser.error("choose --all or at least one --program")

    try:
        for program in programs:
            build_program(program, args.out_dir, args.tool_prefix, args.cflag, args.dry_run)
    except Exception as exc:
        print(f"build_baremetal: error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
