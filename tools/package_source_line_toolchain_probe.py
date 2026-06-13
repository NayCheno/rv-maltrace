from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CURRENT_ROOT = Path("results/evaluation/genesys2-cva6/current")
DEFAULT_OUT = DEFAULT_CURRENT_ROOT / "source_line_toolchain_probe.json"
DEFAULT_PROBE_DIR = Path("build/source_line_toolchain_probe")
SOURCE_NAME = "source_line_probe.c"
ELF_NAME = "source_line_probe.riscv64"
CODE_MAP_NAME = "source_line_probe.code_map.json"

BOARD_ELF_PATHS = {
    "phase4_uart_pass": Path("build/board/genesys2_cva6_phase4/rvmt_cva6_uart_pass.elf"),
    "phase4_onboard_uart_pass": Path("build/board/genesys2_cva6_phase4_onboard_com7/rvmt_cva6_uart_pass.elf"),
    "p0_marker_hello_write": Path("build/board/genesys2_cva6_p0_marker/hello_write/hello_write.riscv64"),
    "safe_surrogate_file_scan": Path(
        "results/board/genesys2_cva6_safe_surrogate/"
        "genesys2-cva6-safe-p2-20260610/file_scan/00_build_syscall_only/file_scan.riscv64"
    ),
}

PROBE_SOURCE = r'''static const char rvmt_message[] = "rvmt-source-line-probe\n";

static long rvmt_syscall(long nr, long arg0, long arg1, long arg2) {
    register long a0 __asm__("a0") = arg0;
    register long a1 __asm__("a1") = arg1;
    register long a2 __asm__("a2") = arg2;
    register long a7 __asm__("a7") = nr;
    __asm__ volatile("ecall" : "+r"(a0) : "r"(a1), "r"(a2), "r"(a7) : "memory");
    return a0;
}

__attribute__((noreturn)) void _start(void) {
    rvmt_syscall(64, 1, (long)rvmt_message, sizeof(rvmt_message) - 1);
    rvmt_syscall(93, 0, 0, 0);
    for (;;) {
    }
}
'''


def repo_rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_if_file(path: Path) -> str | None:
    return sha256_file(path) if path.is_file() else None


def parse_debug_sections(readelf_text: str) -> list[str]:
    names: list[str] = []
    for line in readelf_text.splitlines():
        match = re.search(r"\]\s+(\.\S+)\s+", line)
        if match and match.group(1).startswith(".debug_"):
            names.append(match.group(1))
    return sorted(set(names))


def read_debug_sections(path: Path) -> list[str]:
    if not path.is_file():
        return []
    return parse_debug_sections(path.read_text(encoding="utf-8", errors="replace"))


def read_first_line(path: Path) -> str | None:
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8", errors="replace").splitlines()[0].strip()


def tail_lines(text: str, limit: int = 20) -> list[str]:
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    return lines[-limit:]


def write_probe_source(probe_dir: Path) -> Path:
    path = probe_dir / SOURCE_NAME
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(PROBE_SOURCE, encoding="utf-8", newline="\n")
    return path


def docker_script(probe_dir: Path) -> str:
    out = probe_dir.as_posix()
    src = (probe_dir / SOURCE_NAME).as_posix()
    elf = (probe_dir / ELF_NAME).as_posix()
    lines = [
        "set -euo pipefail",
        f"mkdir -p {out}",
        f"riscv64-linux-gnu-gcc -g -O0 -static -nostdlib -fno-pie -no-pie -Wl,--build-id=none -o {elf} {src}",
        f"riscv64-linux-gnu-readelf -S {elf} > {out}/probe.readelf_sections.txt",
        f"riscv64-linux-gnu-nm -n {elf} > {out}/probe.nm.txt",
        f"python3 tools/build_code_map.py --elf {elf} --sample-id source_line_probe --source {src} "
        f"--binary-role debug_no_pie_probe --runtime-path /tmp/rvmt_source_line_probe "
        f"--addr2line /usr/bin/riscv64-linux-gnu-addr2line --out-dir {out}",
        f"riscv64-linux-gnu-gcc --version | head -n 1 > {out}/gcc.version.txt",
        f"qemu-riscv64 --version | head -n 1 > {out}/qemu.version.txt",
        f"strace --version | head -n 1 > {out}/strace.version.txt",
        f"riscv64-linux-gnu-addr2line --version | head -n 1 > {out}/addr2line.version.txt",
        f"riscv64-linux-gnu-readelf --version | head -n 1 > {out}/readelf.version.txt",
    ]
    for board_id, board_path in BOARD_ELF_PATHS.items():
        section_out = f"{out}/board_{board_id}.readelf_sections.txt"
        rel = board_path.as_posix()
        lines.extend(
            [
                f"if [ -f {rel} ]; then",
                f"  riscv64-linux-gnu-readelf -S {rel} > {section_out}",
                "else",
                f"  printf 'MISSING {rel}\\n' > {section_out}",
                "fi",
            ]
        )
    return "\n".join(lines) + "\n"


def run_docker_probe(probe_dir: Path) -> subprocess.CompletedProcess[str]:
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
        docker_script(probe_dir),
    ]
    return subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)


def probe_source_locations(code_map: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in code_map.get("source_locations", []):
        if not isinstance(row, dict):
            continue
        file_value = str(row.get("file") or "").replace("\\", "/")
        if not file_value.endswith(SOURCE_NAME):
            continue
        line = row.get("line")
        if not isinstance(line, int) or line <= 0:
            continue
        rows.append(
            {
                "pc": row.get("pc"),
                "function": row.get("function"),
                "file": file_value,
                "line": line,
                "confidence": row.get("confidence"),
            }
        )
    return rows


def board_elf_rows(probe_dir: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for board_id, board_path in BOARD_ELF_PATHS.items():
        section_path = probe_dir / f"board_{board_id}.readelf_sections.txt"
        sections = read_debug_sections(section_path)
        full_path = ROOT / board_path
        rows.append(
            {
                "id": board_id,
                "path": board_path.as_posix(),
                "exists": full_path.is_file(),
                "sha256": sha256_if_file(full_path),
                "readelf_sections": repo_rel(section_path),
                "debug_sections_present": bool(sections),
                "debug_section_names": sections,
            }
        )
    return rows


def package_probe(current_root: Path, probe_dir: Path, docker_result: subprocess.CompletedProcess[str] | None) -> dict[str, Any]:
    source_path = probe_dir / SOURCE_NAME
    elf_path = probe_dir / ELF_NAME
    code_map_path = probe_dir / CODE_MAP_NAME
    readelf_path = probe_dir / "probe.readelf_sections.txt"
    code_map = load_json(code_map_path) if code_map_path.is_file() else {}
    probe_sections = read_debug_sections(readelf_path)
    source_rows = probe_source_locations(code_map)
    source_attr = code_map.get("source_attribution") if isinstance(code_map.get("source_attribution"), dict) else {}
    board_rows = board_elf_rows(probe_dir)
    docker_rc = docker_result.returncode if docker_result is not None else 0
    status = "PASS"
    if docker_rc != 0:
        status = "FAIL"
    if not source_path.is_file() or not elf_path.is_file() or not code_map_path.is_file():
        status = "FAIL"
    if ".debug_line" not in probe_sections or not source_rows:
        status = "FAIL"
    if source_attr.get("source_line_level") != "available":
        status = "FAIL"
    if any(row.get("debug_sections_present") for row in board_rows):
        status = "FAIL"
    if any(row.get("exists") is not True for row in board_rows):
        status = "FAIL"

    return {
        "schema": "rvmt.genesys2.source_line_toolchain_probe.v1",
        "status": status,
        "canonical_evaluation_root": repo_rel(current_root),
        "toolchain": {
            "docker_service": "linux-behavior",
            "compiler": read_first_line(probe_dir / "gcc.version.txt"),
            "qemu": read_first_line(probe_dir / "qemu.version.txt"),
            "strace": read_first_line(probe_dir / "strace.version.txt"),
            "addr2line": read_first_line(probe_dir / "addr2line.version.txt"),
            "readelf": read_first_line(probe_dir / "readelf.version.txt"),
        },
        "probe": {
            "source_path": repo_rel(source_path),
            "elf_path": repo_rel(elf_path),
            "code_map_path": repo_rel(code_map_path),
            "readelf_sections": repo_rel(readelf_path),
            "source_sha256": sha256_if_file(source_path),
            "elf_sha256": sha256_if_file(elf_path),
            "code_map_sha256": sha256_if_file(code_map_path),
            "debug_sections_present": bool(probe_sections),
            "debug_section_names": probe_sections,
            "addr2line_tool": source_attr.get("addr2line_tool"),
            "addr2line_source_line_available": source_attr.get("source_line_level") == "available",
            "source_line_basis": source_attr.get("source_line_basis"),
            "source_location_count": len(source_rows),
            "source_locations": source_rows[:16],
        },
        "current_board_elfs": board_rows,
        "claim_boundary": {
            "toolchain_source_line_probe_passed": status == "PASS",
            "debug_counterpart_source_line_available": bool(source_rows),
            "current_board_elf_dwarf_available": any(row.get("debug_sections_present") for row in board_rows),
            "current_board_trace_source_line_available": False,
            "board_rerun_required_for_board_native_source_lines": True,
            "real_malware_validation_claimed": False,
        },
        "docker": {
            "returncode": docker_rc,
            "stdout_tail": tail_lines(docker_result.stdout if docker_result is not None else ""),
            "stderr_tail": tail_lines(docker_result.stderr if docker_result is not None else ""),
        },
        "validation_commands": [
            "uv run python tools/package_source_line_toolchain_probe.py",
            "uv run python tools/check_source_line_toolchain_probe.py --root .",
        ],
        "non_claims": [
            "This proves the RISC-V Linux debug/no-PIE source-line toolchain path, not current board-trace DWARF attribution.",
            "Current generated board ELFs are recorded as lacking DWARF debug sections and remain function-level for board trace attribution.",
            "Board-native source-line attribution still requires rebuilding the exact board workload ELF with DWARF, rerunning board capture, and rejoining the trace to that ELF.",
            "This probe does not add real-malware validation.",
        ],
    }


def self_test() -> int:
    section_text = """
  [ 1] .text             PROGBITS         0000000000010100
  [ 2] .debug_info       PROGBITS         0000000000000000
  [ 3] .debug_line       PROGBITS         0000000000000000
"""
    if parse_debug_sections(section_text) != [".debug_info", ".debug_line"]:
        print("[FAIL] source-line probe debug-section parser failed", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        probe_dir = root / "build" / "probe"
        probe_dir.mkdir(parents=True)
        write_probe_source(probe_dir)
        write_json(
            probe_dir / CODE_MAP_NAME,
            {
                "source_attribution": {
                    "source_line_level": "available",
                    "source_line_basis": "DWARF line table via addr2line-compatible tool",
                    "addr2line_tool": "/usr/bin/riscv64-linux-gnu-addr2line",
                },
                "source_locations": [
                    {"pc": "0x10000", "function": "_start", "file": "build/probe/source_line_probe.c", "line": 10, "confidence": "debug_info"}
                ],
            },
        )
        (probe_dir / ELF_NAME).write_bytes(b"\x7fELF")
        (probe_dir / "probe.readelf_sections.txt").write_text(section_text, encoding="utf-8")
        for name in ("gcc", "qemu", "strace", "addr2line", "readelf"):
            (probe_dir / f"{name}.version.txt").write_text(f"{name} fixture\n", encoding="utf-8")
        old_root = globals()["ROOT"]
        old_board = dict(BOARD_ELF_PATHS)
        try:
            globals()["ROOT"] = root
            BOARD_ELF_PATHS.clear()
            board = root / "board.elf"
            board.write_bytes(b"\x7fELF")
            BOARD_ELF_PATHS["fixture_board"] = Path("board.elf")
            (probe_dir / "board_fixture_board.readelf_sections.txt").write_text("[ 1] .text PROGBITS\n", encoding="utf-8")
            summary = package_probe(root / DEFAULT_CURRENT_ROOT, probe_dir, None)
        finally:
            globals()["ROOT"] = old_root
            BOARD_ELF_PATHS.clear()
            BOARD_ELF_PATHS.update(old_board)
    if summary.get("status") != "PASS":
        print("[FAIL] source-line probe fixture should pass", file=sys.stderr)
        return 1
    print("[PASS] source-line toolchain probe packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package the Genesys2/CVA6 source-line toolchain probe.")
    parser.add_argument("--current-root", type=Path, default=DEFAULT_CURRENT_ROOT)
    parser.add_argument("--probe-dir", type=Path, default=DEFAULT_PROBE_DIR)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        write_probe_source(args.probe_dir)
        docker_result = run_docker_probe(args.probe_dir)
        summary = package_probe(args.current_root, args.probe_dir, docker_result)
        write_json(args.out, summary)
    except Exception as exc:
        print(f"package_source_line_toolchain_probe: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{summary['status']}] wrote source-line toolchain probe to {args.out}")
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
