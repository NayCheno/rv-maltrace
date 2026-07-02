from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    load_json,
    repo_path,
    repo_rel,
    sha256_file,
    write_json,
)

from ccfa_gate_common import ALL_CCFA_SAMPLES, P0_SAMPLES, SAFE_SURROGATE_SAMPLES


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CURRENT_ROOT = Path("results/evaluation/genesys2-cva6/current")
DEFAULT_OUT = DEFAULT_CURRENT_ROOT / "debug_elf_readiness_summary.json"
DEFAULT_BUILD_ROOT = Path("build/debug_elf_readiness")

P0_SOURCE_PATHS = {
    "hello_write": Path("board/trace_validation/programs/hello_write.c"),
    "file_open_read_write": Path("board/trace_validation/programs/file_open_read_write.c"),
    "fork_exec": Path("board/trace_validation/programs/fork_exec.c"),
    "illegal_instruction": Path("board/trace_validation/programs/illegal_instruction.c"),
}
SAFE_SOURCE_PATHS = {
    "file_scan": Path("experiments/linux_behavior/malware_like/programs/file_scan.c"),
    "batch_open_read_write": Path("experiments/linux_behavior/malware_like/programs/batch_open_read_write.c"),
    "self_copy_sim": Path("experiments/linux_behavior/malware_like/programs/self_copy_sim.c"),
    "abnormal_syscall_sequence": Path("experiments/linux_behavior/malware_like/programs/abnormal_syscall_sequence.c"),
    "illegal_trap": Path("experiments/linux_behavior/malware_like/programs/illegal_trap.c"),
    "process_chain": Path("experiments/linux_behavior/malware_like/programs/process_chain.c"),
    "dynamic_executable_memory": Path("experiments/linux_behavior/malware_like/programs/dynamic_executable_memory.c"),
    "anti_debug_like": Path("experiments/linux_behavior/malware_like/programs/anti_debug_like.c"),
}


def sample_specs() -> list[dict[str, Any]]:
    specs: list[dict[str, Any]] = []
    for sample_id in P0_SAMPLES:
        specs.append({"id": sample_id, "sample_class": "p0_safe_synthetic", "source": P0_SOURCE_PATHS[sample_id]})
    for sample_id in SAFE_SURROGATE_SAMPLES:
        specs.append({"id": sample_id, "sample_class": "malware_like_synthetic_syscall_only", "source": SAFE_SOURCE_PATHS[sample_id]})
    return specs


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
    return [line.rstrip() for line in text.splitlines() if line.strip()][-limit:]


def source_location_matches(location: dict[str, Any], source: Path) -> bool:
    file_value = str(location.get("file") or "").replace("\\", "/")
    return file_value.endswith(source.as_posix()) and int(location.get("line") or 0) > 0


def source_location_count(code_map: dict[str, Any], source: Path) -> int:
    return sum(1 for row in code_map.get("source_locations", []) if isinstance(row, dict) and source_location_matches(row, source))


def docker_script(build_root: Path) -> str:
    out = build_root.as_posix()
    lines = [
        "set -euo pipefail",
        f"mkdir -p {out}/toolchain",
        f"riscv64-linux-gnu-gcc --version | head -n 1 > {out}/toolchain/gcc.version.txt",
        f"qemu-riscv64 --version | head -n 1 > {out}/toolchain/qemu.version.txt",
        f"strace --version | head -n 1 > {out}/toolchain/strace.version.txt",
        f"riscv64-linux-gnu-addr2line --version | head -n 1 > {out}/toolchain/addr2line.version.txt",
        f"riscv64-linux-gnu-readelf --version | head -n 1 > {out}/toolchain/readelf.version.txt",
    ]
    for spec in sample_specs():
        sample_id = spec["id"]
        source = spec["source"].as_posix()
        sample_dir = f"{out}/{sample_id}"
        elf = f"{sample_dir}/{sample_id}.debug.riscv64"
        code_map_dir = f"{sample_dir}/code_map"
        lines.extend(
            [
                f"mkdir -p {code_map_dir}",
                (
                    "riscv64-linux-gnu-gcc -g -O0 -static -nostdlib -ffreestanding -fno-builtin "
                    "-fno-pie -no-pie -Wl,--build-id=none "
                    "-include tools/rvmt_freestanding_syscall.h "
                    f"-o {elf} {source}"
                ),
                f"riscv64-linux-gnu-readelf -S {elf} > {sample_dir}/{sample_id}.readelf_sections.txt",
                f"riscv64-linux-gnu-nm -n {elf} > {sample_dir}/{sample_id}.nm.txt",
                (
                    f"python3 tools/build_code_map.py --elf {elf} --sample-id {sample_id} --source {source} "
                    f"--binary-role debug_no_pie_board_rerun_candidate --runtime-path /tmp/rvmt_debug/{sample_id} "
                    f"--addr2line /usr/bin/riscv64-linux-gnu-addr2line --out-dir {code_map_dir}"
                ),
            ]
        )
    return "\n".join(lines) + "\n"


def run_docker_build(root: Path, build_root: Path) -> subprocess.CompletedProcess[str]:
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
        docker_script(build_root),
    ]
    return subprocess.run(command, cwd=root, text=True, capture_output=True, check=False)


def sample_row(root: Path, build_root: Path, spec: dict[str, Any]) -> dict[str, Any]:
    sample_id = str(spec["id"])
    source_rel = Path(spec["source"])
    source = repo_path(root, source_rel)
    sample_dir = repo_path(root, build_root) / sample_id
    elf = sample_dir / f"{sample_id}.debug.riscv64"
    readelf = sample_dir / f"{sample_id}.readelf_sections.txt"
    nm = sample_dir / f"{sample_id}.nm.txt"
    code_map_path = sample_dir / "code_map" / f"{sample_id}.code_map.json"
    code_map = load_json(code_map_path) if code_map_path.is_file() else {}
    sections = read_debug_sections(readelf)
    source_attr = code_map.get("source_attribution") if isinstance(code_map.get("source_attribution"), dict) else {}
    matched_source_locations = source_location_count(code_map, source_rel)
    row_status = "PASS"
    if not source.is_file() or not elf.is_file() or not readelf.is_file() or not code_map_path.is_file():
        row_status = "FAIL"
    if ".debug_line" not in sections or ".debug_info" not in sections:
        row_status = "FAIL"
    if source_attr.get("source_line_level") != "available":
        row_status = "FAIL"
    if int(source_attr.get("source_location_count") or 0) <= 0 or matched_source_locations <= 0:
        row_status = "FAIL"
    if code_map.get("sample_id") != sample_id:
        row_status = "FAIL"
    if elf.is_file() and code_map.get("sha256") and code_map.get("sha256") != sha256_file(elf):
        row_status = "FAIL"
    return {
        "id": sample_id,
        "sample_class": spec["sample_class"],
        "status": row_status,
        "real_malware": False,
        "source_path": repo_rel(root, source),
        "source_sha256": sha256_if_file(source),
        "debug_elf_path": repo_rel(root, elf),
        "debug_elf_sha256": sha256_if_file(elf),
        "readelf_sections_path": repo_rel(root, readelf),
        "readelf_sections_sha256": sha256_if_file(readelf),
        "nm_path": repo_rel(root, nm),
        "nm_sha256": sha256_if_file(nm),
        "debug_sections_present": bool(sections),
        "debug_section_names": sections,
        "code_map_path": repo_rel(root, code_map_path),
        "code_map_sha256": sha256_if_file(code_map_path),
        "code_map_schema": code_map.get("schema"),
        "source_line_available": source_attr.get("source_line_level") == "available",
        "source_line_basis": source_attr.get("source_line_basis"),
        "source_location_count": int(source_attr.get("source_location_count") or 0),
        "sample_source_location_count": matched_source_locations,
        "runtime_path": f"/tmp/rvmt_debug/{sample_id}",
        "board_capture_required": True,
        "accepted_as_board_evidence": False,
    }


def package_summary(
    root: Path,
    current_root: Path,
    build_root: Path,
    docker_result: subprocess.CompletedProcess[str] | None = None,
) -> dict[str, Any]:
    rows = [sample_row(root, build_root, spec) for spec in sample_specs()]
    toolchain_dir = repo_path(root, build_root) / "toolchain"
    docker_rc = docker_result.returncode if docker_result is not None else 0
    status = "PASS"
    if docker_rc != 0 or len(rows) != len(ALL_CCFA_SAMPLES):
        status = "FAIL"
    if [row.get("id") for row in rows] != ALL_CCFA_SAMPLES:
        status = "FAIL"
    if any(row.get("status") != "PASS" for row in rows):
        status = "FAIL"
    return {
        "schema": "rvmt.genesys2.debug_elf_readiness.v1",
        "status": status,
        "canonical_evaluation_root": repo_rel(root, current_root),
        "evidence_scope": "debug_no_pie_elf_and_code_map_readiness_for_future_board_source_line_rerun",
        "sample_count": len(rows),
        "p0_sample_count": len([row for row in rows if row.get("id") in P0_SAMPLES]),
        "safe_surrogate_sample_count": len([row for row in rows if row.get("id") in SAFE_SURROGATE_SAMPLES]),
        "toolchain": {
            "docker_service": "linux-behavior",
            "compiler": read_first_line(toolchain_dir / "gcc.version.txt"),
            "qemu": read_first_line(toolchain_dir / "qemu.version.txt"),
            "strace": read_first_line(toolchain_dir / "strace.version.txt"),
            "addr2line": read_first_line(toolchain_dir / "addr2line.version.txt"),
            "readelf": read_first_line(toolchain_dir / "readelf.version.txt"),
        },
        "samples": rows,
        "future_external_artifact_contribution": {
            "debug_elf_manifest": "prepared",
            "readelf_debug_line_transcript": "prepared",
            "joined_trace_code_map_manifest": "local_code_maps_prepared",
            "board_capture_manifest": "not_prepared_external_board_rerun_required",
            "captured_elf_sha256_exact_match": "not_claimed_until_board_rerun",
        },
        "claim_boundary": {
            "debug_no_pie_elf_readiness_claimed": status == "PASS",
            "board_native_source_line_attribution_claimed": False,
            "captured_elf_sha256_exact_match": False,
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
            "uv run python tools/package_genesys2_debug_elf_readiness.py",
            "uv run python tools/check_genesys2_debug_elf_readiness.py --root .",
        ],
        "non_claims": [
            "This is debug/no-PIE ELF and local code-map readiness, not board-native source-line attribution.",
            "These ELFs are future board rerun candidates and are not claimed to match current captured board ELF hashes.",
            "Current board traces remain function-level unless rerun or rejoined against the exact captured DWARF ELF.",
            "This readiness artifact does not add real-malware validation.",
        ],
    }


def write_fixture_outputs(root: Path, build_root: Path) -> None:
    build_abs = repo_path(root, build_root)
    toolchain = build_abs / "toolchain"
    toolchain.mkdir(parents=True, exist_ok=True)
    for name, text in (
        ("gcc.version.txt", "riscv64-linux-gnu-gcc fixture\n"),
        ("qemu.version.txt", "qemu-riscv64 fixture\n"),
        ("strace.version.txt", "strace fixture\n"),
        ("addr2line.version.txt", "GNU addr2line fixture\n"),
        ("readelf.version.txt", "GNU readelf fixture\n"),
    ):
        (toolchain / name).write_text(text, encoding="utf-8", newline="\n")
    readelf_text = """
  [ 1] .text             PROGBITS         0000000000010100
  [ 2] .debug_info       PROGBITS         0000000000000000
  [ 3] .debug_line       PROGBITS         0000000000000000
"""
    for spec in sample_specs():
        sample_id = spec["id"]
        source_rel = Path(spec["source"])
        source = repo_path(root, source_rel)
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("int main(void) { return 0; }\n", encoding="utf-8", newline="\n")
        sample_dir = build_abs / sample_id
        code_map_dir = sample_dir / "code_map"
        code_map_dir.mkdir(parents=True, exist_ok=True)
        elf = sample_dir / f"{sample_id}.debug.riscv64"
        elf.write_bytes(b"\x7fELF fixture " + sample_id.encode("ascii"))
        (sample_dir / f"{sample_id}.readelf_sections.txt").write_text(readelf_text, encoding="utf-8", newline="\n")
        (sample_dir / f"{sample_id}.nm.txt").write_text("0000000000010100 T main\n", encoding="utf-8", newline="\n")
        write_json(
            code_map_dir / f"{sample_id}.code_map.json",
            {
                "schema": "rvmt.code_map.v1",
                "sample_id": sample_id,
                "source": source_rel.as_posix(),
                "binary_role": "debug_no_pie_board_rerun_candidate",
                "elf": repo_rel(root, elf),
                "sha256": sha256_file(elf),
                "source_locations": [
                    {
                        "pc": "0x0000000000010100",
                        "function": "main",
                        "file": source_rel.as_posix(),
                        "line": 1,
                        "confidence": "debug_info",
                    }
                ],
                "source_attribution": {
                    "function_level": "available",
                    "source_line_level": "available",
                    "source_line_basis": "DWARF line table via addr2line-compatible tool",
                    "source_location_count": 1,
                    "addr2line_tool": "/usr/bin/riscv64-linux-gnu-addr2line",
                },
            },
        )


def self_test() -> int:
    section_text = """
  [ 1] .text             PROGBITS         0000000000010100
  [ 2] .debug_info       PROGBITS         0000000000000000
  [ 3] .debug_line       PROGBITS         0000000000000000
"""
    if parse_debug_sections(section_text) != [".debug_info", ".debug_line"]:
        print("[FAIL] debug ELF readiness debug-section parser failed", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        current = root / DEFAULT_CURRENT_ROOT
        current.mkdir(parents=True, exist_ok=True)
        build_root = Path("build/debug_elf_readiness_fixture")
        write_fixture_outputs(root, build_root)
        summary = package_summary(root, current, build_root, None)
    if summary.get("status") != "PASS":
        print("[FAIL] debug ELF readiness fixture should pass", file=sys.stderr)
        print(json.dumps(summary, indent=2), file=sys.stderr)
        return 1
    if summary.get("claim_boundary", {}).get("board_native_source_line_attribution_claimed") is not False:
        print("[FAIL] debug ELF readiness fixture overclaims board-native source lines", file=sys.stderr)
        return 1
    print("[PASS] Genesys2 debug ELF readiness packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package debug/no-PIE ELF readiness for a future Genesys2/CVA6 board source-line rerun.")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--current-root", type=Path, default=DEFAULT_CURRENT_ROOT)
    parser.add_argument("--build-root", type=Path, default=DEFAULT_BUILD_ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    current_root = repo_path(root, args.current_root)
    out = repo_path(root, args.out)
    try:
        docker_result = run_docker_build(root, args.build_root)
        summary = package_summary(root, current_root, args.build_root, docker_result)
        write_json(out, summary)
    except Exception as exc:
        print(f"package_genesys2_debug_elf_readiness: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{summary['status']}] wrote Genesys2 debug ELF readiness to {out}")
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
