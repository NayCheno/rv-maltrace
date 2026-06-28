from __future__ import annotations

import argparse
import base64
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import official_image_evidence_common as common


ROOT = common.ROOT
SCHEMA = "rvmt.genesys2.official_image_aslr_pie.v1"
DEFAULT_RUN_ROOT = Path("results/board/genesys2_trace_validation/20260625-official-image-aslr-pie")
DEFAULT_OUT = common.CURRENT_ROOT / "official_image_aslr_pie_summary.json"
TARGETS = {
    "static_exec": "/tmp/rvmt_official/official_image_probe",
    "dynamic_pie": "/tmp/rvmt_official/official_image_probe_dynamic_pie",
}


def run(command: list[str], *, cwd: Path, dry_run: bool, allowed: set[int] | None = None) -> None:
    print("+ " + " ".join(command), flush=True)
    if dry_run:
        return
    completed = subprocess.run(command, cwd=cwd)
    if completed.returncode not in (allowed or {0}):
        raise subprocess.CalledProcessError(completed.returncode, command)


def sample_commands(variant: str, rep_name: str, target: str) -> list[str]:
    label = f"{variant}_{rep_name}"
    quoted = common.shell_quote(target)
    return [
        "rm -f /tmp/rvmt-map-ready-* /tmp/rvmt-map-continue-*; "
        f"{quoted} runtime-map 0 0 {label} & rvmt_pid=$!; "
        "for i in $(seq 1 80); do [ -e /tmp/rvmt-map-ready-$rvmt_pid ] && break; sleep 0.05; done; "
        f"echo RVMT_ASLR_SAMPLE_BEGIN variant={variant} rep={rep_name} pid=$rvmt_pid",
        "echo RVMT_ASLR_RANDOMIZE=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo NA)",
        "if [ -e /tmp/rvmt-map-ready-$rvmt_pid ]; then echo RVMT_PROC_SECTION_BEGIN maps; cat /proc/$rvmt_pid/maps 2>&1; echo RVMT_PROC_SECTION_END maps; else echo RVMT_ASLR_SAMPLE_BLOCKED reason=target_not_ready pid=$rvmt_pid; fi",
        "if [ -e /tmp/rvmt-map-ready-$rvmt_pid ]; then echo RVMT_PROC_SECTION_BEGIN exe; readlink /proc/$rvmt_pid/exe 2>&1; echo; sha256sum /proc/$rvmt_pid/exe 2>&1; echo RVMT_PROC_SECTION_END exe; fi",
        f"if [ -e /tmp/rvmt-map-ready-$rvmt_pid ]; then touch /tmp/rvmt-map-continue-$rvmt_pid; wait $rvmt_pid; rc=$?; else wait $rvmt_pid; rc=$?; fi; echo RVMT_ASLR_SAMPLE_DONE variant={variant} rep={rep_name} pid=$rvmt_pid rc=$rc",
    ]


def transfer_variant(args: argparse.Namespace, variant: str, target: str) -> None:
    row = common.variant_row(args.build_manifest, variant)
    binary = Path(str(row.get("binary") or ""))
    if not binary.is_file():
        return
    run(
        [
            sys.executable,
            "tools/serial_base64_transfer.py",
            "--port",
            args.port,
            "--baud",
            str(args.baud),
            "--source",
            str(binary),
            "--target",
            target,
            "--log",
            str(args.run_root / f"{variant}_transfer.log"),
            "--chunk-read",
            "0.25",
            "--final-read",
            "2.5",
            "--disable-echo",
        ],
        cwd=ROOT,
        dry_run=args.dry_run,
    )


def capture_sample(args: argparse.Namespace, variant: str, rep: int) -> None:
    rep_name = f"rep_{rep:02d}"
    rep_dir = args.run_root / variant / rep_name
    rep_dir.mkdir(parents=True, exist_ok=True)
    command = [
            sys.executable,
            "tools/serial_direct_command_capture.py",
            "--port",
            args.port,
            "--baud",
            str(args.baud),
            "--out",
            str(rep_dir / "uart.log"),
            "--pre-read",
            "0.1",
            "--post-read",
            str(args.post_read),
    ]
    for item in sample_commands(variant, rep_name, TARGETS[variant]):
        command.extend(["--command-b64", base64.b64encode(item.encode("utf-8")).decode("ascii")])
    run(
        command,
        cwd=ROOT,
        dry_run=args.dry_run,
    )


def parse_randomize(text: str) -> str | None:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("RVMT_ASLR_RANDOMIZE="):
            return stripped.split("=", 1)[1].strip()
    return None


def has_marker_line(text: str, marker: str) -> bool:
    return any(line.strip().startswith(marker) for line in text.splitlines())


def executable_base(maps: list[dict[str, Any]], target_hint: str) -> int | None:
    basename = Path(target_hint).name
    for row in maps:
        path = str(row.get("path") or "")
        perms = str(row.get("perms") or "")
        if "x" in perms and (basename in path or target_hint in path):
            return int(row["start"])
    return None


def package_sample(run_root: Path, variant: str, rep_dir: Path, build_manifest: Path) -> dict[str, Any]:
    log = rep_dir / "uart.log"
    text = log.read_text(encoding="utf-8", errors="replace") if log.is_file() else ""
    sections = common.extract_sections(text)
    snapshot_rows = common.write_section_files(run_root, rep_dir / "proc_snapshots", sections)
    maps = common.parse_maps(sections.get("maps", ""))
    base = executable_base(maps, TARGETS.get(variant, variant))
    done = common.parse_pid_kv(text, "RVMT_ASLR_SAMPLE_DONE")
    blocked = has_marker_line(text, "RVMT_ASLR_SAMPLE_BLOCKED")
    sha = common.parse_sha256_line(sections.get("exe", ""))
    expected = str(common.variant_row(build_manifest, variant).get("binary_sha256") or "")
    status = "PASS" if not blocked and done.get("rc") == 0 and base is not None and (not expected or sha == expected) else "BLOCKED_SAMPLE_NOT_EXECUTABLE"
    return {
        "rep": rep_dir.name,
        "status": status,
        "pid": done.get("pid"),
        "randomize_va_space": parse_randomize(text),
        "executable_base": f"0x{base:016x}" if base is not None else None,
        "executable_base_int": base,
        "map_entry_count": len(maps),
        "board_proc_exe_sha256": sha,
        "expected_sha256": expected or None,
        "hash_match": (sha == expected) if expected and sha else None,
        "blocked_reason": "target did not stay alive long enough for /proc map capture" if status != "PASS" else None,
        "artifacts": {"uart_log": common.file_row(log), "proc_snapshots": snapshot_rows},
    }


def package_summary(run_root: Path, out: Path, build_manifest: Path, repetitions: int) -> dict[str, Any]:
    samples: dict[str, list[dict[str, Any]]] = {}
    for variant in ("static_exec", "dynamic_pie"):
        rows: list[dict[str, Any]] = []
        for rep_dir in sorted((run_root / variant).glob("rep_*")):
            if rep_dir.is_dir():
                rows.append(package_sample(run_root, variant, rep_dir, build_manifest))
        samples[variant] = rows
    variant_summaries: dict[str, dict[str, Any]] = {}
    for variant, rows in samples.items():
        passed = [row for row in rows if row.get("status") == "PASS"]
        bases = sorted({int(row["executable_base_int"]) for row in passed if row.get("executable_base_int") is not None})
        variant_summaries[variant] = {
            "attempt_count": len(rows),
            "pass_count": len(passed),
            "unique_executable_bases": [f"0x{base:016x}" for base in bases],
            "unique_base_count": len(bases),
            "samples": rows,
        }
    build = common.load_json(build_manifest) if build_manifest.is_file() else {}
    static_ok = variant_summaries["static_exec"]["pass_count"] >= 2 and variant_summaries["static_exec"]["unique_base_count"] == 1
    dynamic_pass = variant_summaries["dynamic_pie"]["pass_count"] >= 2
    dynamic_varies = variant_summaries["dynamic_pie"]["unique_base_count"] > 1
    if static_ok and dynamic_pass and dynamic_varies:
        status = "PASS"
        blocked_reason = None
    elif static_ok and not dynamic_pass:
        status = "BLOCKED_DYNAMIC_PIE_RUNTIME_UNAVAILABLE"
        blocked_reason = "dynamic PIE build exists but did not execute on the official image long enough for repeated /proc map capture"
    elif static_ok:
        status = "BLOCKED_DYNAMIC_PIE_BASE_NOT_RANDOMIZED"
        blocked_reason = "dynamic PIE map captures did not show multiple executable bases"
    else:
        status = "BLOCKED_STATIC_EXEC_BASELINE_INCOMPLETE"
        blocked_reason = "static ET_EXEC baseline did not produce repeated fixed-base /proc map captures"
    summary = {
        "schema": SCHEMA,
        "status": status,
        "run_root": common.repo_rel(run_root),
        "repetitions_requested": repetitions,
        "aslr_policy_source": "/proc/sys/kernel/randomize_va_space on official SD image",
        "static_pie_build_status": (build.get("variants") or {}).get("static_pie", {}).get("status"),
        "variants": variant_summaries,
        "artifacts": {
            "build_manifest": common.file_row(build_manifest),
            "static_exec_transfer_log": common.file_row(run_root / "static_exec_transfer.log"),
            "dynamic_pie_transfer_log": common.file_row(run_root / "dynamic_pie_transfer.log"),
        },
        "blocked_reason": blocked_reason,
        "claim_boundary": {
            "aslr_dynamic_pie_board_claimed": status == "PASS",
            "static_exec_fixed_base_is_baseline_only": True,
            "static_pie_build_failure_not_promoted": (build.get("variants") or {}).get("static_pie", {}).get("status") == "BLOCKED_BUILD_FAILED",
            "qemu_or_strace_substitution_used": False,
            "cycle_level_overhead_claimed": False,
            "real_malware_validation_claimed": False,
        },
        "non_claims": [
            "Static ET_EXEC fixed-base observations are a baseline and are not treated as evidence that ASLR is disabled.",
            "Dynamic PIE claims require repeated board /proc map captures; failed dynamic execution is reported as BLOCKED.",
        ],
    }
    common.write_json(out, summary)
    return summary


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="rvmt-aslr-pie-") as tmp:
        root = Path(tmp)
        old_root = common.ROOT
        try:
            common.ROOT = root
            run_root = root / "run"
            build = root / "build.json"
            common.write_json(build, {"variants": {"static_exec": {"binary_sha256": "a" * 64}, "dynamic_pie": {"binary_sha256": "b" * 64}, "static_pie": {"status": "BLOCKED_BUILD_FAILED"}}})
            for variant, base, sha in (("static_exec", "00010000", "a" * 64), ("dynamic_pie", "40010000", "b" * 64), ("dynamic_pie", "50010000", "b" * 64), ("static_exec", "00010000", "a" * 64)):
                rep_count = len(list((run_root / variant).glob("rep_*"))) + 1
                rep = run_root / variant / f"rep_{rep_count:02d}"
                rep.mkdir(parents=True, exist_ok=True)
                rep.write_text if False else None
                (rep / "uart.log").write_text(
                    "RVMT_ASLR_RANDOMIZE=1\n"
                    f"RVMT_PROC_SECTION_BEGIN maps\n{base}-00020000 r-xp 0 00:01 1 {TARGETS[variant]}\nRVMT_PROC_SECTION_END maps\n"
                    f"RVMT_PROC_SECTION_BEGIN exe\n{TARGETS[variant]}\n{sha}  /proc/1/exe\nRVMT_PROC_SECTION_END exe\n"
                    "RVMT_ASLR_SAMPLE_DONE variant=x rep=y pid=1 rc=0\n",
                    encoding="utf-8",
                )
            echoed = run_root / "dynamic_pie" / "rep_03"
            echoed.mkdir(parents=True, exist_ok=True)
            (echoed / "uart.log").write_text(
                "RVMT_SEND 'else echo RVMT_ASLR_SAMPLE_BLOCKED reason=target_not_ready pid=$rvmt_pid; fi'\n"
                "RVMT_ASLR_RANDOMIZE=1\n"
                "RVMT_PROC_SECTION_BEGIN maps\n"
                "60010000-60020000 r-xp 0 00:01 1 /tmp/rvmt_official/official_image_probe_dynamic_pie\n"
                "RVMT_PROC_SECTION_END maps\n"
                f"RVMT_PROC_SECTION_BEGIN exe\n/tmp/rvmt_official/official_image_probe_dynamic_pie\n{'b' * 64}  /proc/1/exe\nRVMT_PROC_SECTION_END exe\n"
                "RVMT_ASLR_SAMPLE_DONE variant=x rep=y pid=1 rc=0\n",
                encoding="utf-8",
            )
            no_target = run_root / "static_exec" / "rep_03"
            no_target.mkdir(parents=True, exist_ok=True)
            (no_target / "uart.log").write_text(
                "RVMT_ASLR_RANDOMIZE=1\n"
                "RVMT_PROC_SECTION_BEGIN maps\n"
                "3fa2f29000-3fa2f2b000 r-xp 00000000 00:00 0 [vdso]\n"
                "RVMT_PROC_SECTION_END maps\n"
                f"RVMT_PROC_SECTION_BEGIN exe\n/tmp/rvmt_official/official_image_probe\n{'a' * 64}  /proc/1/exe\nRVMT_PROC_SECTION_END exe\n"
                "RVMT_ASLR_SAMPLE_DONE variant=x rep=y pid=1 rc=0\n",
                encoding="utf-8",
            )
            out = root / "summary.json"
            summary = package_summary(run_root, out, build, 2)
        finally:
            common.ROOT = old_root
    if summary.get("status") != "PASS":
        print("[FAIL] ASLR/PIE fixture did not pass", file=sys.stderr)
        return 1
    print("[PASS] official-image ASLR/PIE packager self-test")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run and package official-image ASLR/PIE map captures.")
    parser.add_argument("--port", default="COM7")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--run-root", type=Path, default=DEFAULT_RUN_ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--build-manifest", type=Path, default=common.DEFAULT_BUILD_MANIFEST)
    parser.add_argument("--repetitions", type=int, default=4)
    parser.add_argument("--post-read", type=float, default=8.0)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--skip-transfer", action="store_true")
    parser.add_argument("--skip-capture", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    args.run_root.mkdir(parents=True, exist_ok=True)
    if not args.skip_build:
        run([sys.executable, "tools/build_genesys2_official_image_probe.py"], cwd=ROOT, dry_run=args.dry_run)
    if not args.skip_transfer:
        for variant, target in TARGETS.items():
            transfer_variant(args, variant, target)
    if not args.skip_capture:
        for variant in TARGETS:
            for rep in range(1, args.repetitions + 1):
                capture_sample(args, variant, rep)
    if args.dry_run:
        return 0
    summary = package_summary(args.run_root, args.out, args.build_manifest, args.repetitions)
    print(f"[{summary['status']}] wrote {args.out}")
    return 0 if summary["status"] == "PASS" or str(summary["status"]).startswith("BLOCKED_") else 1


if __name__ == "__main__":
    raise SystemExit(main())
