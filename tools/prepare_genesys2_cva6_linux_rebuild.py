from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    repo_path,
    repo_rel,
    sha256_file,
    write_json,
)


ROOT = Path(__file__).resolve().parents[1]
SUMMARY_SCHEMA = "rvmt.genesys2.cva6_linux_rebuild.v1"
DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/linux_rebuild_manifest.json")
DEFAULT_WORK_DIR = Path("build/linux/genesys2-cva6")
DEFAULT_BUILDROOT_VERSION = "2026.02"
DEFAULT_BUILDROOT_URL = "https://buildroot.org/downloads/buildroot-2026.02.tar.gz"

REQUIRED_TOOLS = [
    "bash",
    "bc",
    "bison",
    "cpio",
    "file",
    "flex",
    "g++",
    "gcc",
    "git",
    "gzip",
    "make",
    "patch",
    "perl",
    "python3",
    "rsync",
    "sed",
    "tar",
    "unzip",
    "wget",
    "xzcat",
]

SOURCE_INPUTS = {
    "buildroot_defconfig": Path("board/genesys2-cva6/linux/buildroot_defconfig"),
    "linux_kernel_config": Path("board/genesys2-cva6/linux/linux.config"),
    "opensbi_manifest": Path("board/genesys2-cva6/linux/opensbi_manifest.json"),
    "opensbi_source_lock": Path("board/genesys2-cva6/linux/opensbi_source_lock.txt"),
    "device_tree_template": Path("rtl/cva6/corev_apu/fpga/src/bootrom/cv64a6.dts.in"),
}

PASS_PREPARED = "PASS_LINUX_REBUILD_PREPARED"
PASS_BUILT = "PASS_LINUX_PAYLOAD_BUILT"
BLOCKED_DEPS = "BLOCKED_LINUX_REBUILD_DEPS_MISSING"
BLOCKED_SOURCE = "BLOCKED_LINUX_REBUILD_SOURCE_FETCH_REQUIRED"
BLOCKED_COMMAND = "BLOCKED_LINUX_REBUILD_COMMAND_FAILED"
BLOCKED_OUTPUT = "BLOCKED_LINUX_PAYLOAD_BUILD_INCOMPLETE"



def hashed_file_row(root: Path, row_id: str, path: Path) -> dict[str, Any]:
    path = repo_path(root, path)
    row: dict[str, Any] = {
        "id": row_id,
        "path": repo_rel(root, path),
        "exists": path.is_file(),
    }
    if path.is_file():
        row["sha256"] = sha256_file(path)
        row["size_bytes"] = path.stat().st_size
    return row


def check_tools() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for tool in REQUIRED_TOOLS:
        resolved = shutil.which(tool)
        rows.append({"tool": tool, "available": resolved is not None, "path": resolved})
    return rows


def materialize_dts(root: Path, out_path: Path) -> None:
    template = repo_path(root, SOURCE_INPUTS["device_tree_template"])
    text = template.read_text(encoding="utf-8", errors="replace")
    replacements = {
        "DRAM_SIZE_64": "0x40000000",
        "HALF_CLOCK_FREQUENCY": "25000000",
        "CLOCK_FREQUENCY": "50000000",
        "UART_BITRATE": "115200",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    lines = [line for line in text.splitlines() if "DELETE_ETH" not in line]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def materialize_defconfig(root: Path, source: Path, out_path: Path, generated_dts: Path) -> None:
    text = repo_path(root, source).read_text(encoding="utf-8", errors="replace")
    root_posix = root.as_posix()
    dts_posix = generated_dts.as_posix()
    text = text.replace("$(RVMT_ROOT)", root_posix)
    text = text.replace("BR2_LINUX_KERNEL_INTREE_DTS_NAME=\"riscv/cv64a6\"", f"BR2_LINUX_KERNEL_CUSTOM_DTS_PATH=\"{dts_posix}\"")
    if "BR2_LINUX_KERNEL_USE_CUSTOM_DTS=y" not in text:
        text += "\nBR2_LINUX_KERNEL_USE_CUSTOM_DTS=y\n"
    # Keep the default payload build independent of the user-space Linux perf
    # tool. Kernel perf/counter support is controlled by linux.config and the
    # board-facing perf_event_open probes; Buildroot 2026.02's perf package can
    # fail in pmu-events generation before a boot payload is produced.
    if "BR2_TARGET_OPENSBI_INSTALL_PAYLOAD_IMG=y" not in text:
        text += "BR2_TARGET_OPENSBI_INSTALL_PAYLOAD_IMG=y\n"
    if "BR2_TARGET_OPENSBI_LINUX_PAYLOAD=y" not in text:
        text += "BR2_TARGET_OPENSBI_LINUX_PAYLOAD=y\n"
    if "BR2_PACKAGE_HOST_LINUX_HEADERS_CUSTOM_6_19=y" not in text:
        text += "BR2_PACKAGE_HOST_LINUX_HEADERS_CUSTOM_6_19=y\n"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text.rstrip() + "\n", encoding="utf-8", newline="\n")


def run_command(cmd: list[str], cwd: Path, env: dict[str, str]) -> dict[str, Any]:
    completed = subprocess.run(cmd, cwd=str(cwd), env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return {
        "command": cmd,
        "cwd": cwd.as_posix(),
        "returncode": completed.returncode,
        "output_tail": completed.stdout[-6000:],
    }


def fetch_buildroot(root: Path, work_dir: Path, version: str, url: str, expected_sha256: str | None, dry_run: bool) -> tuple[Path | None, list[dict[str, Any]], str | None]:
    source_dir = work_dir / f"buildroot-{version}"
    archive = work_dir / f"buildroot-{version}.tar.gz"
    commands: list[dict[str, Any]] = []
    if source_dir.is_dir():
        return source_dir, commands, None
    if dry_run:
        return None, commands, "dry-run did not fetch Buildroot source"
    work_dir.mkdir(parents=True, exist_ok=True)
    if not archive.is_file():
        row = run_command(["wget", "-O", str(archive), url], cwd=root, env=os.environ.copy())
        commands.append(row)
        if row["returncode"] != 0:
            return None, commands, "Buildroot download failed"
    if expected_sha256 and sha256_file(archive) != expected_sha256:
        return None, commands, "Buildroot archive sha256 mismatch"
    row = run_command(["tar", "-C", str(work_dir), "-xzf", str(archive)], cwd=root, env=os.environ.copy())
    commands.append(row)
    if row["returncode"] != 0:
        return None, commands, "Buildroot extraction failed"
    if not source_dir.is_dir():
        return None, commands, "Buildroot source directory was not created"
    return source_dir, commands, None


def collect_output_artifacts(root: Path, build_dir: Path, artifact_out_dir: Path) -> list[dict[str, Any]]:
    candidates = [
        ("fw_payload_bin", build_dir / "images/fw_payload.bin"),
        ("fw_payload_elf", build_dir / "images/fw_payload.elf"),
        ("linux_image", build_dir / "images/Image"),
        ("rootfs_ext2", build_dir / "images/rootfs.ext2"),
        ("rootfs_cpio", build_dir / "images/rootfs.cpio"),
        ("dtb_cv64a6", build_dir / "images/cv64a6.dtb"),
    ]
    rows: list[dict[str, Any]] = []
    artifact_out_dir.mkdir(parents=True, exist_ok=True)
    for row_id, path in candidates:
        if not path.is_file():
            continue
        copied = artifact_out_dir / path.name
        if path.resolve() != copied.resolve():
            shutil.copy2(path, copied)
        rows.append(hashed_file_row(root, row_id, copied))
    return rows


def summarize(
    root: Path,
    summary: Path,
    work_dir: Path,
    build_work_dir: Path | None,
    artifact_out_dir: Path | None,
    buildroot_version: str,
    buildroot_url: str,
    buildroot_sha256: str | None,
    *,
    fetch: bool,
    configure: bool,
    execute: bool,
    jobs: int,
    dry_run: bool,
    tool_rows_override: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    work_dir = repo_path(root, work_dir)
    build_work_dir = repo_path(root, build_work_dir) if build_work_dir is not None else work_dir
    artifact_out_dir = repo_path(root, artifact_out_dir) if artifact_out_dir is not None else work_dir / "images"
    summary = repo_path(root, summary)
    generated_dts = work_dir / "cv64a6.generated.dts"
    generated_defconfig = work_dir / "buildroot_defconfig.generated"
    build_dir = build_work_dir / "buildroot-output"
    command_log: list[dict[str, Any]] = []

    source_rows = [hashed_file_row(root, row_id, path) for row_id, path in SOURCE_INPUTS.items()]
    missing_inputs = [row["id"] for row in source_rows if not row["exists"]]
    tool_rows = tool_rows_override if tool_rows_override is not None else check_tools()
    missing_tools = [row["tool"] for row in tool_rows if not row["available"]]

    generated_rows: list[dict[str, Any]] = []
    if not missing_inputs:
        materialize_dts(root, generated_dts)
        materialize_defconfig(root, SOURCE_INPUTS["buildroot_defconfig"], generated_defconfig, generated_dts)
        generated_rows = [
            hashed_file_row(root, "generated_buildroot_defconfig", generated_defconfig),
            hashed_file_row(root, "generated_cv64a6_dts", generated_dts),
        ]

    source_dir: Path | None = None
    blocked_reason: str | None = None
    if missing_tools:
        blocked_reason = "Docker/container missing required Buildroot tools: " + ", ".join(missing_tools)
    elif missing_inputs:
        blocked_reason = "repo source inputs missing: " + ", ".join(missing_inputs)
    elif fetch or configure or execute:
        source_dir, fetch_log, fetch_error = fetch_buildroot(root, build_work_dir, buildroot_version, buildroot_url, buildroot_sha256, dry_run)
        command_log.extend(fetch_log)
        if fetch_error:
            blocked_reason = fetch_error
    else:
        candidate = build_work_dir / f"buildroot-{buildroot_version}"
        if candidate.is_dir():
            source_dir = candidate

    if blocked_reason is None and (configure or execute):
        if source_dir is None:
            blocked_reason = "Buildroot source is required; rerun with --fetch or pre-populate the source tree"
        elif not dry_run:
            env = os.environ.copy()
            env["RVMT_ROOT"] = root.as_posix()
            build_dir.mkdir(parents=True, exist_ok=True)
            command_log.append(
                run_command(
                    ["make", f"O={build_dir.as_posix()}", f"BR2_DEFCONFIG={generated_defconfig.as_posix()}", "defconfig"],
                    cwd=source_dir,
                    env=env,
                )
            )
            if command_log[-1]["returncode"] != 0:
                blocked_reason = "Buildroot defconfig command failed"
            elif execute:
                command_log.append(run_command(["make", f"O={build_dir.as_posix()}", f"-j{jobs}"], cwd=source_dir, env=env))
                if command_log[-1]["returncode"] != 0:
                    blocked_reason = "Buildroot full build command failed"

    output_artifacts = collect_output_artifacts(root, build_dir, artifact_out_dir)
    output_ids = {row["id"] for row in output_artifacts}
    if blocked_reason is not None:
        status = BLOCKED_DEPS if missing_tools else BLOCKED_COMMAND
        if "source is required" in blocked_reason or "download" in blocked_reason or "extraction" in blocked_reason:
            status = BLOCKED_SOURCE
    elif execute:
        status = PASS_BUILT if "fw_payload_bin" in output_ids else BLOCKED_OUTPUT
        if status == BLOCKED_OUTPUT:
            blocked_reason = "Buildroot finished/configured but fw_payload.bin was not found"
    else:
        status = PASS_PREPARED

    data: dict[str, Any] = {
        "schema": SUMMARY_SCHEMA,
        "status": status,
        "canonical_evaluation_root": "results/evaluation/genesys2-cva6/current",
        "source_inputs": source_rows,
        "generated_inputs": generated_rows,
        "container_tools": tool_rows,
        "buildroot": {
            "version": buildroot_version,
            "url": buildroot_url,
            "expected_sha256": buildroot_sha256,
            "source_dir": repo_rel(root, source_dir) if source_dir is not None else None,
            "fetch_requested": fetch,
            "configure_requested": configure,
            "execute_requested": execute,
            "repo_work_dir": repo_rel(root, work_dir),
            "build_work_dir": repo_rel(root, build_work_dir),
            "build_dir": repo_rel(root, build_dir),
            "artifact_out_dir": repo_rel(root, artifact_out_dir),
        },
        "output_artifacts": output_artifacts,
        "commands": command_log,
        "claim_boundary": {
            "docker_buildroot_preparation_executed": True,
            "buildroot_or_opensbi_compiled": status == PASS_BUILT,
            "boot_payload_built": status == PASS_BUILT,
            "sd_card_image_built": False,
            "genesys2_sd_card_written": False,
            "genesys2_board_booted_from_this_image": False,
            "live_kernel_config_export_claimed": False,
            "board_cycle_source_claimed": False,
            "qemu_or_strace_substitution_allowed": False,
        },
        "validation_commands": [
            "uv run rvmt ndss:linux-rebuild-prep",
            "uv run python tools/check_genesys2_linux_rebuild_manifest.py --root .",
            f"uv run rvmt ndss:boot-sdcard-image --payload {repo_rel(root, artifact_out_dir / 'fw_payload.bin')}",
            "uv run rvmt ndss:sdcard-linux-manifest --port COM7 --baud 115200",
            "uv run rvmt ndss:live-kernel-config-export --port COM7 --baud 115200",
            "uv run rvmt ndss:linux-counter-preflight",
        ],
        "non_claims": [
            "PASS_LINUX_REBUILD_PREPARED only means Docker dependencies, generated DTS, and generated Buildroot defconfig are ready.",
            "A boot payload claim requires an existing fw_payload.bin with SHA256 in output_artifacts.",
            "This manifest never claims that a physical SD card was written or booted on Genesys2.",
            "QEMU, strace, and local software checks remain oracle/sanity checks and cannot replace board evidence.",
        ],
    }
    if blocked_reason:
        data["blocked_reason"] = blocked_reason
    write_json(summary, data)
    return data


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="rvmt-linux-rebuild-") as tmp:
        root = Path(tmp)
        (root / "board/genesys2-cva6/linux").mkdir(parents=True)
        (root / "rtl/cva6/corev_apu/fpga/src/bootrom").mkdir(parents=True)
        (root / "board/genesys2-cva6/linux/buildroot_defconfig").write_text(
            "BR2_riscv=y\n"
            "BR2_LINUX_KERNEL=y\n"
            "BR2_LINUX_KERNEL_USE_CUSTOM_CONFIG=y\n"
            "BR2_LINUX_KERNEL_CUSTOM_CONFIG_FILE=\"$(RVMT_ROOT)/board/genesys2-cva6/linux/linux.config\"\n"
            "BR2_LINUX_KERNEL_DTS_SUPPORT=y\n"
            "BR2_LINUX_KERNEL_INTREE_DTS_NAME=\"riscv/cv64a6\"\n"
            "BR2_TARGET_OPENSBI=y\n",
            encoding="utf-8",
        )
        (root / "board/genesys2-cva6/linux/linux.config").write_text("CONFIG_PERF_EVENTS=y\n", encoding="utf-8")
        (root / "board/genesys2-cva6/linux/opensbi_manifest.json").write_text(
            json.dumps({"schema": "rvmt.genesys2.opensbi_source_manifest.v1"}) + "\n",
            encoding="utf-8",
        )
        (root / "board/genesys2-cva6/linux/opensbi_source_lock.txt").write_text("opensbi v1.7\n", encoding="utf-8")
        (root / "rtl/cva6/corev_apu/fpga/src/bootrom/cv64a6.dts.in").write_text(
            "/dts-v1/;\n/ { model = \"cv64a6\"; clock = <CLOCK_FREQUENCY>; };\n",
            encoding="utf-8",
        )
        summary = root / DEFAULT_SUMMARY
        data = summarize(
            root,
            summary,
            root / DEFAULT_WORK_DIR,
            None,
            None,
            DEFAULT_BUILDROOT_VERSION,
            DEFAULT_BUILDROOT_URL,
            None,
            fetch=False,
            configure=False,
            execute=False,
            jobs=1,
            dry_run=False,
            tool_rows_override=[{"tool": tool, "available": True, "path": f"/usr/bin/{tool}"} for tool in REQUIRED_TOOLS],
        )
        if data["status"] != PASS_PREPARED:
            print(f"[FAIL] expected {PASS_PREPARED}, got {data['status']}", file=sys.stderr)
            return 1
        generated = {row["id"]: row for row in data["generated_inputs"]}
        if "generated_buildroot_defconfig" not in generated or "generated_cv64a6_dts" not in generated:
            print("[FAIL] generated rows missing", file=sys.stderr)
            return 1
        gen_defconfig = root / generated["generated_buildroot_defconfig"]["path"]
        text = gen_defconfig.read_text(encoding="utf-8")
        if "$(RVMT_ROOT)" in text or "BR2_LINUX_KERNEL_USE_CUSTOM_DTS=y" not in text:
            print("[FAIL] generated defconfig did not materialize expected paths/options", file=sys.stderr)
            return 1
    print("[PASS] Genesys2/CVA6 Linux rebuild preparer self-test")
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prepare or execute the Docker-side Genesys2/CVA6 Buildroot/OpenSBI Linux rebuild.")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--work-dir", type=Path, default=DEFAULT_WORK_DIR)
    parser.add_argument("--build-work-dir", type=Path, help="Buildroot source/output directory. Use a Docker volume path for full builds.")
    parser.add_argument("--artifact-out-dir", type=Path, help="Repository-visible directory where selected build images are copied.")
    parser.add_argument("--buildroot-version", default=DEFAULT_BUILDROOT_VERSION)
    parser.add_argument("--buildroot-url", default=DEFAULT_BUILDROOT_URL)
    parser.add_argument("--buildroot-sha256")
    parser.add_argument("--fetch", action="store_true", help="Download/extract Buildroot if the source tree is absent.")
    parser.add_argument("--configure", action="store_true", help="Run Buildroot defconfig in the generated output directory.")
    parser.add_argument("--execute", action="store_true", help="Run the full Buildroot build. This is long-running.")
    parser.add_argument("--jobs", type=int, default=max(1, min(os.cpu_count() or 1, 8)))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    data = summarize(
        root,
        args.summary,
        args.work_dir,
        args.build_work_dir,
        args.artifact_out_dir,
        args.buildroot_version,
        args.buildroot_url,
        args.buildroot_sha256,
        fetch=args.fetch,
        configure=args.configure or args.execute,
        execute=args.execute,
        jobs=args.jobs,
        dry_run=args.dry_run,
    )
    print(json.dumps({"status": data["status"], "summary": data["canonical_evaluation_root"] + "/linux_rebuild_manifest.json"}, sort_keys=True))
    return 0 if data["status"].startswith("PASS") else 2


if __name__ == "__main__":
    raise SystemExit(main())
