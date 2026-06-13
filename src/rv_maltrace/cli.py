from __future__ import annotations

import argparse
import binascii
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path
from typing import Iterable

from rv_maltrace.trace_profiles import profile_names


BOARD_DEFAULTS = {
    "genesys2": ("xc7k325tffg900-2", "digilentinc.com:genesys2:part0:1.1"),
    "kc705": ("xc7k325tffg900-2", "xilinx.com:kc705:part0:1.5"),
    "vc707": ("xc7vx485tffg1761-2", "xilinx.com:vc707:part0:1.3"),
    "nexys_video": ("xc7a200tsbg484-1", "digilentinc.com:nexys_video:part0:1.1"),
}

XLNX_ILA_XCI = Path("corev_apu/fpga/xilinx/xlnx_ila/xlnx_ila.srcs/sources_1/ip/xlnx_ila/xlnx_ila.xci")
XLNX_ILA_EXPECTED = {
    "C_NUM_OF_PROBES": "3",
    "C_PROBE1_WIDTH": "136",
    "C_PROBE2_WIDTH": "716",
    "C_DATA_DEPTH": "8192",
    "C_INPUT_PIPE_STAGES": "2",
    "C_EN_STRG_QUAL": "1",
    "C_ADV_TRIGGER": "TRUE",
}
TRACE_MARKER_BUILD_MANIFEST = Path("work-fpga/rvmt_trace_marker_build_manifest.json")
TRACE_MARKER_SOURCE_HASH_FILES = {
    "rtl/cva6/corev_apu/fpga/src/ariane_xilinx.sv": ("cva6", "corev_apu/fpga/src/ariane_xilinx.sv"),
    "rtl/cva6/corev_apu/fpga/xilinx/xlnx_ila/tcl/run.tcl": ("cva6", "corev_apu/fpga/xilinx/xlnx_ila/tcl/run.tcl"),
    "rtl/trace/trace_pkg.sv": ("repo", "rtl/trace/trace_pkg.sv"),
    "rtl/trace/trace_filter.sv": ("repo", "rtl/trace/trace_filter.sv"),
    "rtl/trace/trace_bram_ring.sv": ("repo", "rtl/trace/trace_bram_ring.sv"),
    "rtl/trace/trace_uart_stream_sink.sv": ("repo", "rtl/trace/trace_uart_stream_sink.sv"),
    "rtl/trace/rvmt_genesys2_oled_status.sv": ("repo", "rtl/trace/rvmt_genesys2_oled_status.sv"),
    "rtl/trace/cva6_rvfi_trace_adapter.sv": ("repo", "rtl/trace/cva6_rvfi_trace_adapter.sv"),
    "tools/capture_genesys2_ila_event.tcl": ("repo", "tools/capture_genesys2_ila_event.tcl"),
    "tools/decode_genesys2_ila_trace.py": ("repo", "tools/decode_genesys2_ila_trace.py"),
    "tools/decode_genesys2_bram_ring_dump.py": ("repo", "tools/decode_genesys2_bram_ring_dump.py"),
    "tools/package_genesys2_bram_trace_sink_summary.py": ("repo", "tools/package_genesys2_bram_trace_sink_summary.py"),
    "tools/run_genesys2_ila_command_capture.py": ("repo", "tools/run_genesys2_ila_command_capture.py"),
}

TASK_ALIASES = {
    "help": "help",
    "docker": "docker:build",
    "docker:build": "docker:build",
    "image": "docker:build",
    "image:build": "docker:build",
    "tool": "toolchain:build",
    "tool:build": "toolchain:build",
    "toolchain": "toolchain:build",
    "toolchain:build": "toolchain:build",
    "bootrom": "bootrom:build",
    "bootrom:build": "bootrom:build",
    "bitstream": "bitstream:build",
    "bitstream:build": "bitstream:build",
    "bitstream:build-trace": "bitstream:build-trace",
    "bitstream:build-trace-marker": "bitstream:build-trace-marker",
    "bitstream:build-trace-source-lines": "bitstream:build-trace-source-lines",
    "bitstream:trace": "bitstream:build-trace",
    "bitstream:trace-marker": "bitstream:build-trace-marker",
    "bitstream:trace-source-lines": "bitstream:build-trace-source-lines",
    "bitstream:collect": "bitstream:collect",
    "fpga": "bitstream:build",
    "fpga:build": "bitstream:build",
    "fpga:build-trace": "bitstream:build-trace",
    "fpga:build-trace-marker": "bitstream:build-trace-marker",
    "fpga:build-trace-source-lines": "bitstream:build-trace-source-lines",
    "fpga:trace": "bitstream:build-trace",
    "fpga:trace-marker": "bitstream:build-trace-marker",
    "fpga:trace-source-lines": "bitstream:build-trace-source-lines",
    "vivado": "vivado:check",
    "vivado:check": "vivado:check",
    "vivado:project": "vivado:project",
    "vivado:xpr": "vivado:project",
    "board:artix7:jtag-scan": "board:artix7:jtag-scan",
    "board:artix7:led-build": "board:artix7:led-build",
    "board:artix7:led-load": "board:artix7:led-load",
    "board:artix7:litex-prep-docker": "board:artix7:litex-prep-docker",
    "board:artix7:litex-build": "board:artix7:litex-build",
    "board:artix7:litex-load": "board:artix7:litex-load",
    "board:artix7:serial-capture": "board:artix7:serial-capture",
    "board:artix7:baremetal-build": "board:artix7:baremetal-build",
    "board:artix7:baremetal-load": "board:artix7:baremetal-load",
    "board:artix7:baremetal-run": "board:artix7:baremetal-run",
    "board:artix7:linux-images-prep": "board:artix7:linux-images-prep",
    "board:artix7:linux-build": "board:artix7:linux-build",
    "board:artix7:linux-load": "board:artix7:linux-load",
    "board:artix7:linux-boot-capture": "board:artix7:linux-boot-capture",
    "board:artix7:trace-build": "board:artix7:trace-build",
    "board:artix7:trace-load": "board:artix7:trace-load",
    "board:artix7:trace-dump": "board:artix7:trace-dump",
    "board:artix7:trace-jsonl-compare": "board:artix7:trace-jsonl-compare",
    "artix7:jtag-scan": "board:artix7:jtag-scan",
    "artix7:led-build": "board:artix7:led-build",
    "artix7:led-load": "board:artix7:led-load",
    "artix7:litex-prep-docker": "board:artix7:litex-prep-docker",
    "artix7:litex-build": "board:artix7:litex-build",
    "artix7:litex-load": "board:artix7:litex-load",
    "artix7:serial-capture": "board:artix7:serial-capture",
    "artix7:baremetal-build": "board:artix7:baremetal-build",
    "artix7:baremetal-load": "board:artix7:baremetal-load",
    "artix7:baremetal-run": "board:artix7:baremetal-run",
    "artix7:linux-images-prep": "board:artix7:linux-images-prep",
    "artix7:linux-build": "board:artix7:linux-build",
    "artix7:linux-load": "board:artix7:linux-load",
    "artix7:linux-boot-capture": "board:artix7:linux-boot-capture",
    "artix7:trace-build": "board:artix7:trace-build",
    "artix7:trace-load": "board:artix7:trace-load",
    "artix7:trace-dump": "board:artix7:trace-dump",
    "artix7:trace-jsonl-compare": "board:artix7:trace-jsonl-compare",
    "sim": "sim:trace-unit",
    "sim:unit": "sim:trace-unit",
    "sim:trace": "sim:trace-unit",
    "sim:trace-unit": "sim:trace-unit",
    "sim:cva6": "sim:cva6-smoke",
    "sim:cva6-xsim": "sim:cva6-smoke",
    "sim:cva6-smoke": "sim:cva6-smoke",
    "sim:full-soc": "sim:cva6-full-soc",
    "sim:fullsoc": "sim:cva6-full-soc",
    "sim:cva6-full-soc": "sim:cva6-full-soc",
    "sim:cva6-full-soc-smoke": "sim:cva6-full-soc",
    "sim:cva6-full-soc-store": "sim:cva6-full-soc-store",
    "sim:cva6-full-soc-uart-store": "sim:cva6-full-soc-store",
    "sim:cva6-full-soc-tohost": "sim:cva6-full-soc-tohost",
    "sim:full-soc-tohost": "sim:cva6-full-soc-tohost",
    "sim:cva6-full-soc-rv64gc": "sim:cva6-full-soc-rv64gc",
    "sim:full-soc-rv64gc": "sim:cva6-full-soc-rv64gc",
    "sim:cva6-run": "sim:cva6-run",
    "sim:cva6-custom": "sim:cva6-run",
    "sim:run": "sim:cva6-run",
    "sim:summary": "sim:summary",
    "summary": "sim:summary",
    "baremetal": "baremetal:build",
    "baremetal:build": "baremetal:build",
    "programs": "baremetal:build",
    "programs:build": "baremetal:build",
    "demo": "demo:behavior",
    "demo:behavior": "demo:behavior",
    "demo:groundtruth": "demo:groundtruth",
    "exp:35t": "exp:35t",
    "experiment:35t": "exp:35t",
    "35t": "exp:35t",
    "run:35t": "exp:35t",
    "35t:run": "exp:35t",
    "explain:35t": "explain:35t",
    "35t:explain": "explain:35t",
    "sample:explain": "explain:35t",
    "config": "config:show",
    "config:show": "config:show",
    "tasks": "tasks:list",
    "tasks:list": "tasks:list",
    "completion": "completion:powershell",
    "completion:bash": "completion:bash",
    "completion:ps1": "completion:powershell",
    "completion:powershell": "completion:powershell",
    "completion:zsh": "completion:zsh",
}

DISPLAY_TASKS = [
    "docker:build",
    "toolchain:build",
    "bootrom:build",
    "vivado:check",
    "vivado:project",
    "board:artix7:jtag-scan",
    "board:artix7:led-build",
    "board:artix7:led-load",
    "board:artix7:litex-prep-docker",
    "board:artix7:litex-build",
    "board:artix7:litex-load",
    "board:artix7:serial-capture",
    "board:artix7:baremetal-build",
    "board:artix7:baremetal-load",
    "board:artix7:baremetal-run",
    "board:artix7:linux-images-prep",
    "board:artix7:linux-build",
    "board:artix7:linux-load",
    "board:artix7:linux-boot-capture",
    "board:artix7:trace-build",
    "board:artix7:trace-load",
    "board:artix7:trace-dump",
    "board:artix7:trace-jsonl-compare",
    "bitstream:build",
    "bitstream:build-trace",
    "bitstream:build-trace-marker",
    "bitstream:build-trace-source-lines",
    "bitstream:collect",
    "sim:trace-unit",
    "sim:cva6-smoke",
    "sim:cva6-full-soc",
    "sim:cva6-full-soc-store",
    "sim:cva6-full-soc-tohost",
    "sim:cva6-full-soc-rv64gc",
    "sim:cva6-run",
    "sim:summary",
    "baremetal:build",
    "demo:behavior",
    "demo:groundtruth",
    "exp:35t",
    "run:35t",
    "explain:35t",
    "config:show",
    "tasks:list",
    "completion:powershell",
    "completion:bash",
    "completion:zsh",
]

COMPLETION_CANDIDATES = sorted(
    {
        "--dry-run",
        "--asm",
        "--bin",
        "--cflag",
        "--elf",
        "--expected",
        "--help",
        "--include",
        "--linker",
        "--mem",
        "--name",
        "--backend",
        "--run-id",
        "--sample",
        "--stage",
        "--reps",
        "--no-runtime",
        "--out-dir",
        "--port",
        "--baud",
        "--board-step",
        "--duration",
        "--send",
        "--tool-mode",
        "--tool-prefix",
        "--trace",
        "--trace-profile",
        "--format",
        "--out",
        "--tee-out",
        "--strict",
        "--flow",
        "--detail",
        "--live-flow",
        "--flow-detail",
        "--include-extension-samples",
        "--trace-profile-policy",
        "--syscall-side-channel",
        "-h",
        "--runtime-order",
        "--warmup",
        "docker/tool/bootrom/bitstream",
        "docker/toolchain/bootrom/bitstream",
        "tool/bootrom/bitstream",
        *TASK_ALIASES.keys(),
        *DISPLAY_TASKS,
    }
)


class TaskError(RuntimeError):
    pass


def repo_root() -> Path:
    cwd = Path.cwd().resolve()
    for parent in [cwd, *cwd.parents]:
        candidate = parent / "pyproject.toml"
        if candidate.exists() and "rv-maltrace" in candidate.read_text(encoding="utf-8"):
            return parent

    here = Path(__file__).resolve()
    for parent in [here, *here.parents]:
        candidate = parent / "pyproject.toml"
        if candidate.exists() and "rv-maltrace" in candidate.read_text(encoding="utf-8"):
            return parent
    raise TaskError("Could not find pyproject.toml from rvmt package path.")


def load_config(root: Path) -> dict:
    data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    return data.get("tool", {}).get("rv-maltrace", {})


def as_posix_path(value: str | os.PathLike[str]) -> str:
    return str(value).replace("\\", "/")


def configured_path(root: Path, value: str, *, must_exist: bool = False) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = root / path
    if must_exist and not path.exists():
        raise TaskError(f"Configured path does not exist: {path}")
    return path


def configured_search_paths(root: Path, values: Iterable[str]) -> list[Path]:
    paths: list[Path] = []
    for value in values:
        path = Path(str(value))
        if not path.is_absolute():
            path = root / path
        paths.append(path)
    return paths


def resolve_executable(
    name_or_path: str,
    *,
    candidates: tuple[str, ...] = (),
    search_path: str | None = None,
) -> str:
    if any(sep in name_or_path for sep in ("/", "\\")):
        path = Path(name_or_path)
        if path.is_dir():
            for candidate in candidates:
                candidate_path = path / candidate
                if candidate_path.exists():
                    return str(candidate_path)
            suffix = ", ".join(candidates) if candidates else "an executable"
            raise TaskError(f"Configured directory does not contain {suffix}: {name_or_path}")
        if not path.exists() and path.suffix == "" and os.name == "nt":
            for suffix in (".exe", ".bat", ".cmd"):
                candidate_path = path.with_suffix(suffix)
                if candidate_path.exists():
                    return str(candidate_path)
        if not path.exists():
            raise TaskError(f"Configured executable does not exist: {name_or_path}")
        return str(path)

    resolved = shutil.which(name_or_path, path=search_path)
    if not resolved:
        raise TaskError(
            f"Executable '{name_or_path}' was not found in PATH. "
            "Set it in [tool.rv-maltrace] in pyproject.toml."
        )
    return resolved


def resolve_make(root: Path, config: dict) -> str:
    make_config = str(config.get("make", "make.exe"))
    make_paths = configured_search_paths(root, config.get("make_path_prepend", []))

    if any(sep in make_config for sep in ("/", "\\")):
        resolved = Path(resolve_executable(make_config)).resolve()
        if make_paths and resolved.parent not in {path.resolve() for path in make_paths}:
            allowed = os.pathsep.join(str(path) for path in make_paths)
            raise TaskError(
                f"Configured make is outside make_path_prepend: {resolved}. "
                f"Allowed make directories: {allowed}"
            )
        return str(resolved)

    if not make_paths:
        raise TaskError(
            "make_path_prepend must contain the MSYS bin directory. "
            "rvmt does not search the global PATH for make."
        )

    names = [make_config]
    if os.name == "nt" and Path(make_config).suffix == "":
        names.extend(f"{make_config}{suffix}" for suffix in (".exe", ".bat", ".cmd"))

    for directory in make_paths:
        for name in names:
            candidate = directory / name
            if candidate.exists():
                return str(candidate.resolve())

    searched = os.pathsep.join(str(path) for path in make_paths)
    raise TaskError(f"make '{make_config}' was not found in make_path_prepend: {searched}")


def resolve_vivado(config: dict) -> str:
    vivado_config = str(config.get("vivado", "vivado"))
    return resolve_executable(vivado_config, candidates=("vivado.bat", "vivado.exe", "vivado"))


def xilinx_settings(config: dict) -> tuple[str, str]:
    board = str(config.get("board", "genesys2"))
    part, board_part = BOARD_DEFAULTS.get(board, ("", ""))
    part = str(config.get("xilinx_part", part))
    board_part = str(config.get("xilinx_board", board_part))
    if not part or not board_part:
        raise TaskError(
            f"No Xilinx part mapping for board '{board}'. "
            "Set xilinx_part and xilinx_board in [tool.rv-maltrace]."
        )
    return part, board_part


def xci_config_value(text: str, key: str) -> str | None:
    match = re.search(rf'"{re.escape(key)}"\s*:\s*\[\s*\{{\s*"value"\s*:\s*"([^"]+)"', text)
    return match.group(1) if match else None


def check_xlnx_ila_xci(cva6_dir: Path, xci: Path | None = None) -> None:
    xci = xci or (cva6_dir / XLNX_ILA_XCI)
    if not xci.is_file():
        raise TaskError(f"Missing ILA XCI after refresh: {xci}")
    text = xci.read_text(encoding="utf-8", errors="replace")
    mismatches: list[str] = []
    for key, expected in XLNX_ILA_EXPECTED.items():
        actual = xci_config_value(text, key)
        if actual is None or actual.upper() != expected.upper():
            mismatches.append(f"{key}={actual or 'MISSING'} expected {expected}")
    if mismatches:
        joined = "; ".join(mismatches)
        raise TaskError(f"ILA XCI is not configured for marker-scope evidence capture: {joined}")


def sync_xlnx_ila_artifact_xci(cva6_dir: Path, vivado_work_dir: Path, *, dry_run: bool) -> None:
    source = cva6_dir / XLNX_ILA_XCI
    target = vivado_work_dir / "xlnx_ila.xci"
    if dry_run:
        print(f"+ copy {quote_for_display(str(source))} {quote_for_display(str(target))}")
        return
    check_xlnx_ila_xci(cva6_dir, source)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    check_xlnx_ila_xci(cva6_dir, target)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def trace_marker_source_hashes(source_root: Path, cva6_dir: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for manifest_path, (base, source_path) in TRACE_MARKER_SOURCE_HASH_FILES.items():
        full_path = (cva6_dir if base == "cva6" else source_root) / source_path
        if not full_path.is_file():
            raise TaskError(f"Missing trace-marker manifest source file: {full_path}")
        hashes[manifest_path] = sha256_file(full_path)
    return hashes


def refresh_xlnx_ila_ip(
    cva6_dir: Path,
    env: dict[str, str],
    vivado: str,
    xpart: str,
    xboard: str,
    dry_run: bool,
) -> None:
    ila_dir = cva6_dir / "corev_apu" / "fpga" / "xilinx" / "xlnx_ila"
    script = ila_dir / "tcl" / "run.tcl"
    if not dry_run and not script.is_file():
        raise TaskError(f"Missing ILA generator script: {script}")
    refresh_env = prepend_env_path(env, Path(vivado).parent)
    refresh_env = refresh_env.copy()
    refresh_env["XILINX_PART"] = xpart
    refresh_env["XILINX_BOARD"] = xboard
    run(
        [vivado, "-mode", "batch", "-nojournal", "-nolog", "-notrace", "-source", "tcl/run.tcl"],
        cwd=ila_dir,
        env=refresh_env,
        dry_run=dry_run,
    )
    if not dry_run:
        check_xlnx_ila_xci(cva6_dir)


def write_trace_marker_build_manifest(
    artifact_dir: Path,
    *,
    source_root: Path,
    cva6_dir: Path,
    board: str,
    target: str,
    xpart: str,
    xboard: str,
    verilog_defines: list[str],
) -> None:
    manifest = {
        "schema": "rvmt.trace_marker_build_manifest.v1",
        "board": board,
        "target": target,
        "xilinx_part": xpart,
        "xilinx_board": xboard,
        "trace_enabled": "RV_MALTRACE_FPGA_TRACE" in verilog_defines,
        "trace_marker_scope": "RV_MALTRACE_FPGA_TRACE_MARKER_SCOPE" in verilog_defines,
        "trace_source_line_profile": "RV_MALTRACE_FPGA_TRACE_SOURCE_LINES" in verilog_defines,
        "verilog_defines": verilog_defines,
        "ila_expected": XLNX_ILA_EXPECTED,
        "marker_scope_policy": {
            "enable_marker": True,
            "enable_retire": False,
            "enable_branch": False,
            "enable_jump": False,
            "enable_syscall": True,
            "enable_trap": True,
            "enable_context": True,
            "pc_filter": (
                "0x0000000000010500..0x0000000000010700"
                if "RV_MALTRACE_FPGA_TRACE_SOURCE_LINES" in verilog_defines
                else "disabled"
            ),
            "reason": (
                "source-line profile keeps marker control and filters syscall/trap/context events to no-PIE target source PCs"
                if "RV_MALTRACE_FPGA_TRACE_SOURCE_LINES" in verilog_defines
                else "keep event-limited ILA windows focused on marker/syscall/trap evidence"
            ),
        },
        "source_hashes": {
            "hash_algorithm": "sha256",
            "files": trace_marker_source_hashes(source_root, cva6_dir),
        },
    }
    path = artifact_dir / TRACE_MARKER_BUILD_MANIFEST
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def vivado_board_repo_paths(root: Path, config: dict) -> list[Path]:
    return configured_search_paths(root, config.get("vivado_board_repo_paths", []))


def normalize_windows_path(value: str | os.PathLike[str]) -> str:
    return os.path.normcase(os.path.normpath(str(value)))


def current_subst_mappings() -> dict[str, str]:
    if os.name != "nt":
        return {}
    completed = subprocess.run(
        ["subst"],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
    )
    mappings: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        if "=>" not in line:
            continue
        drive, target = line.split("=>", 1)
        drive = drive.strip().upper()
        if len(drive) >= 2 and drive[1] == ":":
            mappings[drive[:2]] = target.strip()
    return mappings


def vivado_subst_drive(config: dict) -> str | None:
    drive = str(config.get("vivado_subst_drive", "")).strip()
    if not drive:
        return None
    if os.name != "nt":
        raise TaskError("vivado_subst_drive is only supported on Windows.")

    drive = drive.rstrip("\\/")
    if not drive.endswith(":"):
        drive = f"{drive}:"
    return drive.upper()


def release_subst_mapping(drive: str, root: Path) -> None:
    existing = current_subst_mappings().get(drive)
    if not existing:
        return
    if normalize_windows_path(existing) != normalize_windows_path(root):
        print(f"rvmt: warning: not releasing {drive}; it now maps to {existing}", file=sys.stderr)
        return

    completed = subprocess.run(["subst", drive, "/D"], capture_output=True, encoding="utf-8", errors="replace")
    if completed.returncode:
        message = (completed.stderr or completed.stdout).strip()
        print(f"rvmt: warning: failed to release {drive}: {message}", file=sys.stderr)


def make_vivado_project_portable(project: Path, work_root: Path, real_root: Path) -> None:
    if not project.exists():
        return
    work_prefix = as_posix_path(work_root).rstrip("/")
    real_prefix = as_posix_path(real_root).rstrip("/")
    text = project.read_text(encoding="utf-8")
    text = text.replace(work_prefix, real_prefix)
    text = text.replace(work_prefix.lower(), real_prefix)
    project.write_text(text, encoding="utf-8", newline="\n")


def safe_artifact_segment(value: str) -> str:
    segment = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in value)
    segment = segment.strip("._-")
    return segment or "default"


def vivado_artifact_dir(root: Path, config: dict) -> Path:
    override = config.get("vivado_artifact_dir")
    if override:
        return configured_path(root, str(override))

    build_dir = configured_path(root, str(config.get("build_dir", "build")))
    board = safe_artifact_segment(str(config.get("board", "genesys2")))
    target = safe_artifact_segment(str(config.get("target", "cv64a6_imafdc_sv39")))
    return build_dir / "vivado" / f"{board}-{target}"


def trace_vivado_artifact_dir(root: Path, config: dict) -> Path:
    base = vivado_artifact_dir(root, config)
    return base.with_name(f"{base.name}-trace")


def trace_marker_vivado_artifact_dir(root: Path, config: dict) -> Path:
    base = vivado_artifact_dir(root, config)
    return base.with_name(f"{base.name}-trace-marker")


def trace_source_lines_vivado_artifact_dir(root: Path, config: dict) -> Path:
    base = vivado_artifact_dir(root, config)
    return base.with_name(f"{base.name}-trace-source-lines")


def vivado_project_dir(root: Path, config: dict) -> Path:
    override = config.get("vivado_project_dir")
    if override:
        return configured_path(root, str(override))
    return vivado_artifact_dir(root, config) / "project"


def vivado_project_xpr(root: Path, config: dict) -> Path:
    return vivado_project_dir(root, config) / "ariane.xpr"


def makefile_relative_path(path: Path, start: Path) -> str:
    try:
        return as_posix_path(os.path.relpath(path, start))
    except ValueError as exc:
        raise TaskError(f"{path} must be on the same drive as {start}.") from exc


VIVADO_WORK_PATTERNS = (
    "*.bit",
    "*.bin",
    "*.mcs",
    "*.ltx",
    "*.dcp",
    "*.rpt",
    "*.rpx",
    "*.pb",
    "*.prm",
    "*.tcl",
    "*.vdi",
    "*.xci",
    "*.sdf",
    "*.v",
)


def copy_matching_files(source_dir: Path, target_dir: Path, patterns: Iterable[str]) -> list[Path]:
    if not source_dir.exists():
        return []

    target_dir.mkdir(parents=True, exist_ok=True)
    copied: list[Path] = []
    for pattern in patterns:
        for source in source_dir.glob(pattern):
            if not source.is_file():
                continue
            target = target_dir / source.name
            if source.resolve() == target.resolve():
                continue
            shutil.copy2(source, target)
            copied.append(target)
    return copied


def seed_existing_vivado_artifacts(fpga_dir: Path, artifact_dir: Path) -> None:
    artifact_work_dir = artifact_dir / "work-fpga"
    if not (artifact_work_dir / "ariane_xilinx.bit").exists():
        copy_matching_files(fpga_dir / "work-fpga", artifact_work_dir, VIVADO_WORK_PATTERNS)

    artifact_report_dir = artifact_dir / "reports"
    if not artifact_report_dir.exists():
        copy_matching_files(fpga_dir / "reports", artifact_report_dir, ("*.rpt", "*.rpx", "*.pb"))


def collect_vivado_artifacts(fpga_dir: Path, artifact_dir: Path) -> list[Path]:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    copied = []
    copied.extend(copy_matching_files(fpga_dir / "work-fpga", artifact_dir / "work-fpga", VIVADO_WORK_PATTERNS))
    copied.extend(copy_matching_files(fpga_dir / "reports", artifact_dir / "reports", ("*.rpt", "*.rpx", "*.pb")))
    return copied


def print_vivado_artifact_summary(artifact_dir: Path) -> None:
    print(f"Vivado artifacts: {artifact_dir}")
    for label, path in (
        ("bitstream", artifact_dir / "work-fpga" / "ariane_xilinx.bit"),
        ("flash image", artifact_dir / "work-fpga" / "ariane_xilinx.mcs"),
        ("timing report", artifact_dir / "reports" / "ariane.timing.rpt"),
        ("utilization report", artifact_dir / "reports" / "ariane.utilization.rpt"),
    ):
        if path.exists():
            print(f"  {label}: {path}")


def vivado_work_root(root: Path, config: dict, *, dry_run: bool) -> Path:
    drive = vivado_subst_drive(config)
    if not drive:
        return root

    drive_root = Path(f"{drive}\\")

    if dry_run:
        return drive_root

    root_text = str(root)
    mappings = current_subst_mappings()
    existing = mappings.get(drive)
    if existing:
        if normalize_windows_path(existing) != normalize_windows_path(root_text):
            raise TaskError(f"{drive} is already mapped to {existing}, not {root_text}.")
    else:
        completed = subprocess.run(["subst", drive, root_text])
        if completed.returncode:
            raise TaskError(f"Failed to create subst mapping {drive} => {root_text}.")

    if not drive_root.exists():
        raise TaskError(f"subst mapping did not create an accessible drive: {drive_root}")
    return drive_root


def vivado_shell_entry(vivado: str) -> str:
    path = Path(vivado)
    if path.name.lower() == "vivado.bat":
        shell_script = path.with_suffix("")
        if shell_script.exists():
            return str(shell_script)
    return vivado


def prepare_msys_python_wrapper(root: Path) -> Path:
    wrapper_dir = root / ".rvmt" / "bin"
    wrapper_dir.mkdir(parents=True, exist_ok=True)
    real_python = shell_single_quoted(as_posix_path(sys.executable))
    for name in ("python3", "python"):
        wrapper = wrapper_dir / name
        wrapper.write_text(
            f"""#!/usr/bin/env bash
exec {real_python} "$@"
""",
            encoding="utf-8",
            newline="\n",
        )
        os.chmod(wrapper, 0o755)
    return wrapper_dir


def prepare_vivado_wrapper(root: Path, config: dict, vivado: str) -> str:
    repo_paths = vivado_board_repo_paths(root, config)
    wrapper_dir = root / ".rvmt" / "bin"
    wrapper_dir.mkdir(parents=True, exist_ok=True)
    wrapper = wrapper_dir / "vivado"
    real_vivado = as_posix_path(vivado_shell_entry(vivado))
    repo_args = " ".join(f"'{as_posix_path(path)}'" for path in repo_paths)
    wrapper.write_text(
        f"""#!/usr/bin/env bash
set -euo pipefail

real_vivado='{real_vivado}'
target_cfg='{str(config.get("target", "cv64a6_imafdc_sv39"))}'
board_repo_paths=({repo_args})
args=()
tmp_files=()

normalize_msys_paths() {{
  local file="scripts/add_sources.tcl"
  [[ -f "$file" ]] || return 0

  local tmp_file="${{file}}.rvmt"
  local sed_args=("-e" "/read_verilog[[:space:]]*-sv[[:space:]]*{{[[:space:]]*}}/d")
  local pair lower upper
  for pair in a:A b:B c:C d:D e:E f:F g:G h:H i:I j:J k:K l:L m:M n:N o:O p:P q:Q r:R s:S t:T u:U v:V w:W x:X y:Y z:Z; do
    lower="${{pair%:*}}"
    upper="${{pair#*:}}"
    sed_args+=("-e" "s#/${{lower}}/#${{upper}}:/#g")
  done
  local dedup_pattern
  local dedup_patterns=(
    'core/cvfpu/src/fpnew_pkg\\.sv'
    'core/include/config_pkg\\.sv'
    'core/include/[^[:space:]{{}}]*_config_pkg\\.sv'
    'core/include/riscv_pkg\\.sv'
    'core/include/ariane_pkg\\.sv'
    'vendor/pulp-platform/axi/src/axi_pkg\\.sv'
    'core/include/wt_cache_pkg\\.sv'
    'core/include/std_cache_pkg\\.sv'
    'core/include/instr_tracer_pkg\\.sv'
    'core/include/build_config_pkg\\.sv'
    'core/include/aes_pkg\\.sv'
    'core/include/triggers_pkg\\.sv'
    'core/cache_subsystem/axi_adapter\\.sv'
    'common/local/util/instr_tracer\\.sv'
    'common/local/util/tc_sram_wrapper\\.sv'
    'vendor/pulp-platform/tech_cells_generic/src/rtl/tc_sram\\.sv'
    'core/cache_subsystem/hpdcache/rtl/src/common/macros/behav/hpdcache_sram_1rw\\.sv'
    'core/cache_subsystem/hpdcache/rtl/src/common/macros/behav/hpdcache_sram_wbyteenable_1rw\\.sv'
    'core/cache_subsystem/hpdcache/rtl/src/common/macros/behav/hpdcache_sram_wmask_1rw\\.sv'
    'vendor/pulp-platform/common_cells/src/cf_math_pkg\\.sv'
    'vendor/pulp-platform/common_cells/src/delta_counter\\.sv'
    'vendor/pulp-platform/common_cells/src/rr_arb_tree\\.sv'
  )
  for dedup_pattern in "${{dedup_patterns[@]}}"; do
    sed_args+=("-e" "s#[^[:space:]{{}}]*${{dedup_pattern}}[[:space:]]*##g")
  done
  sed_args+=("-e" "/read_verilog[[:space:]]*-sv[[:space:]]*{{[[:space:]]*}}/d")
  sed "${{sed_args[@]}}" "$file" > "$tmp_file"
  mv "$tmp_file" "$file"

  if grep -q "ariane_axi_pkg.sv\\|common_cells/src/addr_decode.sv" "$file"; then
    tmp_file="${{file}}.rvmt"
    {{
      echo "read_verilog -sv {{../../core/cvfpu/src/fpnew_pkg.sv}}"
      echo "read_verilog -sv {{../../core/include/config_pkg.sv}}"
      echo "read_verilog -sv {{../../core/include/${{target_cfg}}_config_pkg.sv}}"
      echo "read_verilog -sv {{../../core/include/riscv_pkg.sv}}"
      echo "read_verilog -sv {{../../core/include/ariane_pkg.sv}}"
      echo "read_verilog -sv {{../../vendor/pulp-platform/axi/src/axi_pkg.sv}}"
      echo "read_verilog -sv {{../../core/include/wt_cache_pkg.sv}}"
      echo "read_verilog -sv {{../../core/include/std_cache_pkg.sv}}"
      echo "read_verilog -sv {{../../core/include/instr_tracer_pkg.sv}}"
      echo "read_verilog -sv {{../../core/include/build_config_pkg.sv}}"
      echo "read_verilog -sv {{../../core/include/aes_pkg.sv}}"
      echo "read_verilog -sv {{../../core/include/triggers_pkg.sv}}"
      echo "read_verilog -sv {{../../core/cache_subsystem/axi_adapter.sv}}"
      echo "read_verilog -sv {{../../vendor/pulp-platform/common_cells/src/cf_math_pkg.sv}}"
      echo "read_verilog -sv {{../../vendor/pulp-platform/common_cells/src/delta_counter.sv}}"
      echo "read_verilog -sv {{../../vendor/pulp-platform/common_cells/src/rr_arb_tree.sv}}"
      cat "$file"
    }} > "$tmp_file"
    mv "$tmp_file" "$file"
  fi

  if ! grep -q "R:/rtl/trace/rvmt_genesys2_oled_status.sv" "$file"; then
    echo "read_verilog -sv {{R:/rtl/trace/rvmt_genesys2_oled_status.sv}}" >> "$file"
  fi

  if [[ "${{RV_MALTRACE_FPGA_TRACE:-0}}" == "1" || "${{RVMT_VIVADO_VERILOG_DEFINES:-}}" == *"RV_MALTRACE_FPGA_TRACE"* ]]; then
    if grep -q "R:/rtl/trace/trace_board_minimal_ctrl.sv" "$file" && ! grep -q "R:/rtl/trace/trace_bram_ring.sv" "$file"; then
      tmp_file="${{file}}.rvmt"
      sed "s#R:/rtl/trace/trace_board_minimal_ctrl\\.sv[[:space:]]*#R:/rtl/trace/trace_board_minimal_ctrl.sv R:/rtl/trace/trace_bram_ring.sv #g" "$file" > "$tmp_file"
      mv "$tmp_file" "$file"
    fi
    if grep -q "R:/rtl/trace/trace_bram_ring.sv" "$file" && ! grep -q "R:/rtl/trace/trace_uart_stream_sink.sv" "$file"; then
      tmp_file="${{file}}.rvmt"
      sed "s#R:/rtl/trace/trace_bram_ring\\.sv[[:space:]]*#R:/rtl/trace/trace_bram_ring.sv R:/rtl/trace/trace_uart_stream_sink.sv #g" "$file" > "$tmp_file"
      mv "$tmp_file" "$file"
    fi
  fi

  chmod u+w "$file" 2>/dev/null || true
}}

cleanup() {{
  for file in "${{tmp_files[@]}}"; do
    rm -f "$file"
  done
}}
trap cleanup EXIT

while (($#)); do
  if [[ "$1" == "-source" && $# -ge 2 ]]; then
    src="$2"
    source_to_run="$src"
    if [[ "$src" == "scripts/run.tcl" && -f "$src" ]]; then
      patch_dir="${{RVMT_VIVADO_PATCH_DIR:-${{RVMT_VIVADO_WORK_DIR:-work-fpga}}}}"
      mkdir -p "$patch_dir"
      patched_src="$patch_dir/rvmt-vivado-run-$$-${{#tmp_files[@]}}.tcl"
      {{
        cat <<'RVMT_TCL'
if {{[info exists ::env(RVMT_VIVADO_REPORT_DIR)]}} {{
  set rvmt_report_dir $::env(RVMT_VIVADO_REPORT_DIR)
}} else {{
  set rvmt_report_dir reports
}}
file mkdir $rvmt_report_dir
if {{[info exists ::env(RVMT_VIVADO_WORK_DIR)]}} {{
  set rvmt_work_dir $::env(RVMT_VIVADO_WORK_DIR)
}} else {{
  set rvmt_work_dir work-fpga
}}
file mkdir $rvmt_work_dir
RVMT_TCL
        sed -E \\
          -e 's#exec[[:space:]]+mkdir[[:space:]]+-p[[:space:]]+reports/#file mkdir ${{rvmt_report_dir}}#g' \\
          -e 's#exec[[:space:]]+rm[[:space:]]+-rf[[:space:]]+reports/\\*#file delete -force {{*}}[glob -nocomplain ${{rvmt_report_dir}}/*]#g' \\
          -e 's#reports/#${{rvmt_report_dir}}/#g' \\
          -e 's#work-fpga/#${{rvmt_work_dir}}/#g' \\
          "$src"
      }} > "$patched_src"
      tmp_files+=("$patched_src")
      source_to_run="$patched_src"
    fi
    tmp="${{TMPDIR:-/tmp}}/rvmt-vivado-$$-${{#tmp_files[@]}}.tcl"
    {{
      printf 'set_param board.repoPaths [list'
      for repo in "${{board_repo_paths[@]}}"; do
        printf ' {{%s}}' "$repo"
      done
      printf ']\\n'
      printf 'source {{%s}}\\n' "$source_to_run"
    }} > "$tmp"
    tmp_files+=("$tmp")
    args+=("-source" "$tmp")
    shift 2
  else
    args+=("$1")
    shift
  fi
done

normalize_msys_paths
"$real_vivado" "${{args[@]}}"
""",
        encoding="utf-8",
        newline="\n",
    )
    os.chmod(wrapper, 0o755)
    return str(wrapper)


def task_list(raw_tasks: Iterable[str]) -> list[str]:
    tasks: list[str] = []
    for raw in raw_tasks:
        for part in raw.split("/"):
            part = part.strip()
            if not part:
                continue
            canonical = TASK_ALIASES.get(part)
            if not canonical:
                known = ", ".join(sorted(TASK_ALIASES))
                raise TaskError(f"Unknown task '{part}'. Known tasks: {known}")
            tasks.append(canonical)
    return tasks


def print_task_list() -> None:
    for task in DISPLAY_TASKS:
        print(task)


def merged_env(config: dict) -> dict[str, str]:
    env = os.environ.copy()
    for key, value in config.get("env", {}).items():
        env[str(key)] = str(value)
    prepend = [str(item) for item in config.get("make_path_prepend", [])]
    if prepend:
        env["PATH"] = os.pathsep.join([*prepend, env.get("PATH", "")])
    return env


def prepend_env_path(env: dict[str, str], *paths: str | os.PathLike[str]) -> dict[str, str]:
    env = env.copy()
    existing = env.get("PATH", "")
    prepend = [str(path) for path in paths if str(path)]
    if prepend:
        env["PATH"] = os.pathsep.join([*prepend, existing])
    return env


def run(cmd: list[str], *, cwd: Path, env: dict[str, str], dry_run: bool) -> None:
    printable = " ".join(quote_for_display(part) for part in cmd)
    print(f"+ {printable}")
    if dry_run:
        return

    completed = subprocess.run(cmd, cwd=str(cwd), env=env)
    if completed.returncode:
        raise TaskError(f"Command failed with exit code {completed.returncode}: {printable}")


def run_capture(
    cmd: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    dry_run: bool,
    log_path: Path,
) -> str:
    printable = " ".join(quote_for_display(part) for part in cmd)
    print(f"+ {printable} > {quote_for_display(str(log_path))}")
    if dry_run:
        return ""

    log_path.parent.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
    )
    output = "\n".join(part for part in (completed.stdout, completed.stderr) if part)
    log_path.write_text(output, encoding="utf-8", newline="\n")
    if completed.returncode:
        raise TaskError(f"Command failed with exit code {completed.returncode}: {printable}. See {log_path}")
    return output


def quote_for_display(value: str) -> str:
    if not value or any(ch.isspace() for ch in value):
        return f'"{value}"'
    return value


def docker_compose_base(config: dict) -> list[str]:
    docker = resolve_executable(str(config.get("docker", "docker")))
    compose_file = str(config.get("docker_compose_file", "docker-compose.toolchain.yml"))
    return [docker, "compose", "-f", compose_file]


def task_docker_build(root: Path, config: dict, env: dict[str, str], dry_run: bool) -> None:
    run([*docker_compose_base(config), "build"], cwd=root, env=env, dry_run=dry_run)


def task_toolchain_build(root: Path, config: dict, env: dict[str, str], dry_run: bool) -> None:
    env = env.copy()
    env.setdefault("TOOLCHAIN_CONFIG", str(config.get("toolchain_config", "gcc-13.1.0-baremetal")))
    env.setdefault("NUM_JOBS", str(config.get("num_jobs", 8)))
    service = str(config.get("docker_service", "cva6-toolchain"))
    run([*docker_compose_base(config), "run", "--rm", service], cwd=root, env=env, dry_run=dry_run)


def task_bootrom_build(root: Path, config: dict, env: dict[str, str], dry_run: bool) -> None:
    env = env.copy()
    env.setdefault("BOARD", str(config.get("board", "genesys2")))
    env.setdefault("XLEN", str(config.get("xlen", 64)))
    env.setdefault("PLATFORM", str(config.get("platform", "PLAT_XILINX")))
    service = str(config.get("docker_service", "cva6-toolchain"))
    run(
        [
            *docker_compose_base(config),
            "run",
            "--rm",
            service,
            "bash",
            "docker/toolchain/build-cva6-bootrom.sh",
        ],
        cwd=root,
        env=env,
        dry_run=dry_run,
    )


def tcl_braced(value: str | os.PathLike[str]) -> str:
    return "{" + as_posix_path(value).replace("}", "\\}") + "}"


def tcl_list(values: Iterable[str | os.PathLike[str]]) -> str:
    return "[list " + " ".join(tcl_braced(as_posix_path(value)) for value in values) + "]"


ARTIX7_LITEX_PYTHONPATHS = (
    "vendor/litex/migen",
    "vendor/litex/litex",
    "vendor/litex/litex-boards",
    "vendor/litex/litedram",
    "vendor/litex/pythondata-cpu-vexriscv_smp",
)
ARTIX7_DEFAULT_LITEX_BUILD = Path("build/litex/artix7_35t_embedfire_rise_pro")
ARTIX7_LED_BUILD = Path("build/vivado/artix7_35t_led_blink")
ARTIX7_BAREMETAL_SRC = Path("board/artix7_35t/baremetal")
ARTIX7_BAREMETAL_BUILD = Path("build/board/artix7_35t/baremetal")
ARTIX7_BAREMETAL_BIN = ARTIX7_BAREMETAL_BUILD / "rvmt_baremetal_pass.bin"
ARTIX7_LINUX_SRC = Path("board/artix7_35t/linux")
ARTIX7_LINUX_BUILD = Path("build/board/artix7_35t/linux")
ARTIX7_LOLV_DIR = Path("vendor/litex/linux-on-litex-vexriscv")
ARTIX7_LOLV_BUILD = ARTIX7_LOLV_DIR / "build" / "embedfire_rise_pro"
ARTIX7_LOLV_TRACE_BUILD = ARTIX7_LOLV_DIR / "build" / "embedfire_rise_pro_trace"
ARTIX7_LOLV_IMAGES = ARTIX7_LOLV_DIR / "images"
ARTIX7_TRACE_RAW_RECORD_WORDS = 16
ARTIX7_TRACE_DEFAULT_CSR_BASE = 0xF0004000

SFL_PROMPT_REQ = b"F7:    boot from serial\n"
SFL_PROMPT_ACK = b"\x06"
SFL_MAGIC_REQ = b"sL5DdSMmkekro\n"
SFL_MAGIC_ACK = b"z6IHG7cYDID6o\n"
SFL_CMD_LOAD = b"\x01"
SFL_CMD_JUMP = b"\x02"
SFL_ACK_SUCCESS = b"K"
SFL_ACK_CRCERROR = b"C"
SFL_SAFE_DATA_LENGTH = 251


def artix7_run_id(args: argparse.Namespace) -> str:
    if args.run_id and args.run_id != "manual":
        return safe_artifact_segment(args.run_id)
    date = dt.datetime.now().strftime("%Y-%m-%d")
    port = safe_artifact_segment(str(args.port or "COM5")).lower()
    return f"{date}-{port}-ddr"


def artix7_run_dir(root: Path, args: argparse.Namespace) -> Path:
    return root / "results" / "board" / "artix7_35t_litex" / artix7_run_id(args)


def artix7_step_dir(root: Path, args: argparse.Namespace, step: str) -> Path:
    return artix7_run_dir(root, args) / step


def artix7_litex_build_dir(root: Path, args: argparse.Namespace) -> Path:
    if args.out_dir is not None:
        return args.out_dir if args.out_dir.is_absolute() else root / args.out_dir
    return root / ARTIX7_DEFAULT_LITEX_BUILD


def artix7_litex_env(root: Path, env: dict[str, str]) -> dict[str, str]:
    resolved = [str((root / path).resolve()) for path in ARTIX7_LITEX_PYTHONPATHS]
    result = env.copy()
    existing = result.get("PYTHONPATH", "")
    result["PYTHONPATH"] = os.pathsep.join([*resolved, existing]) if existing else os.pathsep.join(resolved)
    return result


def artix7_litex_vivado_env(root: Path, config: dict, env: dict[str, str]) -> dict[str, str]:
    return artix7_litex_env(root, artix7_vivado_env(config, env))


def artix7_vivado_env(config: dict, env: dict[str, str]) -> dict[str, str]:
    vivado = resolve_vivado(config)
    return prepend_env_path(env, Path(vivado).parent)


def serial_port_inventory() -> list[str]:
    try:
        from serial.tools import list_ports
    except ImportError:
        return ["pyserial unavailable; serial ports were not enumerated"]
    ports = []
    for port in list_ports.comports():
        description = port.description or ""
        hwid = port.hwid or ""
        ports.append(f"{port.device}: {description} [{hwid}]")
    return ports or ["no serial ports reported by pyserial"]


def write_artix7_observation(step_dir: Path, status: str, lines: Iterable[str]) -> None:
    step_dir.mkdir(parents=True, exist_ok=True)
    body = [f"# Observation", "", f"Status: {status}", "", *lines, ""]
    (step_dir / "observation.md").write_text("\n".join(body), encoding="utf-8", newline="\n")


def write_artix7_failure(step_dir: Path, exc: Exception, log_path: Path) -> None:
    lines = [f"- Command failed: {exc}."]
    if log_path.exists():
        lines.append(f"- Transcript: `{log_path}`.")
    write_artix7_observation(step_dir, "FAIL", lines)


def record_artix7_board_identity(root: Path, config: dict, env: dict[str, str], args: argparse.Namespace, dry_run: bool) -> None:
    step_dir = artix7_step_dir(root, args, "00_board_identity")
    if dry_run:
        print(f"+ record Artix-7 35T board identity in {step_dir}")
        return

    step_dir.mkdir(parents=True, exist_ok=True)
    vivado = resolve_vivado(config)
    completed = subprocess.run(
        [vivado, "-version"],
        cwd=str(root),
        env=artix7_vivado_env(config, env),
        capture_output=True,
        encoding="utf-8",
        errors="replace",
    )
    version_text = "\n".join(part for part in (completed.stdout, completed.stderr) if part).strip()
    (step_dir / "vivado_version.txt").write_text(version_text + "\n", encoding="utf-8", newline="\n")
    (step_dir / "serial_ports.txt").write_text("\n".join(serial_port_inventory()) + "\n", encoding="utf-8", newline="\n")
    observation = [
        "- Board path: EmbedFire Shengteng Pro A35T / XC7A35T-FGG484-2.",
        f"- Primary UART: board CH340 on `{args.port}` at `{args.baud} 8N1`.",
        "- Source material: `docs/03-platform-architecture/artix7-35t/artix7_35t_pinmap.xlsx` and `docs/03-platform-architecture/artix7-35t/artix8_35t_hw_spec.pdf`.",
        "- Vivado executable: `" + vivado + "`.",
        "- Notes: repository hardware spec PDF is currently named `artix8_35t_hw_spec.pdf`.",
    ]
    write_artix7_observation(step_dir, "PASS", observation)


def artix7_vivado_capture(
    root: Path,
    config: dict,
    env: dict[str, str],
    args: argparse.Namespace,
    script: Path,
    tclargs: list[str],
    transcript: Path,
    dry_run: bool,
) -> str:
    vivado = resolve_vivado(config)
    cmd = [
        vivado,
        "-mode",
        "batch",
        "-nojournal",
        "-nolog",
        "-notrace",
        "-source",
        str(script),
    ]
    if tclargs:
        cmd.extend(["-tclargs", *tclargs])
    return run_capture(cmd, cwd=root, env=artix7_vivado_env(config, env), dry_run=dry_run, log_path=transcript)


def find_artix7_litex_bitstream(build_dir: Path) -> Path:
    candidates = sorted((build_dir / "gateware").glob("*.bit"))
    if not candidates:
        candidates = sorted(build_dir.glob("**/*.bit"))
    if not candidates:
        raise TaskError(f"No LiteX bitstream found under {build_dir}. Run board:artix7:litex-build first.")
    return candidates[0]


def artix7_litex_target_path(root: Path | str) -> str:
    base = Path(root) if not isinstance(root, str) else root.rstrip("/\\")
    if isinstance(base, Path):
        return str(base / "vendor" / "litex" / "litex-boards" / "litex_boards" / "targets" / "embedfire_rise_pro.py")
    return f"{base}/vendor/litex/litex-boards/litex_boards/targets/embedfire_rise_pro.py"


def artix7_litex_base_cmd(
    root: Path,
    args: argparse.Namespace,
    *,
    build: bool,
    load: bool,
    no_compile_gateware: bool = False,
    no_compile_software: bool = False,
    integrated_rom_init: Path | None = None,
) -> list[str]:
    target = artix7_litex_target_path(root)
    build_dir = artix7_litex_build_dir(root, args)
    cmd = [
        sys.executable,
        target,
        "--variant",
        "a7-35",
        "--sys-clk-freq",
        "50e6",
        "--uart-baudrate",
        str(args.baud),
        "--cpu-type",
        "vexriscv",
        "--output-dir",
        str(build_dir),
    ]
    if no_compile_gateware:
        cmd.append("--no-compile-gateware")
    if no_compile_software:
        cmd.append("--no-compile-software")
    if integrated_rom_init is not None:
        cmd.extend(["--integrated-rom-init", str(integrated_rom_init)])
    if build:
        cmd.append("--build")
    if load:
        cmd.append("--load")
    return cmd


def artix7_litex_docker_cmd(root: Path, config: dict, args: argparse.Namespace) -> list[str]:
    build_dir = artix7_litex_build_dir(root, args)
    try:
        build_dir_in_repo = as_posix_path(build_dir.relative_to(root))
    except ValueError as exc:
        raise TaskError("Artix-7 LiteX Docker build output must be inside the repository.") from exc
    docker_build_dir = f"/workspace/rv-maltrace/{build_dir_in_repo}"
    target = artix7_litex_target_path("/workspace/rv-maltrace")
    return [
        *docker_compose_base(config),
        "run",
        "--rm",
        "--build",
        "litex-build",
        "python3",
        target,
        "--variant",
        "a7-35",
        "--sys-clk-freq",
        "50e6",
        "--uart-baudrate",
        str(args.baud),
        "--cpu-type",
        "vexriscv",
        "--output-dir",
        docker_build_dir,
        "--no-compile-gateware",
        "--build",
    ]


def artix7_litex_bios_path(root: Path, args: argparse.Namespace) -> Path:
    return artix7_litex_build_dir(root, args) / "software" / "bios" / "bios.bin"


def artix7_baremetal_build_dir(root: Path) -> Path:
    return root / ARTIX7_BAREMETAL_BUILD


def artix7_baremetal_bin(root: Path) -> Path:
    return root / ARTIX7_BAREMETAL_BIN


def artix7_lolv_dir(root: Path) -> Path:
    return root / ARTIX7_LOLV_DIR


def artix7_lolv_images_dir(root: Path) -> Path:
    return root / ARTIX7_LOLV_IMAGES


def artix7_lolv_make_cmd(
    root: Path,
    args: argparse.Namespace,
    *,
    build: bool = False,
    load: bool = False,
) -> list[str]:
    wrapper = root / "fpga" / "artix7_35t" / "litex" / "linux_nosd.py"
    cmd = [
        sys.executable,
        str(wrapper),
        "--variant",
        "a7-35",
        "--uart-baudrate",
        str(args.baud),
        "--rootfs",
        "ram0",
    ]
    if build:
        cmd.append("--build")
    if load:
        cmd.append("--load")
    return cmd


def artix7_lolv_docker_cmd(
    root: Path,
    config: dict,
    args: argparse.Namespace,
    *,
    build: bool = False,
    load: bool = False,
    no_compile_gateware: bool = False,
    no_compile_software: bool = False,
    integrated_rom_init: Path | None = None,
    skip_dts: bool = False,
) -> list[str]:
    wrapper = "/workspace/rv-maltrace/fpga/artix7_35t/litex/linux_nosd.py"
    cmd = [
        *docker_compose_base(config),
        "run",
        "--rm",
        "--build",
        "litex-build",
        "python3",
        wrapper,
        "--variant",
        "a7-35",
        "--uart-baudrate",
        str(args.baud),
        "--rootfs",
        "ram0",
    ]
    if build:
        cmd.append("--build")
    if load:
        cmd.append("--load")
    if no_compile_gateware:
        cmd.append("--no-compile-gateware")
    if no_compile_software:
        cmd.append("--no-compile-software")
    if integrated_rom_init is not None:
        try:
            rom_in_repo = as_posix_path(integrated_rom_init.relative_to(root))
        except ValueError as exc:
            raise TaskError("Linux integrated ROM image must be inside the repository.") from exc
        cmd.extend(["--integrated-rom-init", f"/workspace/rv-maltrace/{rom_in_repo}"])
    if skip_dts:
        cmd.append("--skip-dts")
    return cmd


def artix7_linux_boot_json(root: Path) -> Path:
    boot = artix7_lolv_images_dir(root) / "boot.json"
    return boot if boot.exists() else artix7_lolv_images_dir(root) / "boot_ram0.json"


def artix7_linux_bios_path(root: Path) -> Path:
    return root / ARTIX7_LOLV_BUILD / "software" / "bios" / "bios.bin"


def artix7_trace_bios_path(root: Path) -> Path:
    return root / ARTIX7_LOLV_TRACE_BUILD / "software" / "bios" / "bios.bin"


def artix7_trace_jsonl_path(root: Path, args: argparse.Namespace) -> Path:
    return artix7_step_dir(root, args, "08_trace_jsonl_compare") / "trace.jsonl"


def artix7_trace_build_name(trace_records: int | None) -> str:
    records = 256 if trace_records is None else int(trace_records)
    return "embedfire_rise_pro_trace" if records == 256 else f"embedfire_rise_pro_trace_r{records}"


def artix7_trace_build_dir(root: Path, trace_records: int | None) -> Path:
    return root / ARTIX7_LOLV_DIR / "build" / artix7_trace_build_name(trace_records)


def artix7_trace_csr_csv(root: Path, trace_records: int | None = None) -> Path:
    return artix7_trace_build_dir(root, trace_records) / "csr.csv"


def artix7_trace_csr_base(root: Path, trace_records: int | None = None, *, allow_default: bool = False) -> int:
    csr_csv = artix7_trace_csr_csv(root, trace_records)
    if not csr_csv.exists():
        if allow_default:
            return ARTIX7_TRACE_DEFAULT_CSR_BASE
        raise TaskError(f"Missing trace CSR map: {csr_csv}. Run board:artix7:trace-build first.")
    for line in csr_csv.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = [part.strip() for part in line.split(",")]
        if len(parts) >= 3 and parts[0] == "csr_base" and parts[1] == "rvmt_trace":
            return int(parts[2], 0)
    if allow_default:
        return ARTIX7_TRACE_DEFAULT_CSR_BASE
    raise TaskError(f"`rvmt_trace` CSR base was not found in {csr_csv}")


def sfl_frame(cmd: bytes, payload: bytes) -> bytes:
    crc = binascii.crc_hqx(cmd + payload, 0)
    return bytes([len(payload)]) + crc.to_bytes(2, "big") + cmd + payload


def sfl_read_reply(ser, timeout: float) -> bytes:
    old_timeout = ser.timeout
    ser.timeout = timeout
    try:
        reply = ser.read(1)
    finally:
        ser.timeout = old_timeout
    if not reply:
        raise TaskError("timed out waiting for LiteX serial loader reply")
    return reply


def sfl_send_frame(ser, cmd: bytes, payload: bytes, timeout: float = 1.0, retries: int = 16) -> int:
    frame = sfl_frame(cmd, payload)
    crc_retries = 0
    for _attempt in range(retries):
        ser.write(frame)
        ser.flush()
        reply = sfl_read_reply(ser, timeout)
        if reply == SFL_ACK_SUCCESS:
            return crc_retries
        if reply == SFL_ACK_CRCERROR:
            crc_retries += 1
            continue
        raise TaskError(f"LiteX serial loader returned unexpected reply {reply!r}")
    raise TaskError("LiteX serial loader reported too many CRC errors")


def serialboot_theoretical_seconds(total_bytes: int, baud: int) -> float:
    if baud <= 0:
        return 0.0
    return (total_bytes * 10.0) / baud


def append_timestamped_text(log, start: float, text: str) -> None:
    for line in text.splitlines(keepends=True):
        log.write(f"[{time.monotonic() - start:010.3f}] {line}")


def read_serial_text(ser, log, start: float, buffer: bytearray) -> None:
    chunk = ser.read(4096)
    if not chunk:
        return
    buffer.extend(chunk)
    text = chunk.decode("utf-8", errors="replace")
    append_timestamped_text(log, start, text)
    log.flush()


def serial_boot_images(
    *,
    port: str,
    baud: int,
    images: list[tuple[Path, int]],
    boot_address: int,
    log_path: Path,
    marker: str | None,
    timeout: float,
    send_serialboot_command: bool = True,
) -> str:
    try:
        import serial
    except ImportError as exc:
        raise TaskError("pyserial is required for Artix-7 serial boot tasks. Run `uv sync` first.") from exc

    log_path.parent.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    deadline = start + timeout
    raw = bytearray()
    image_sizes = [(image, address, image.stat().st_size if image.exists() else 0) for image, address in images]
    total_bytes = sum(size for _image, _address, size in image_sizes)
    theoretical = serialboot_theoretical_seconds(total_bytes, baud)
    with serial.Serial(port, baud, timeout=0.05) as ser, log_path.open("w", encoding="utf-8", newline="\n") as log:
        log.write(f"# port={port} baud={baud} framing=8N1\n")
        log.write(
            f"# serialboot_total_bytes={total_bytes} theoretical_raw_seconds={theoretical:.1f} "
            f"theoretical_raw_minutes={theoretical / 60.0:.2f}\n"
        )
        if send_serialboot_command:
            ser.write(b"\nserialboot\n")
            ser.flush()
            log.write(f"[{time.monotonic() - start:010.3f}] >> serialboot\n")

        entered_loader = False
        while time.monotonic() < deadline:
            read_serial_text(ser, log, start, raw)
            if SFL_PROMPT_REQ in raw:
                ser.write(SFL_PROMPT_ACK)
                ser.flush()
                log.write(f"[{time.monotonic() - start:010.3f}] LiteX serial prompt acknowledged\n")
                raw.clear()
            if SFL_MAGIC_REQ in raw:
                ser.write(SFL_MAGIC_ACK)
                ser.flush()
                log.write(f"[{time.monotonic() - start:010.3f}] LiteX serial loader magic acknowledged\n")
                entered_loader = True
                break
        if not entered_loader:
            raise TaskError(f"LiteX serial loader did not request firmware download before timeout. See {log_path}")

        upload_start = time.monotonic()
        uploaded_total = 0
        crc_retry_total = 0
        next_progress = 1024 * 1024
        for image, address, image_size in image_sizes:
            payload = image.read_bytes()
            image_start = time.monotonic()
            image_crc_retries = 0
            log.write(f"[{time.monotonic() - start:010.3f}] uploading {image} to 0x{address:08x} ({len(payload)} bytes)\n")
            for offset in range(0, len(payload), SFL_SAFE_DATA_LENGTH):
                chunk = payload[offset:offset + SFL_SAFE_DATA_LENGTH]
                retries_for_frame = sfl_send_frame(ser, SFL_CMD_LOAD, (address + offset).to_bytes(4, "big") + chunk)
                crc_retry_total += retries_for_frame
                image_crc_retries += retries_for_frame
                uploaded_total += len(chunk)
                if uploaded_total >= next_progress or uploaded_total == total_bytes:
                    elapsed = max(time.monotonic() - upload_start, 1e-6)
                    throughput = uploaded_total / elapsed
                    percent = (uploaded_total * 100.0 / total_bytes) if total_bytes else 100.0
                    log.write(
                        f"[{time.monotonic() - start:010.3f}] serialboot progress "
                        f"{uploaded_total}/{total_bytes} bytes ({percent:.1f}%) "
                        f"{throughput:.0f} B/s crc_retries={crc_retry_total}\n"
                    )
                    log.flush()
                    while next_progress <= uploaded_total:
                        next_progress += 1024 * 1024
            image_elapsed = max(time.monotonic() - image_start, 1e-6)
            log.write(
                f"[{time.monotonic() - start:010.3f}] upload complete: {image} "
                f"bytes={image_size} throughput={image_size / image_elapsed:.0f} B/s "
                f"crc_retries={image_crc_retries}\n"
            )

        upload_elapsed = max(time.monotonic() - upload_start, 1e-6)
        log.write(
            f"[{time.monotonic() - start:010.3f}] serialboot upload summary "
            f"bytes={uploaded_total} elapsed={upload_elapsed:.1f}s throughput={uploaded_total / upload_elapsed:.0f} B/s "
            f"crc_retries={crc_retry_total}\n"
        )
        jump_crc_retries = sfl_send_frame(ser, SFL_CMD_JUMP, boot_address.to_bytes(4, "big"))
        log.write(f"[{time.monotonic() - start:010.3f}] jumped to 0x{boot_address:08x} crc_retries={jump_crc_retries}\n")
        marker_text = marker or ""
        while time.monotonic() < deadline:
            read_serial_text(ser, log, start, raw)
            decoded = raw.decode("utf-8", errors="replace")
            if marker_text and marker_text in decoded:
                log.write(f"[{time.monotonic() - start:010.3f}] marker detected: {marker_text}\n")
                return decoded
        return raw.decode("utf-8", errors="replace")


def load_litex_images_json(images_json: Path) -> list[tuple[Path, int]]:
    payload = json.loads(images_json.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TaskError(f"{images_json} must contain a JSON object")
    images: list[tuple[Path, int]] = []
    for name, address in payload.items():
        image = images_json.parent / str(name)
        images.append((image, int(str(address), 0)))
    return images


def task_artix7_litex_prep_docker(root: Path, config: dict, env: dict[str, str], args: argparse.Namespace) -> None:
    record_artix7_board_identity(root, config, env, args, args.dry_run)
    step_dir = artix7_step_dir(root, args, "04_litex_ddr")
    build_dir = artix7_litex_build_dir(root, args)
    bios = artix7_litex_bios_path(root, args)
    log_path = step_dir / "litex_docker_prep.log"
    cmd = artix7_litex_docker_cmd(root, config, args)
    try:
        run_capture(cmd, cwd=root, env=env, dry_run=args.dry_run, log_path=log_path)
    except TaskError as exc:
        if not args.dry_run:
            write_artix7_failure(step_dir, exc, log_path)
        raise
    if args.dry_run:
        return
    if not bios.exists():
        write_artix7_observation(
            step_dir,
            "FAIL",
            [
                "- Docker LiteX software preparation completed, but BIOS output was not found.",
                f"- Expected BIOS: `{bios}`.",
            ],
        )
        raise TaskError(f"LiteX Docker prep did not produce {bios}")
    write_artix7_observation(
        step_dir,
        "PASS",
        [
            "- Docker LiteX software preparation completed.",
            f"- BIOS image: `{bios}`.",
            f"- Build directory: `{build_dir}`.",
            "- DDR PASS is not claimed until the UART BIOS memory-test log is captured.",
        ],
    )


def task_artix7_jtag_scan(root: Path, config: dict, env: dict[str, str], args: argparse.Namespace) -> None:
    record_artix7_board_identity(root, config, env, args, args.dry_run)
    step_dir = artix7_step_dir(root, args, "01_vivado_jtag")
    script = root / "fpga" / "artix7_35t" / "scripts" / "jtag_scan.tcl"
    log_path = step_dir / "vivado_jtag_scan.log"
    try:
        output = artix7_vivado_capture(root, config, env, args, script, [], log_path, args.dry_run)
    except TaskError as exc:
        if not args.dry_run:
            write_artix7_failure(step_dir, exc, log_path)
        raise
    if args.dry_run:
        return
    if "xc7a35t" not in output.lower():
        write_artix7_observation(step_dir, "FAIL", ["- JTAG scan completed but did not report an `xc7a35t` device."])
        raise TaskError(f"JTAG scan did not identify xc7a35t. See {step_dir / 'vivado_jtag_scan.log'}")
    write_artix7_observation(step_dir, "PASS", ["- Vivado hardware scan reported an `xc7a35t`-compatible device."])


def task_artix7_led_build(root: Path, config: dict, env: dict[str, str], args: argparse.Namespace) -> None:
    record_artix7_board_identity(root, config, env, args, args.dry_run)
    step_dir = artix7_step_dir(root, args, "02_led_clock_reset")
    build_dir = root / ARTIX7_LED_BUILD
    script = root / "fpga" / "artix7_35t" / "scripts" / "build_led_blink.tcl"
    log_path = step_dir / "vivado_led_build.log"
    try:
        artix7_vivado_capture(root, config, env, args, script, [str(build_dir)], log_path, args.dry_run)
    except TaskError as exc:
        if not args.dry_run:
            write_artix7_failure(step_dir, exc, log_path)
        raise
    if args.dry_run:
        return
    bitstream = build_dir / "led_blink.bit"
    if not bitstream.exists():
        write_artix7_observation(step_dir, "FAIL", [f"- LED build did not produce `{bitstream}`."])
        raise TaskError(f"LED build did not produce {bitstream}")
    write_artix7_observation(
        step_dir,
        "PASS",
        [
            f"- LED blink bitstream built: `{bitstream}`.",
            f"- Timing/utilization reports are under `{build_dir}`.",
        ],
    )


def task_artix7_led_load(root: Path, config: dict, env: dict[str, str], args: argparse.Namespace) -> None:
    record_artix7_board_identity(root, config, env, args, args.dry_run)
    step_dir = artix7_step_dir(root, args, "02_led_clock_reset")
    bitstream = root / ARTIX7_LED_BUILD / "led_blink.bit"
    if not args.dry_run and not bitstream.exists():
        raise TaskError(f"Missing LED bitstream: {bitstream}. Run board:artix7:led-build first.")
    script = root / "fpga" / "artix7_35t" / "scripts" / "program_bitstream.tcl"
    log_path = step_dir / "vivado_led_program.log"
    try:
        artix7_vivado_capture(root, config, env, args, script, [str(bitstream)], log_path, args.dry_run)
    except TaskError as exc:
        if not args.dry_run:
            write_artix7_failure(step_dir, exc, log_path)
        raise
    if args.dry_run:
        return
    write_artix7_observation(
        step_dir,
        "PASS",
        [
            f"- Programmed LED blink bitstream through Vivado: `{bitstream}`.",
            "- Operator still needs to append visual LED/reset behavior if using this as final board evidence.",
        ],
    )


def task_artix7_litex_build(root: Path, config: dict, env: dict[str, str], args: argparse.Namespace) -> None:
    record_artix7_board_identity(root, config, env, args, args.dry_run)
    step_dir = artix7_step_dir(root, args, "04_litex_ddr")
    build_dir = artix7_litex_build_dir(root, args)
    bios = artix7_litex_bios_path(root, args)
    docker_log = step_dir / "litex_docker_prep.log"
    vivado_log = step_dir / "litex_vivado_build.log"
    docker_cmd = artix7_litex_docker_cmd(root, config, args)
    try:
        run_capture(docker_cmd, cwd=root, env=env, dry_run=args.dry_run, log_path=docker_log)
    except TaskError as exc:
        if not args.dry_run:
            write_artix7_failure(step_dir, exc, docker_log)
        raise
    if args.dry_run:
        cmd = artix7_litex_base_cmd(
            root,
            args,
            build=True,
            load=False,
            no_compile_software=True,
            integrated_rom_init=bios,
        )
        run_capture(cmd, cwd=root, env=artix7_litex_vivado_env(root, config, env), dry_run=True, log_path=vivado_log)
        return
    if not bios.exists():
        write_artix7_observation(
            step_dir,
            "FAIL",
            [
                "- Docker LiteX software preparation did not produce the BIOS image required for Windows Vivado build.",
                f"- Expected BIOS: `{bios}`.",
            ],
        )
        raise TaskError(f"LiteX Docker prep did not produce {bios}")
    cmd = artix7_litex_base_cmd(
        root,
        args,
        build=True,
        load=False,
        no_compile_software=True,
        integrated_rom_init=bios,
    )
    try:
        run_capture(cmd, cwd=root, env=artix7_litex_vivado_env(root, config, env), dry_run=False, log_path=vivado_log)
    except TaskError as exc:
        write_artix7_failure(step_dir, exc, vivado_log)
        raise
    bitstream = find_artix7_litex_bitstream(build_dir)
    write_artix7_observation(
        step_dir,
        "PASS",
        [
            "- Docker built the LiteX BIOS/software artifacts.",
            "- Windows Vivado built the no-trace LiteX/VexRiscv gateware for `embedfire_rise_pro --variant a7-35`.",
            f"- BIOS image: `{bios}`.",
            f"- Bitstream: `{bitstream}`.",
            f"- Build directory: `{build_dir}`.",
            "- DDR PASS is not claimed until the UART BIOS memory-test log is captured.",
        ],
    )


def task_artix7_litex_load(root: Path, config: dict, env: dict[str, str], args: argparse.Namespace) -> None:
    record_artix7_board_identity(root, config, env, args, args.dry_run)
    step_dir = artix7_step_dir(root, args, "04_litex_ddr")
    bios = artix7_litex_bios_path(root, args)
    if not args.dry_run:
        find_artix7_litex_bitstream(artix7_litex_build_dir(root, args))
    cmd = artix7_litex_base_cmd(
        root,
        args,
        build=False,
        load=True,
        no_compile_software=True,
        integrated_rom_init=bios if bios.exists() or args.dry_run else None,
    )
    log_path = step_dir / "litex_load.log"
    try:
        run_capture(cmd, cwd=root, env=artix7_litex_vivado_env(root, config, env), dry_run=args.dry_run, log_path=log_path)
    except TaskError as exc:
        if not args.dry_run:
            write_artix7_failure(step_dir, exc, log_path)
        raise
    if args.dry_run:
        return
    write_artix7_observation(
        step_dir,
        "PASS",
        [
            "- Programmed the no-trace LiteX bitstream through the LiteX/Vivado programmer path.",
            "- DDR PASS is not claimed until the UART BIOS memory-test log is captured.",
        ],
    )


def task_artix7_serial_capture(root: Path, config: dict, env: dict[str, str], args: argparse.Namespace) -> None:
    record_artix7_board_identity(root, config, env, args, args.dry_run)
    step = str(args.board_step)
    step_dir = artix7_step_dir(root, args, step)
    if step == "04_litex_ddr":
        log_name = "uart_ddr.log"
    elif step == "08_trace_jsonl_compare":
        log_name = "trace_raw_uart.log"
    else:
        log_name = "raw_uart.log"
    log_path = step_dir / log_name
    print(
        f"+ capture serial {args.port} {args.baud} 8N1 for {args.duration:g}s "
        f"to {quote_for_display(str(log_path))}"
    )
    if args.dry_run:
        return
    try:
        import serial
    except ImportError as exc:
        raise TaskError("pyserial is required for board:artix7:serial-capture. Run `uv sync` first.") from exc

    step_dir.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    deadline = start + float(args.duration)
    sent_commands = [str(command) for command in args.send]
    send_char_delay = max(0.0, float(getattr(args, "send_char_delay", 0.0)))
    send_delay = max(0.0, float(getattr(args, "send_delay", 0.0)))
    with serial.Serial(args.port, args.baud, timeout=0.1) as ser, log_path.open("w", encoding="utf-8", newline="\n") as log:
        log.write(f"# port={args.port} baud={args.baud} framing=8N1 send_char_delay={send_char_delay:g} send_delay={send_delay:g}\n")
        pending_text = ""

        def write_serial_text(text: str) -> None:
            nonlocal pending_text
            text = pending_text + text
            pending_text = ""
            lines = text.splitlines(keepends=True)
            if lines and not lines[-1].endswith(("\n", "\r")):
                pending_text = lines.pop()
            for line in lines:
                log.write(f"[{time.monotonic() - start:010.3f}] {line}")
            log.flush()

        def flush_pending_text() -> None:
            nonlocal pending_text
            if pending_text:
                log.write(f"[{time.monotonic() - start:010.3f}] {pending_text}")
                pending_text = ""
                log.flush()

        def drain(seconds: float) -> None:
            until = min(deadline, time.monotonic() + seconds)
            while time.monotonic() < until:
                chunk = ser.read(4096)
                if not chunk:
                    continue
                write_serial_text(chunk.decode("utf-8", errors="replace"))

        drain(send_delay)
        for command in sent_commands:
            flush_pending_text()
            log.write(f"[{time.monotonic() - start:010.3f}] >> {command}\n")
            log.flush()
            for char in command:
                ser.write(char.encode("utf-8"))
                ser.flush()
                if send_char_delay:
                    time.sleep(send_char_delay)
            ser.write(b"\r")
            ser.flush()
            drain(send_delay)
        while time.monotonic() < deadline:
            chunk = ser.read(4096)
            if not chunk:
                continue
            write_serial_text(chunk.decode("utf-8", errors="replace"))
        flush_pending_text()
    lines = [
        f"- Captured UART log from `{args.port}` at `{args.baud} 8N1`.",
        f"- Raw log: `{log_path}`.",
    ]
    if step == "04_litex_ddr":
        text = log_path.read_text(encoding="utf-8", errors="replace").lower()
        if "fail" in text or "error" in text:
            status = "FAIL"
            lines.append("- DDR log contains `fail` or `error`; inspect the raw UART log.")
        elif "sdram" in text and ("ok" in text or "pass" in text):
            status = "PASS"
            lines.append("- UART log contains SDRAM test success text.")
        else:
            status = "FAIL"
            lines.append("- DDR PASS was not detected automatically; keep the raw log as evidence and inspect manually.")
    else:
        status = "PASS" if log_path.stat().st_size > 0 else "FAIL"
    write_artix7_observation(step_dir, status, lines)
    if status != "PASS":
        raise TaskError(f"Serial capture did not meet PASS criteria. See {log_path}")


def task_artix7_baremetal_build(root: Path, config: dict, env: dict[str, str], args: argparse.Namespace) -> None:
    record_artix7_board_identity(root, config, env, args, args.dry_run)
    step_dir = artix7_step_dir(root, args, "05_baremetal")
    build_dir = artix7_baremetal_build_dir(root)
    src_dir = root / ARTIX7_BAREMETAL_SRC
    log_path = step_dir / "baremetal_build.log"
    docker_build_dir = "/workspace/rv-maltrace/" + as_posix_path(ARTIX7_BAREMETAL_BUILD)
    docker_src_dir = "/workspace/rv-maltrace/" + as_posix_path(ARTIX7_BAREMETAL_SRC)
    cmd = [
        *docker_compose_base(config),
        "run",
        "--rm",
        "--build",
        "litex-build",
        "bash",
        "-lc",
        (
            f"mkdir -p {docker_build_dir} && "
            "riscv64-unknown-elf-gcc -march=rv32ima -mabi=ilp32 -nostdlib -ffreestanding "
            f"-Wl,-T,{docker_src_dir}/linker.ld -Wl,-Map,{docker_build_dir}/rvmt_baremetal_pass.map "
            f"-o {docker_build_dir}/rvmt_baremetal_pass.elf "
            f"{docker_src_dir}/start.S {docker_src_dir}/rvmt_baremetal_pass.c && "
            f"riscv64-unknown-elf-objcopy -O binary {docker_build_dir}/rvmt_baremetal_pass.elf "
            f"{docker_build_dir}/rvmt_baremetal_pass.bin && "
            f"riscv64-unknown-elf-objdump -d {docker_build_dir}/rvmt_baremetal_pass.elf > "
            f"{docker_build_dir}/rvmt_baremetal_pass.dis"
        ),
    ]
    try:
        run_capture(cmd, cwd=root, env=env, dry_run=args.dry_run, log_path=log_path)
    except TaskError as exc:
        if not args.dry_run:
            write_artix7_failure(step_dir, exc, log_path)
        raise
    if args.dry_run:
        return
    binary = artix7_baremetal_bin(root)
    if not binary.exists():
        write_artix7_observation(step_dir, "FAIL", [f"- Bare-metal build did not produce `{binary}`."])
        raise TaskError(f"Bare-metal build did not produce {binary}")
    write_artix7_observation(
        step_dir,
        "PASS",
        [
            f"- Source directory: `{src_dir}`.",
            f"- Build directory: `{build_dir}`.",
            f"- Binary image: `{binary}`.",
            "- Hardware PASS is not claimed until `RVMT_BAREMETAL_PASS` appears in raw UART evidence.",
        ],
    )


def task_artix7_baremetal_load(root: Path, config: dict, env: dict[str, str], args: argparse.Namespace) -> None:
    record_artix7_board_identity(root, config, env, args, args.dry_run)
    step_dir = artix7_step_dir(root, args, "05_baremetal")
    binary = artix7_baremetal_bin(root)
    log_path = step_dir / "uart_baremetal_load.log"
    if args.dry_run:
        print(
            f"+ serial boot {args.port} {args.baud} 8N1 "
            f"{quote_for_display(str(binary))} @ 0x40000000 > {quote_for_display(str(log_path))}"
        )
        return
    if not binary.exists():
        raise TaskError(f"Missing bare-metal binary: {binary}. Run board:artix7:baremetal-build first.")
    text = serial_boot_images(
        port=args.port,
        baud=args.baud,
        images=[(binary, 0x40000000)],
        boot_address=0x40000000,
        log_path=log_path,
        marker=None,
        timeout=float(args.duration),
    )
    write_artix7_observation(
        step_dir,
        "PASS",
        [
            f"- Loaded `{binary}` through LiteX serial boot on `{args.port}`.",
            f"- Raw UART/load log: `{log_path}`.",
            "- Use `board:artix7:baremetal-run` to require the `RVMT_BAREMETAL_PASS` marker.",
        ],
    )


def task_artix7_baremetal_run(root: Path, config: dict, env: dict[str, str], args: argparse.Namespace) -> None:
    record_artix7_board_identity(root, config, env, args, args.dry_run)
    step_dir = artix7_step_dir(root, args, "05_baremetal")
    binary = artix7_baremetal_bin(root)
    log_path = step_dir / "uart_baremetal_run.log"
    if args.dry_run:
        print(
            f"+ serial boot/run {args.port} {args.baud} 8N1 "
            f"{quote_for_display(str(binary))} @ 0x40000000; require RVMT_BAREMETAL_PASS"
        )
        return
    if not binary.exists():
        task_artix7_baremetal_build(root, config, env, args)
    text = serial_boot_images(
        port=args.port,
        baud=args.baud,
        images=[(binary, 0x40000000)],
        boot_address=0x40000000,
        log_path=log_path,
        marker="RVMT_BAREMETAL_PASS",
        timeout=float(args.duration),
    )
    if "RVMT_BAREMETAL_PASS" not in text:
        write_artix7_observation(
            step_dir,
            "FAIL",
            [
                "- Bare-metal program loaded, but `RVMT_BAREMETAL_PASS` was not found.",
                f"- Raw UART log: `{log_path}`.",
            ],
        )
        raise TaskError(f"Bare-metal PASS marker not found. See {log_path}")
    write_artix7_observation(
        step_dir,
        "PASS",
        [
            "- Proved build -> LiteX BIOS serial load -> execute -> UART evidence for RV32 bare-metal.",
            f"- Binary image: `{binary}`.",
            f"- Raw UART log: `{log_path}`.",
        ],
    )


def task_artix7_linux_images_prep(root: Path, config: dict, env: dict[str, str], args: argparse.Namespace) -> None:
    record_artix7_board_identity(root, config, env, args, args.dry_run)
    step_dir = artix7_step_dir(root, args, "06_linux_boot")
    log_path = step_dir / "linux_images_prep.log"
    lolv = artix7_lolv_dir(root)
    cmd = artix7_lolv_docker_cmd(root, config, args, no_compile_gateware=True)
    try:
        run_capture(cmd, cwd=root, env=env, dry_run=args.dry_run, log_path=log_path)
    except TaskError as exc:
        if not args.dry_run:
            write_artix7_failure(step_dir, exc, log_path)
        raise
    if args.dry_run:
        return

    images_json = artix7_linux_boot_json(root)
    missing: list[Path] = []
    try:
        images = load_litex_images_json(images_json)
    except TaskError as exc:
        write_artix7_failure(step_dir, exc, log_path)
        raise
    for image, _address in images:
        if not image.exists():
            missing.append(image)
    if missing:
        write_artix7_observation(
            step_dir,
            "FAIL",
            [
                f"- Linux-on-LiteX metadata was prepared in `{lolv}`.",
                "- Required boot payloads are missing:",
                *(f"  - `{path}`" for path in missing),
                "- Provide/build these Linux payloads before claiming gate 06.",
            ],
        )
        raise TaskError("Linux boot payloads are missing; see observation.md")
    write_artix7_observation(
        step_dir,
        "PASS",
        [
            f"- Linux-on-LiteX metadata prepared in `{lolv}`.",
            f"- Boot image manifest: `{images_json}`.",
            "- Required ram0 boot payloads exist.",
        ],
    )


def task_artix7_linux_build(root: Path, config: dict, env: dict[str, str], args: argparse.Namespace) -> None:
    record_artix7_board_identity(root, config, env, args, args.dry_run)
    step_dir = artix7_step_dir(root, args, "06_linux_boot")
    log_path = step_dir / "linux_vivado_build.log"
    bios = artix7_linux_bios_path(root)
    if not args.dry_run and not bios.exists():
        raise TaskError(f"Missing Linux BIOS image: {bios}. Run board:artix7:linux-images-prep first.")
    cmd = artix7_lolv_make_cmd(root, args, build=True)
    cmd.extend(["--no-compile-software", "--skip-dts"])
    if bios.exists() or args.dry_run:
        cmd.extend(["--integrated-rom-init", str(bios)])
    try:
        run_capture(cmd, cwd=artix7_lolv_dir(root), env=artix7_litex_vivado_env(root, config, env), dry_run=args.dry_run, log_path=log_path)
    except TaskError as exc:
        if not args.dry_run:
            write_artix7_failure(step_dir, exc, log_path)
        raise
    if args.dry_run:
        return
    bitstreams = sorted((root / ARTIX7_LOLV_BUILD / "gateware").glob("*.bit"))
    if not bitstreams:
        write_artix7_observation(step_dir, "FAIL", [f"- Linux build did not produce a bitstream under `{root / ARTIX7_LOLV_BUILD}`."])
        raise TaskError("Linux-on-LiteX build did not produce a bitstream")
    write_artix7_observation(
        step_dir,
        "PASS",
        [
            "- Built Linux-capable LiteX SoC with `vexriscv_smp` / `cpu_variant=linux` through linux-on-litex-vexriscv.",
            f"- Bitstream: `{bitstreams[0]}`.",
            f"- Build log: `{log_path}`.",
        ],
    )


def task_artix7_linux_load(root: Path, config: dict, env: dict[str, str], args: argparse.Namespace) -> None:
    record_artix7_board_identity(root, config, env, args, args.dry_run)
    step_dir = artix7_step_dir(root, args, "06_linux_boot")
    log_path = step_dir / "linux_load.log"
    cmd = artix7_lolv_make_cmd(root, args, load=True)
    cmd.extend(["--no-compile-software", "--skip-dts"])
    bios = artix7_linux_bios_path(root)
    if bios.exists() or args.dry_run:
        cmd.extend(["--integrated-rom-init", str(bios)])
    try:
        run_capture(cmd, cwd=artix7_lolv_dir(root), env=artix7_litex_vivado_env(root, config, env), dry_run=args.dry_run, log_path=log_path)
    except TaskError as exc:
        if not args.dry_run:
            write_artix7_failure(step_dir, exc, log_path)
        raise
    if args.dry_run:
        return
    write_artix7_observation(
        step_dir,
        "PASS",
        [
            "- Loaded Linux-capable LiteX bitstream through linux-on-litex-vexriscv.",
            f"- Load log: `{log_path}`.",
            "- Linux userspace PASS is not claimed until `RVMT_LINUX_USER_PASS` appears in UART evidence.",
        ],
    )


def task_artix7_linux_boot_capture(root: Path, config: dict, env: dict[str, str], args: argparse.Namespace) -> None:
    record_artix7_board_identity(root, config, env, args, args.dry_run)
    step_dir = artix7_step_dir(root, args, "06_linux_boot")
    images_json = artix7_linux_boot_json(root)
    log_path = step_dir / "uart_linux_boot.log"
    if args.dry_run:
        upload_note = ""
        if images_json.exists():
            try:
                dry_images = load_litex_images_json(images_json)
                total_bytes = sum(image.stat().st_size for image, _address in dry_images if image.exists())
                upload_note = (
                    f"; serialboot payload {total_bytes} bytes, "
                    f"raw 8N1 lower bound {serialboot_theoretical_seconds(total_bytes, args.baud) / 60.0:.2f} min"
                )
            except (OSError, TaskError, ValueError):
                upload_note = ""
        print(
            f"+ serial boot Linux images from {quote_for_display(str(images_json))} "
            f"on {args.port} {args.baud} 8N1; require RVMT_LINUX_USER_PASS{upload_note}"
        )
        return
    images = load_litex_images_json(images_json)
    missing = [image for image, _address in images if not image.exists()]
    if missing:
        write_artix7_observation(
            step_dir,
            "FAIL",
            [
                "- Linux boot payloads are missing:",
                *(f"  - `{path}`" for path in missing),
            ],
        )
        raise TaskError("Linux boot payloads are missing; run board:artix7:linux-images-prep first")
    boot_address = images[-1][1]
    text = serial_boot_images(
        port=args.port,
        baud=args.baud,
        images=images,
        boot_address=boot_address,
        log_path=log_path,
        marker="RVMT_LINUX_USER_PASS",
        timeout=float(args.duration),
    )
    if "RVMT_LINUX_USER_PASS" not in text:
        write_artix7_observation(
            step_dir,
            "FAIL",
            [
                "- Linux boot capture did not contain `RVMT_LINUX_USER_PASS`.",
                f"- Raw UART log: `{log_path}`.",
            ],
        )
        raise TaskError(f"Linux userspace PASS marker not found. See {log_path}")
    write_artix7_observation(
        step_dir,
        "PASS",
        [
            "- Linux boot reached userspace and produced the tiny program PASS marker.",
            f"- Boot image manifest: `{images_json}`.",
            f"- Raw UART log: `{log_path}`.",
        ],
    )


def task_artix7_trace_build(root: Path, config: dict, env: dict[str, str], args: argparse.Namespace) -> None:
    record_artix7_board_identity(root, config, env, args, args.dry_run)
    step_dir = artix7_step_dir(root, args, "07_trace_minimal")
    trace_soc = root / "fpga" / "artix7_35t" / "litex" / "rvmt_trace_soc.py"
    log_path = step_dir / "trace_build.log"
    cmd = [
        sys.executable,
        str(trace_soc),
        "--variant",
        "a7-35",
        "--sys-clk-freq",
        "50e6",
        "--uart-baudrate",
        str(args.baud),
        "--rootfs",
        "ram0",
        "--trace-depth",
        str(args.trace_records),
        "--output-dir",
        f"build/{artix7_trace_build_name(args.trace_records)}",
        "--build",
        "--no-compile-software",
        "--skip-dts",
        "--vivado",
        resolve_vivado(config),
    ]
    linux_bios = artix7_linux_bios_path(root)
    if linux_bios.exists() or args.dry_run:
        cmd.extend(["--integrated-rom-init", str(linux_bios)])
    if args.dry_run:
        run_capture(cmd, cwd=root, env=artix7_litex_vivado_env(root, config, env), dry_run=True, log_path=log_path)
        return
    if not trace_soc.exists():
        write_artix7_observation(
            step_dir,
            "FAIL",
            [
                f"- Missing trace SoC integration: `{trace_soc}`.",
                "- Gate 07 must not claim PASS until a real VexRiscvSMP trace adapter emits syscall/trap/context/drop events.",
            ],
        )
        raise TaskError(f"Missing trace SoC integration: {trace_soc}")
    run_capture(cmd, cwd=root, env=artix7_litex_vivado_env(root, config, env), dry_run=False, log_path=log_path)
    trace_build_dir = artix7_trace_build_dir(root, args.trace_records)
    bitstream = trace_build_dir / "gateware" / "embedfire_rise_pro.bit"
    if not bitstream.exists():
        write_artix7_observation(step_dir, "FAIL", [f"- Trace build did not produce `{bitstream}`."])
        raise TaskError(f"Trace build did not produce {bitstream}")
    write_artix7_observation(
        step_dir,
        "PASS",
        [
            "- Built trace-instrumented Linux-capable SoC with a repo-owned CSR/BRAM trace ring.",
            "- CPU trace outputs are connected by generated gateware patching, not by editing vendor netlists in place.",
            f"- Bitstream: `{bitstream}`.",
            f"- Build transcript: `{log_path}`.",
        ],
    )


def task_artix7_trace_load(root: Path, config: dict, env: dict[str, str], args: argparse.Namespace) -> None:
    record_artix7_board_identity(root, config, env, args, args.dry_run)
    step_dir = artix7_step_dir(root, args, "07_trace_minimal")
    trace_build_dir = artix7_trace_build_dir(root, args.trace_records)
    bitstreams = sorted((trace_build_dir / "gateware").glob("*.bit"))
    log_path = step_dir / "trace_load.log"
    if args.dry_run:
        print(f"+ load Artix-7 minimal trace bitstream > {quote_for_display(str(log_path))}")
        return
    if not bitstreams:
        write_artix7_observation(step_dir, "FAIL", [f"- No trace bitstream found under `{trace_build_dir / 'gateware'}`."])
        raise TaskError("No Artix-7 trace bitstream found")
    script = root / "fpga" / "artix7_35t" / "scripts" / "program_bitstream.tcl"
    artix7_vivado_capture(root, config, env, args, script, [str(bitstreams[0])], log_path, False)
    write_artix7_observation(step_dir, "PASS", [f"- Programmed trace bitstream: `{bitstreams[0]}`."])


def task_artix7_trace_dump(root: Path, config: dict, env: dict[str, str], args: argparse.Namespace) -> None:
    record_artix7_board_identity(root, config, env, args, args.dry_run)
    step_dir = artix7_step_dir(root, args, "08_trace_jsonl_compare")
    log_path = step_dir / "trace_raw_uart.log"
    csr_base = artix7_trace_csr_base(root, args.trace_records, allow_default=args.dry_run)
    dump_command = f"/usr/bin/rvmt_trace_dump 0x{csr_base:08x} {args.trace_records}"
    print(
        f"+ capture trace dump from {args.port} {args.baud} 8N1 for {args.duration:g}s "
        f"to {quote_for_display(str(log_path))}; clear ring, run linux pass, send {quote_for_display(dump_command)}"
    )
    if args.dry_run:
        return
    args_for_capture = argparse.Namespace(**vars(args))
    args_for_capture.board_step = "08_trace_jsonl_compare"
    args_for_capture.send_char_delay = max(float(getattr(args, "send_char_delay", 0.0)), 0.004)
    args_for_capture.send_delay = max(float(getattr(args, "send_delay", 0.0)), 1.5)
    args_for_capture.send = [
        "root",
        f"devmem 0x{csr_base:08x} 32 0x3",
        f"devmem 0x{csr_base:08x} 32 0x1",
        "/usr/bin/rvmt_linux_user_pass",
        dump_command,
    ]
    task_artix7_serial_capture(root, config, env, args_for_capture)
    raw = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
    status = "PASS" if "RVMT_TRACE_DUMP_BEGIN" in raw and "RVMT_TRACE_DUMP_END" in raw else "FAIL"
    write_artix7_observation(
        step_dir,
        status,
        [
            f"- Raw trace UART log: `{log_path}`.",
            f"- Trace CSR base: `0x{csr_base:08x}` from `{artix7_trace_csr_csv(root, args.trace_records)}`.",
            f"- Records requested: `{args.trace_records}`.",
            "- Required markers: `RVMT_TRACE_DUMP_BEGIN` and `RVMT_TRACE_DUMP_END`.",
        ],
    )
    if status != "PASS":
        raise TaskError(f"Trace dump markers not found. See {log_path}")


def artix7_hex32(value: int) -> str:
    return f"0x{value & 0xffffffff:08x}"


def artix7_pc_hex(value: int) -> str:
    return f"0x{value & 0xffffffff:016x}"


def artix7_priv_name(value: int) -> str:
    return {0: "U", 1: "S", 3: "M"}.get(value & 0x3, f"0x{value & 0x3:x}")


def raw_trace_record_to_event(index: int, words: list[int]) -> dict[str, object]:
    event_names = {
        1: "RETIRE",
        2: "BRANCH",
        3: "JUMP",
        4: "SYSCALL_ENTRY",
        5: "SYSCALL_RET",
        6: "TRAP",
        7: "CSR",
        8: "SATP",
        9: "PRIV",
        10: "ARG_MEM",
        11: "DROP",
        12: "MARKER",
    }
    original_words = list(words)
    if len(words) < ARTIX7_TRACE_RAW_RECORD_WORDS:
        words = [*words, *([0] * (ARTIX7_TRACE_RAW_RECORD_WORDS - len(words)))]
    header = words[0]
    evt_code = header & 0xF
    evt = event_names.get(evt_code, "UNKNOWN")
    priv = artix7_priv_name((header >> 4) & 0x3)
    old_priv = artix7_priv_name((header >> 6) & 0x3)
    new_priv = artix7_priv_name((header >> 8) & 0x3)
    parser_warnings = []
    if evt == "UNKNOWN":
        parser_warnings.append("unknown_event_code")
    event: dict[str, object] = {
        "cycle": words[1],
        "evt": evt,
        "evt_code": evt_code,
        "pc": artix7_pc_hex(words[2]),
        "parser_warnings": parser_warnings,
        "raw_header": artix7_hex32(header),
        "raw_words": [artix7_hex32(word) for word in original_words],
        "record_index": index,
    }
    if evt == "SYSCALL_ENTRY":
        event.update(
            {
                "instr": artix7_hex32(words[3]),
                "priv": priv,
                "syscall_id": artix7_hex32(words[6]),
                **{f"a{arg}": artix7_hex32(words[8 + arg]) for arg in range(8)},
            }
        )
    elif evt == "SYSCALL_RET":
        event.update(
            {
                "instr": artix7_hex32(words[3]),
                "priv": priv,
                "syscall_id": artix7_hex32(words[6]),
                "target": artix7_pc_hex(words[4]),
                "duration": words[5],
                **{f"a{arg}": artix7_hex32(words[8 + arg]) for arg in range(8)},
            }
        )
    elif evt == "TRAP":
        event.update(
            {
                "instr": artix7_hex32(words[3]),
                "cause": artix7_hex32(words[4]),
                "tval": artix7_hex32(words[5]),
                "priv": priv,
                "syscall_id": artix7_hex32(words[6]),
                **{f"a{arg}": artix7_hex32(words[8 + arg]) for arg in range(8)},
            }
        )
    elif evt in {"RETIRE", "BRANCH", "JUMP"}:
        event.update({"instr": artix7_hex32(words[3]), "priv": priv})
        if evt in {"BRANCH", "JUMP"}:
            event["target"] = artix7_pc_hex(words[4])
        if evt == "BRANCH":
            event["taken"] = bool(words[5] & 1)
    elif evt == "CSR":
        event.update({"csr": artix7_hex32(words[4]), "value": artix7_hex32(words[5]), "priv": priv})
    elif evt == "SATP":
        event.update({"satp": artix7_hex32(words[4]), "priv": priv})
    elif evt == "ARG_MEM":
        event.update(
            {
                "priv": priv,
                "syscall_id": artix7_hex32(words[6]),
                "arg_index": words[3] & 0x7,
                "mem_addr": artix7_pc_hex(words[4]),
                "mem_data": artix7_hex32(words[5]),
                "mem_size": words[7] & 0xff,
                "mem_last": bool(words[7] & 0x100),
            }
        )
    elif evt == "PRIV":
        event.update({"old_priv": old_priv, "new_priv": new_priv, "target": artix7_pc_hex(words[4])})
    elif evt == "DROP":
        event.update({"value": artix7_hex32(words[7] or words[6] or index)})
    elif evt == "MARKER":
        event.update({"value": artix7_hex32(words[7] or words[6] or words[4])})
    return event


def convert_artix7_raw_trace_to_jsonl(raw_path: Path, jsonl_path: Path) -> int:
    events: list[dict[str, object]] = []
    pending_scalar: str | None = None
    for line in raw_path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = re.sub(r"\[[0-9.]+\]", " ", line).strip()
        if not stripped:
            continue
        same_line_drop = re.search(r"\bRVMT_TRACE_DROP\s+(?:0x)?([0-9a-fA-F]+)\b", stripped)
        if same_line_drop:
            events.append({"cycle": 0, "evt": "DROP", "value": f"0x{int(same_line_drop.group(1), 16):x}"})
            pending_scalar = None
            continue
        if pending_scalar is not None:
            scalar_match = re.match(r"^0x[0-9a-fA-F]+$", stripped)
            if scalar_match:
                if pending_scalar == "RVMT_TRACE_DROP":
                    events.append({"cycle": 0, "evt": "DROP", "value": f"0x{int(stripped, 16):x}"})
                pending_scalar = None
                continue
        if stripped == "RVMT_TRACE_DROP":
            pending_scalar = stripped
            continue
        if stripped.startswith("{"):
            value = json.loads(stripped)
            if isinstance(value, dict):
                events.append(value)
            continue
        match = re.search(r"RVMT_TRACE_RECORD\s+(\d+)\s+(.+)$", stripped)
        if not match:
            continue
        index_text = match.group(1)
        payload_text = match.group(2)
        if len(index_text) > 8 and index_text.isdigit():
            payload_text = f"{index_text[-8:]} {payload_text}"
            index_text = index_text[:-8]
        word_tokens = re.findall(r"\b[0-9a-fA-F]{8}\b", payload_text)
        words = [int(item, 16) for item in word_tokens[:ARTIX7_TRACE_RAW_RECORD_WORDS]]
        if len(words) not in (8, ARTIX7_TRACE_RAW_RECORD_WORDS):
            events.append(
                {
                    "cycle": 0,
                    "evt": "UNKNOWN",
                    "evt_code": None,
                    "parser_warnings": ["corrupt_raw_record_word_count"],
                    "raw_header": artix7_hex32(words[0]) if words else None,
                    "raw_words": [artix7_hex32(word) for word in words],
                    "record_index": int(index_text),
                }
            )
            continue
        events.append(raw_trace_record_to_event(int(index_text), words))
    jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    jsonl_path.write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in events), encoding="utf-8", newline="\n")
    return len(events)


def task_artix7_trace_jsonl_compare(root: Path, config: dict, env: dict[str, str], args: argparse.Namespace) -> None:
    record_artix7_board_identity(root, config, env, args, args.dry_run)
    step_dir = artix7_step_dir(root, args, "08_trace_jsonl_compare")
    raw_path = step_dir / "trace_raw_uart.log"
    jsonl_path = artix7_trace_jsonl_path(root, args)
    parse_log = step_dir / "parse_trace_summary.log"
    recover_dir = step_dir / "behavior_recovery"
    lightweight_dir = step_dir / "lightweight"
    lightweight_log = step_dir / "lightweight_board_minimal.log"
    if args.dry_run:
        print(f"+ convert {quote_for_display(str(raw_path))} to {quote_for_display(str(jsonl_path))}")
        print(f"+ {sys.executable} tools/parse_trace.py {quote_for_display(str(jsonl_path))} --summary > {quote_for_display(str(parse_log))}")
        print(
            f"+ {sys.executable} tools/analyze_trace_lightweight.py --trace {quote_for_display(str(jsonl_path))} "
            f"--out-dir {quote_for_display(str(lightweight_dir))} --profile board_minimal > {quote_for_display(str(lightweight_log))}"
        )
        return
    if not raw_path.exists():
        raise TaskError(f"Missing raw trace dump: {raw_path}. Run board:artix7:trace-dump first.")
    count = convert_artix7_raw_trace_to_jsonl(raw_path, jsonl_path)
    if count == 0:
        write_artix7_observation(step_dir, "FAIL", [f"- No trace events were converted from `{raw_path}`."])
        raise TaskError("No trace events converted")
    run_capture([sys.executable, "tools/parse_trace.py", str(jsonl_path), "--summary"], cwd=root, env=env, dry_run=False, log_path=parse_log)
    recover_log = step_dir / "recover_behavior.log"
    run_capture([sys.executable, "tools/recover_behavior.py", "--trace", str(jsonl_path), "--out-dir", str(recover_dir)], cwd=root, env=env, dry_run=False, log_path=recover_log)
    run_capture(
        [
            sys.executable,
            "tools/analyze_trace_lightweight.py",
            "--trace",
            str(jsonl_path),
            "--out-dir",
            str(lightweight_dir),
            "--profile",
            "board_minimal",
        ],
        cwd=root,
        env=env,
        dry_run=False,
        log_path=lightweight_log,
    )
    write_artix7_observation(
        step_dir,
        "PASS",
        [
            f"- Converted `{raw_path}` to `{jsonl_path}`.",
            f"- Event count: `{count}`.",
            f"- Parser summary: `{parse_log}`.",
            f"- Board-minimal lightweight profile: `{lightweight_dir}`.",
            f"- Behavior recovery output: `{recover_dir}`.",
        ],
    )


def normalize_vivado_source_path(fpga_dir: Path, repo_root: Path, value: str) -> Path:
    raw = value.strip().replace("\\", "/")
    lower = raw.lower()
    if lower.startswith("/r/"):
        return repo_root / raw[3:]
    if lower.startswith("r:/"):
        return repo_root / raw[3:]

    drive_slash = re.match(r"^/([a-zA-Z])/(.*)$", raw)
    if drive_slash:
        return Path(f"{drive_slash.group(1).upper()}:/{drive_slash.group(2)}")

    if re.match(r"^[a-zA-Z]:/", raw):
        return Path(raw)

    return fpga_dir / raw


def parse_vivado_add_sources(fpga_dir: Path, repo_root: Path, add_sources: Path) -> tuple[dict[str, list[Path]], list[str]]:
    grouped: dict[str, list[Path]] = {"VHDL": [], "Verilog": [], "SystemVerilog": []}
    missing: list[str] = []
    seen: set[str] = set()

    for line in add_sources.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        file_type = ""
        payload = ""
        match = re.fullmatch(r"read_vhdl\s+\{(.*)\}", line)
        if match:
            file_type = "VHDL"
            payload = match.group(1)
        else:
            match = re.fullmatch(r"read_verilog\s+-sv\s+\{(.*)\}", line)
            if match:
                file_type = "SystemVerilog"
                payload = match.group(1)
            else:
                match = re.fullmatch(r"read_verilog\s+\{(.*)\}", line)
                if match:
                    file_type = "Verilog"
                    payload = match.group(1)

        if not file_type:
            continue

        for raw in payload.split():
            source = normalize_vivado_source_path(fpga_dir, repo_root, raw)
            key = normalize_windows_path(source)
            if key in seen:
                continue
            seen.add(key)
            if source.exists():
                grouped[file_type].append(source)
            else:
                missing.append(raw)

    return grouped, missing


def board_constraint_and_header_files(fpga_dir: Path, cva6_dir: Path, board: str) -> tuple[list[Path], list[Path]]:
    board_map = {
        "genesys2": "genesysii",
        "kc705": "kc705",
        "vc707": "vc707",
        "nexys_video": "nexys_video",
    }
    board_file = board_map.get(board)
    constraints = [fpga_dir / "constraints" / "ariane.xdc"]
    headers = [cva6_dir / "vendor" / "pulp-platform" / "common_cells" / "include" / "common_cells" / "registers.svh"]
    if board_file:
        constraints.insert(0, fpga_dir / "constraints" / f"{board_file if board_file != 'genesysii' else 'genesys-2'}.xdc")
        headers.insert(0, fpga_dir / "src" / f"{board_file}.svh")
    return constraints, headers


def include_dirs(fpga_dir: Path, cva6_dir: Path) -> list[Path]:
    return [
        fpga_dir / "src" / "axi_sd_bridge" / "include",
        cva6_dir / "vendor" / "pulp-platform" / "common_cells" / "include",
        cva6_dir / "vendor" / "pulp-platform" / "axi" / "include",
        cva6_dir / "core" / "cache_subsystem" / "hpdcache" / "rtl" / "include",
        cva6_dir / "corev_apu" / "register_interface" / "include",
        cva6_dir / "corev_apu" / "instr_tracing" / "ITI" / "include",
        cva6_dir / "core" / "include",
    ]


def vivado_project_import_script(root: Path, config: dict, project_dir: Path) -> tuple[str, int, int]:
    cva6_dir = configured_path(root, str(config.get("cva6_dir", "rtl/cva6")), must_exist=True)
    fpga_dir = cva6_dir / "corev_apu" / "fpga"
    add_sources = fpga_dir / "scripts" / "add_sources.tcl"
    if not add_sources.exists():
        raise TaskError(f"Missing source list: {add_sources}. Run 'uv run rvmt bitstream:build' first.")

    grouped, missing = parse_vivado_add_sources(fpga_dir, root, add_sources)
    board = str(config.get("board", "genesys2"))
    constraints, headers = board_constraint_and_header_files(fpga_dir, cva6_dir, board)
    constraints = [path for path in constraints if path.exists()]
    headers = [path for path in headers if path.exists()]
    ip_files = sorted(fpga_dir.glob("xilinx/*/*.srcs/sources_1/ip/*/*.xci"))
    source_count = sum(len(files) for files in grouped.values()) + len(headers) + len(ip_files)

    repo_paths = vivado_board_repo_paths(root, config)
    repo_line = f"set_param board.repoPaths {tcl_list(repo_paths)}" if repo_paths else ""
    xpart, xboard = xilinx_settings(config)
    script = f"""
set rvmt_source_count 0
set rvmt_constraint_count 0
{repo_line}
file mkdir {tcl_braced(project_dir)}
create_project ariane {tcl_braced(project_dir)} -force -part {tcl_braced(xpart)}
set_property board_part {tcl_braced(xboard)} [current_project]

proc rvmt_add_files {{files file_type fileset}} {{
  if {{[llength $files] == 0}} {{
    return
  }}
  add_files -fileset $fileset -norecurse $files
  if {{$file_type ne ""}} {{
    foreach file $files {{
      set objects [get_files -quiet [file normalize $file]]
      if {{[llength $objects] > 0}} {{
        set_property file_type $file_type $objects
      }}
    }}
  }}
}}

rvmt_add_files {tcl_list(grouped["VHDL"])} VHDL sources_1
rvmt_add_files {tcl_list(grouped["Verilog"])} Verilog sources_1
rvmt_add_files {tcl_list(grouped["SystemVerilog"])} SystemVerilog sources_1
rvmt_add_files {tcl_list(headers)} {{Verilog Header}} sources_1
foreach file {tcl_list(headers)} {{
  set objects [get_files -quiet [file normalize $file]]
  if {{[llength $objects] > 0}} {{
    set_property is_global_include true $objects
  }}
}}
rvmt_add_files {tcl_list(ip_files)} "" sources_1
rvmt_add_files {tcl_list(constraints)} "" constrs_1

set_property include_dirs {tcl_list(include_dirs(fpga_dir, cva6_dir))} [get_filesets sources_1]
set_property top ariane_xilinx [get_filesets sources_1]
update_compile_order -fileset sources_1
puts "RVMT_PROJECT_SOURCES=[llength [get_files -quiet -of_objects [get_filesets sources_1]]]"
puts "RVMT_PROJECT_CONSTRAINTS=[llength [get_files -quiet -of_objects [get_filesets constrs_1]]]"
close_project
"""
    return script, source_count, len(missing)


def task_vivado_check(root: Path, config: dict, env: dict[str, str], dry_run: bool) -> None:
    vivado = resolve_vivado(config)
    xpart, xboard = xilinx_settings(config)
    board_repos = vivado_board_repo_paths(root, config)
    if dry_run:
        print(
            f"+ {quote_for_display(vivado)} -mode batch -source <vivado-check.tcl> "
            f"# XILINX_PART={xpart} XILINX_BOARD={xboard}"
        )
        return

    env = prepend_env_path(env, Path(vivado).parent)
    script = "\n".join(
        [
            f"set rvmt_part {tcl_braced(xpart)}",
            f"set rvmt_board {tcl_braced(xboard)}",
            "set rvmt_failed 0",
            (
                "set_param board.repoPaths [list "
                + " ".join(tcl_braced(as_posix_path(path)) for path in board_repos)
                + "]"
                if board_repos
                else ""
            ),
            "if {[llength [get_parts -quiet $rvmt_part]] == 0} {",
            "  puts \"RVMT_MISSING_PART=$rvmt_part\"",
            "  set rvmt_failed 1",
            "} else {",
            "  puts \"RVMT_PART_OK=$rvmt_part\"",
            "}",
            "if {[llength [get_board_parts -quiet $rvmt_board]] == 0} {",
            "  puts \"RVMT_MISSING_BOARD=$rvmt_board\"",
            "  set rvmt_failed 1",
            "} else {",
            "  puts \"RVMT_BOARD_OK=$rvmt_board\"",
            "}",
            "if {$rvmt_failed} { exit 12 }",
        ]
    )

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".tcl", delete=False) as tcl_file:
        tcl_file.write(script)
        tcl_path = Path(tcl_file.name)

    cmd = [vivado, "-mode", "batch", "-nojournal", "-nolog", "-notrace", "-source", str(tcl_path)]
    print("+ " + " ".join(quote_for_display(part) for part in cmd))
    try:
        completed = subprocess.run(
            cmd,
            cwd=str(root),
            env=env,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
        )
    finally:
        try:
            tcl_path.unlink()
        except OSError:
            pass

    output = "\n".join(part for part in (completed.stdout, completed.stderr) if part)
    markers = [line.strip() for line in output.splitlines() if line.startswith("RVMT_")]
    for marker in markers:
        if marker.startswith("RVMT_PART_OK="):
            print(f"Vivado part OK: {marker.split('=', 1)[1]}")
        elif marker.startswith("RVMT_BOARD_OK="):
            print(f"Vivado board part OK: {marker.split('=', 1)[1]}")

    if completed.returncode:
        missing = []
        for marker in markers:
            if marker.startswith("RVMT_MISSING_PART="):
                missing.append(f"missing Vivado part: {marker.split('=', 1)[1]}")
            elif marker.startswith("RVMT_MISSING_BOARD="):
                missing.append(f"missing Vivado board part: {marker.split('=', 1)[1]}")
        details = "\n- ".join(missing) if missing else output.strip()
        if details:
            raise TaskError(f"Vivado preflight failed:\n- {details}")
        raise TaskError(f"Vivado preflight failed with exit code {completed.returncode}")


def task_vivado_project(root: Path, config: dict, env: dict[str, str], dry_run: bool) -> None:
    vivado = resolve_vivado(config)
    cva6_dir = configured_path(root, str(config.get("cva6_dir", "rtl/cva6")), must_exist=not dry_run)
    fpga_dir = cva6_dir / "corev_apu" / "fpga"
    project_dir = vivado_project_dir(root, config)
    xpr = vivado_project_xpr(root, config)
    if dry_run:
        print(f"+ {quote_for_display(vivado)} -mode batch -source <vivado-project-import.tcl> # {xpr}")
        return

    project_dir.mkdir(parents=True, exist_ok=True)
    script, expected_sources, missing_sources = vivado_project_import_script(root, config, project_dir)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".tcl", delete=False) as tcl_file:
        tcl_file.write(script)
        tcl_path = Path(tcl_file.name)

    cmd = [vivado, "-mode", "batch", "-nojournal", "-nolog", "-notrace", "-source", str(tcl_path)]
    print("+ " + " ".join(quote_for_display(part) for part in cmd))
    try:
        completed = subprocess.run(
            cmd,
            cwd=str(root),
            env=prepend_env_path(env, Path(vivado).parent),
            capture_output=True,
            encoding="utf-8",
            errors="replace",
        )
    finally:
        try:
            tcl_path.unlink()
        except OSError:
            pass

    output = "\n".join(part for part in (completed.stdout, completed.stderr) if part)
    markers = [line.strip() for line in output.splitlines() if line.startswith("RVMT_")]
    for marker in markers:
        print(marker.replace("RVMT_PROJECT_SOURCES=", "Vivado project sources: ").replace(
            "RVMT_PROJECT_CONSTRAINTS=", "Vivado project constraints: "
        ))

    if completed.returncode:
        details = "\n".join(markers) or output.strip()
        raise TaskError(f"Vivado project import failed with exit code {completed.returncode}:\n{details}")

    if missing_sources:
        print(f"rvmt: warning: {missing_sources} source paths from add_sources.tcl were missing.", file=sys.stderr)
    transient_xpr = fpga_dir / "ariane.xpr"
    if transient_xpr.exists():
        transient_xpr.unlink()
    print(f"Vivado project ready: {xpr}")
    print(f"Expected imported source-like files: {expected_sources}")


def task_bitstream_build(
    root: Path,
    config: dict,
    env: dict[str, str],
    dry_run: bool,
    *,
    trace_enabled: bool = False,
    trace_marker_scope: bool = False,
    trace_source_lines: bool = False,
) -> None:
    if trace_source_lines:
        trace_enabled = True
        trace_marker_scope = True
    subst_drive = vivado_subst_drive(config)
    subst_before = current_subst_mappings() if subst_drive and not dry_run else {}
    work_root = vivado_work_root(root, config, dry_run=dry_run)
    release_drive = subst_drive if subst_drive and not dry_run and subst_drive not in subst_before else None
    try:
        cva6_dir = configured_path(work_root, str(config.get("cva6_dir", "rtl/cva6")), must_exist=not dry_run)
        xlen = int(config.get("xlen", 64))
        bootrom = cva6_dir / "corev_apu" / "fpga" / "src" / "bootrom" / f"bootrom_{xlen}.sv"
        if not bootrom.exists() and not dry_run:
            raise TaskError(
                f"Missing {bootrom}. Run 'uv run rvmt bootrom:build' before bitstream:build."
            )

        fpga_dir = cva6_dir / "corev_apu" / "fpga"
        if trace_source_lines:
            artifact_dir = trace_source_lines_vivado_artifact_dir(work_root, config)
            real_artifact_dir = trace_source_lines_vivado_artifact_dir(root, config)
        elif trace_marker_scope:
            artifact_dir = trace_marker_vivado_artifact_dir(work_root, config)
            real_artifact_dir = trace_marker_vivado_artifact_dir(root, config)
        elif trace_enabled:
            artifact_dir = trace_vivado_artifact_dir(work_root, config)
            real_artifact_dir = trace_vivado_artifact_dir(root, config)
        else:
            artifact_dir = vivado_artifact_dir(work_root, config)
            real_artifact_dir = vivado_artifact_dir(root, config)
        vivado_work_dir = artifact_dir / "work-fpga"
        vivado_report_dir = artifact_dir / "reports"
        work_dir_arg = makefile_relative_path(vivado_work_dir, fpga_dir)

        vivado_config = str(config.get("vivado", "vivado"))
        make = resolve_make(root, config)
        board = str(config.get("board", "genesys2"))
        target = str(config.get("target", "cv64a6_imafdc_sv39"))
        riscv = str(config.get("riscv_placeholder", "/tmp/riscv-placeholder"))
        xpart, xboard = xilinx_settings(config)
        verilog_defines: list[str] = []
        if trace_enabled:
            verilog_defines.append("RV_MALTRACE_FPGA_TRACE")
            if trace_marker_scope:
                verilog_defines.append("RV_MALTRACE_FPGA_TRACE_MARKER_SCOPE")
            if trace_source_lines:
                verilog_defines.append("RV_MALTRACE_FPGA_TRACE_SOURCE_LINES")
        if not dry_run:
            artifact_dir.mkdir(parents=True, exist_ok=True)
            if not trace_enabled:
                seed_existing_vivado_artifacts(fpga_dir, artifact_dir)
            else:
                for stale in (
                    vivado_work_dir / "ariane_xilinx.bit",
                    vivado_work_dir / "ariane_xilinx.mcs",
                    vivado_work_dir / "ariane_xilinx.dcp",
                ):
                    if stale.exists():
                        stale.unlink()
            task_vivado_check(work_root, config, env, dry_run=False)
            add_sources = cva6_dir / "corev_apu" / "fpga" / "scripts" / "add_sources.tcl"
            if add_sources.exists():
                os.chmod(add_sources, 0o666)
                add_sources.unlink()
        vivado = vivado_config
        if not dry_run:
            real_vivado = resolve_vivado(config)
            vivado = prepare_vivado_wrapper(work_root, config, real_vivado)
            wrapper_dir = prepare_msys_python_wrapper(work_root)
            env = prepend_env_path(env, wrapper_dir, Path(vivado).parent, Path(real_vivado).parent)
            env = env.copy()
            env["RVMT_VIVADO_WORK_DIR"] = as_posix_path(vivado_work_dir)
            env["RVMT_VIVADO_REPORT_DIR"] = as_posix_path(vivado_report_dir)
            env["RVMT_VIVADO_PATCH_DIR"] = as_posix_path(artifact_dir / ".tmp")
            if verilog_defines:
                env["RVMT_VIVADO_VERILOG_DEFINES"] = ",".join(verilog_defines)
            if trace_enabled:
                refresh_xlnx_ila_ip(cva6_dir, env, real_vivado, xpart, xboard, dry_run=False)
                sync_xlnx_ila_artifact_xci(cva6_dir, vivado_work_dir, dry_run=False)
        elif trace_enabled:
            refresh_xlnx_ila_ip(cva6_dir, env, vivado_config, xpart, xboard, dry_run=True)
            sync_xlnx_ila_artifact_xci(cva6_dir, vivado_work_dir, dry_run=True)

        run(
            [
                make,
                f"MAKE={Path(make).name}",
                f"BOARD={board}",
                f"XILINX_PART={xpart}",
                f"XILINX_BOARD={xboard}",
                f"target={target}",
                f"RISCV={riscv}",
                f"VIVADO={as_posix_path(vivado)}",
                f"work-dir={work_dir_arg}",
                *(["RV_MALTRACE_FPGA_TRACE=1"] if trace_enabled else []),
                *([f"RVMT_VIVADO_VERILOG_DEFINES={','.join(verilog_defines)}"] if verilog_defines else []),
                "fpga",
            ],
            cwd=cva6_dir,
            env=env,
            dry_run=dry_run,
        )
        if not dry_run:
            project = cva6_dir / "corev_apu" / "fpga" / "ariane.xpr"
            make_vivado_project_portable(project, work_root, root)
            if bool(config.get("vivado_populate_project", True)) and not trace_enabled:
                task_vivado_project(root, config, env, dry_run=False)
            if work_root != root:
                print_vivado_artifact_summary(real_artifact_dir)
            else:
                print_vivado_artifact_summary(artifact_dir)
            if trace_marker_scope:
                write_trace_marker_build_manifest(
                    artifact_dir,
                    source_root=work_root,
                    cva6_dir=cva6_dir,
                    board=board,
                    target=target,
                    xpart=xpart,
                    xboard=xboard,
                    verilog_defines=verilog_defines,
                )
    finally:
        if release_drive:
            release_subst_mapping(release_drive, root)


def task_bitstream_collect(root: Path, config: dict, dry_run: bool) -> None:
    cva6_dir = configured_path(root, str(config.get("cva6_dir", "rtl/cva6")), must_exist=not dry_run)
    fpga_dir = cva6_dir / "corev_apu" / "fpga"
    artifact_dir = vivado_artifact_dir(root, config)
    if dry_run:
        print(f"+ collect Vivado artifacts from {fpga_dir} to {artifact_dir}")
        return

    collect_vivado_artifacts(fpga_dir, artifact_dir)
    print_vivado_artifact_summary(artifact_dir)


def task_sim_trace_unit(root: Path, config: dict, env: dict[str, str], dry_run: bool) -> None:
    vivado = resolve_vivado(config)
    env = prepend_env_path(env, Path(vivado).parent)
    env = env.copy()
    env["PYTHON"] = sys.executable
    run(
        [
            vivado,
            "-mode",
            "batch",
            "-nojournal",
            "-nolog",
            "-notrace",
            "-source",
            "sim/vivado/run_all_tests.tcl",
        ],
        cwd=root,
        env=env,
        dry_run=dry_run,
    )
    if not dry_run:
        task_sim_summary(root, env, dry_run=False)


def task_sim_cva6_smoke(
    root: Path,
    config: dict,
    env: dict[str, str],
    dry_run: bool,
    runner_args: list[str] | None = None,
    work_dir: Path | None = None,
) -> None:
    vivado = resolve_vivado(config)
    env = prepend_env_path(env, Path(vivado).parent)
    resolved_work_dir = work_dir or Path(str(config.get("build_dir", "build"))) / "cva6_xsim_smoke"
    try:
        run(
            [
                sys.executable,
                "tools/run_cva6_xsim.py",
                "--vivado-bin",
                str(Path(vivado).parent),
                "--cva6",
                str(config.get("cva6_dir", "rtl/cva6")),
                "--target",
                str(config.get("target", "cv64a6_imafdc_sv39")),
                "--work-dir",
                str(resolved_work_dir),
                *(runner_args or []),
                *(("--dry-run",) if dry_run else ()),
            ],
            cwd=root,
            env=env,
            dry_run=False,
        )
    except TaskError:
        if not dry_run:
            task_sim_summary(root, env, dry_run=False)
        raise
    if not dry_run:
        task_sim_summary(root, env, dry_run=False)


def task_sim_cva6_full_soc(root: Path, config: dict, env: dict[str, str], dry_run: bool) -> None:
    build_dir = Path(str(config.get("build_dir", "build")))
    task_sim_cva6_smoke(
        root,
        config,
        env,
        dry_run,
        ["--full-soc-smoke"],
        work_dir=build_dir / "cva6_xsim_full_soc",
    )


def task_sim_cva6_full_soc_store(root: Path, config: dict, env: dict[str, str], dry_run: bool) -> None:
    build_dir = Path(str(config.get("build_dir", "build")))
    task_sim_cva6_smoke(
        root,
        config,
        env,
        dry_run,
        [
            "--full-soc-smoke",
            "--full-soc-store-path-only",
            "--mem",
            "sim/programs/full_soc_uart_store_path/full_soc_uart_store_path.mem",
            "--name",
            "uart_store_path",
        ],
        work_dir=build_dir / "cva6_xsim_full_soc_uart_store_path",
    )


def task_sim_cva6_full_soc_tohost(root: Path, config: dict, env: dict[str, str], dry_run: bool) -> None:
    build_dir = Path(str(config.get("build_dir", "build")))
    task_sim_cva6_smoke(
        root,
        config,
        env,
        dry_run,
        [
            "--full-soc-smoke",
            "--mem",
            "sim/programs/full_soc_dram_tohost/full_soc_dram_tohost.mem",
            "--name",
            "tohost_normal",
        ],
        work_dir=build_dir / "cva6_xsim_full_soc_tohost_normal",
    )


def task_sim_cva6_full_soc_rv64gc(root: Path, config: dict, env: dict[str, str], dry_run: bool) -> None:
    build_dir = Path(str(config.get("build_dir", "build")))
    task_sim_cva6_smoke(
        root,
        config,
        env,
        dry_run,
        [
            "--full-soc-smoke",
            "--full-soc-rv64gc-suite",
            "--full-soc-allow-suite-blocked",
            "--run-timeout-seconds",
            "120",
        ],
        work_dir=build_dir / "cva6_xsim_full_soc_rv64gc_gate2",
    )


def custom_cva6_runner_args(args: argparse.Namespace, config: dict) -> list[str]:
    selected_inputs = sum(value is not None for value in (args.asm, args.elf, args.bin, args.mem))
    if selected_inputs != 1:
        raise TaskError("sim:cva6-run requires exactly one of --asm, --elf, --bin, or --mem.")
    runner_args: list[str] = []
    for option, value in (
        ("--asm", args.asm),
        ("--elf", args.elf),
        ("--bin", args.bin),
        ("--mem", args.mem),
        ("--name", args.name),
        ("--expected", args.expected),
        ("--linker", args.linker),
        ("--tool-mode", args.tool_mode),
    ):
        if value is not None:
            runner_args.extend([option, str(value)])
    tool_prefix = args.tool_prefix if args.tool_prefix is not None else str(config.get("baremetal_tool_prefix", "riscv-none-elf-"))
    runner_args.extend(["--tool-prefix", tool_prefix])
    for include in args.include:
        runner_args.extend(["--include", str(include)])
    for cflag in args.cflag:
        runner_args.extend(["--cflag", cflag])
    if args.no_runtime:
        runner_args.append("--no-runtime")
    return runner_args


def task_sim_summary(root: Path, env: dict[str, str], dry_run: bool) -> None:
    run(
        [
            sys.executable,
            "tools/summarize_results.py",
            "results/vivado_sim",
            "--out",
            "results/vivado_sim/summary.json",
        ],
        cwd=root,
        env=env,
        dry_run=dry_run,
    )


def task_baremetal_build(root: Path, config: dict, env: dict[str, str], dry_run: bool) -> None:
    tool_prefix = str(config.get("baremetal_tool_prefix", "riscv-none-elf-"))
    run(
        [sys.executable, "tools/build_baremetal.py", "--all", "--tool-prefix", tool_prefix],
        cwd=root,
        env=env,
        dry_run=dry_run,
    )


def load_json_file(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def demo_run_dir(root: Path, out_dir: Path | None, run_id: str | None, sample: str) -> Path:
    base = out_dir or Path("results/demo")
    if not base.is_absolute():
        base = root / base
    return base / (run_id or "manual") / sample


def demo_fixture_trace(root: Path, sample: str) -> Path:
    path = root / "sim" / "golden" / "demo_behavior" / f"{sample}.trace.jsonl"
    if not path.exists():
        raise TaskError(f"No demo fixture trace for sample '{sample}': {path}")
    return path


def demo_manifest_sample(root: Path, sample: str) -> dict:
    manifest_path = root / "experiments" / "linux_behavior" / "malware_like" / "manifest.json"
    manifest = load_json_file(manifest_path)
    samples = manifest.get("samples", [])
    if not isinstance(samples, list):
        raise TaskError(f"{manifest_path}: samples must be a list")
    for item in samples:
        if isinstance(item, dict) and item.get("id") == sample:
            return item
    raise TaskError(f"Unknown malware-like synthetic sample '{sample}' in {manifest_path}")


def cli_sample_values(args: argparse.Namespace) -> list[str]:
    value = args.sample
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item]
    return [str(value)]


def cli_primary_sample(args: argparse.Namespace, default: str) -> str:
    values = cli_sample_values(args)
    return values[-1] if values else default


def task_demo_behavior(root: Path, env: dict[str, str], args: argparse.Namespace) -> None:
    sample = cli_primary_sample(args, "anti_debug_like")
    run_dir = demo_run_dir(root, args.out_dir, args.run_id, sample)
    trace_dir = run_dir / "02_trace"
    semantic_dir = run_dir / "03_semantic"
    audit_dir = run_dir / "04_audit"
    visual_dir = run_dir / "05_visual"
    if args.backend == "fixture":
        source_trace = demo_fixture_trace(root, sample)
    elif args.backend == "trace":
        if args.trace is None:
            raise TaskError("demo:behavior --backend trace requires --trace <path>.")
        source_trace = args.trace if args.trace.is_absolute() else root / args.trace
        if not source_trace.exists():
            raise TaskError(f"Trace does not exist: {source_trace}")
    else:
        raise TaskError(f"Unsupported demo backend: {args.backend}")

    trace_path = trace_dir / "trace.jsonl"
    print(f"+ copy {quote_for_display(str(source_trace))} {quote_for_display(str(trace_path))}")
    if not args.dry_run:
        trace_dir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_trace, trace_path)

    run(
        [sys.executable, "tools/recover_behavior.py", "--trace", str(trace_path), "--out-dir", str(semantic_dir)],
        cwd=root,
        env=env,
        dry_run=args.dry_run,
    )
    run(
        [
            sys.executable,
            "tools/audit_behavior.py",
            "--semantic",
            str(semantic_dir / "semantic_events.json"),
            "--graph",
            str(semantic_dir / "behavior_graph.json"),
            "--manifest",
            "experiments/linux_behavior/malware_like/manifest.json",
            "--sample-id",
            sample,
            "--out-dir",
            str(audit_dir),
        ],
        cwd=root,
        env=env,
        dry_run=args.dry_run,
    )
    run(
        [
            sys.executable,
            "tools/render_behavior_demo.py",
            "--trace",
            str(trace_path),
            "--semantic",
            str(semantic_dir / "semantic_events.json"),
            "--graph",
            str(semantic_dir / "behavior_graph.json"),
            "--audit",
            str(audit_dir / "behavior_audit.json"),
            "--manifest",
            "experiments/linux_behavior/malware_like/manifest.json",
            "--sample-id",
            sample,
            "--out-dir",
            str(visual_dir),
        ],
        cwd=root,
        env=env,
        dry_run=args.dry_run,
    )
    print(f"demo behavior artifacts: {run_dir}")


def task_demo_groundtruth(root: Path, config: dict, env: dict[str, str], args: argparse.Namespace) -> None:
    sample = cli_primary_sample(args, "anti_debug_like")
    sample_spec = demo_manifest_sample(root, sample)
    source = str(sample_spec.get("source", ""))
    if not source:
        raise TaskError(f"Sample '{sample}' does not define a source path")
    source_path = root / source
    if not source_path.exists():
        raise TaskError(f"Sample source does not exist: {source_path}")

    run_dir = demo_run_dir(root, args.out_dir, args.run_id, sample)
    build_dir = run_dir / "00_build"
    groundtruth_dir = run_dir / "01_ground_truth"
    build_posix = as_posix_path(build_dir.relative_to(root) if build_dir.is_relative_to(root) else build_dir)
    groundtruth_posix = as_posix_path(groundtruth_dir.relative_to(root) if groundtruth_dir.is_relative_to(root) else groundtruth_dir)
    source_posix = as_posix_path(source)
    shell = f"""
set -eu
sample={shell_single_quoted(sample)}
source_path={shell_single_quoted(source_posix)}
build_dir={shell_single_quoted(build_posix)}
groundtruth_dir={shell_single_quoted(groundtruth_posix)}
mkdir -p "$build_dir" "$groundtruth_dir"
sha256sum "$source_path" > "$build_dir/source.sha256"
gcc --version | head -n 1 > "$build_dir/compiler.txt"
riscv64-linux-gnu-gcc --version | head -n 1 >> "$build_dir/compiler.txt"
gcc -O2 -Wall -Wextra -o "$build_dir/$sample.host" "$source_path"
riscv64-linux-gnu-gcc -O2 -static -o "$build_dir/$sample.riscv64" "$source_path"
sha256sum "$build_dir/$sample.host" > "$build_dir/host_elf.sha256"
sha256sum "$build_dir/$sample.riscv64" > "$build_dir/riscv64_elf.sha256"
set +e
strace -f -o "$groundtruth_dir/host.strace.log" "$build_dir/$sample.host" > "$groundtruth_dir/host.stdout.txt" 2> "$groundtruth_dir/host.stderr.txt"
host_code=$?
qemu-riscv64 -strace "$build_dir/$sample.riscv64" > "$groundtruth_dir/qemu-riscv64.stdout.txt" 2> "$groundtruth_dir/qemu-riscv64.strace.log"
qemu_code=$?
set -e
printf 'host_exit_code=%s\\nqemu_riscv64_exit_code=%s\\n' "$host_code" "$qemu_code" > "$groundtruth_dir/exit-codes.txt"
exit 0
""".strip()
    run(
        [
            *docker_compose_base(config),
            "run",
            "--rm",
            "--build",
            "linux-behavior",
            "bash",
            "-lc",
            shell,
        ],
        cwd=root,
        env=env,
        dry_run=args.dry_run,
    )
    print(f"demo groundtruth artifacts: {run_dir}")


def task_exp_35t(root: Path, env: dict[str, str], args: argparse.Namespace) -> None:
    cmd = [
        sys.executable,
        "tools/experiment_35t.py",
        "--stage",
        args.stage,
        "--run-id",
        args.run_id,
        "--port",
        args.port,
        "--reps",
        str(args.reps),
    ]
    if args.duration is not None:
        cmd.extend(["--duration", str(args.duration)])
    if args.trace_records is not None:
        cmd.extend(["--trace-records", str(args.trace_records)])
    if args.trace_profile is not None:
        cmd.extend(["--trace-profile", args.trace_profile])
    if args.trace_profile_policy is not None:
        cmd.extend(["--trace-profile-policy", args.trace_profile_policy])
    if args.runtime_order is not None:
        cmd.extend(["--runtime-order", args.runtime_order])
    if args.warmup is not None:
        cmd.extend(["--warmup", str(args.warmup)])
    if args.baud is not None:
        cmd.extend(["--baud", str(args.baud)])
    for sample in cli_sample_values(args):
        cmd.extend(["--sample", sample])
    if args.include_extension_samples:
        cmd.append("--include-extension-samples")
    if args.syscall_side_channel:
        cmd.append("--syscall-side-channel")
    if args.live_flow:
        cmd.append("--live-flow")
        cmd.extend(["--flow-detail", args.flow_detail])
    if args.dry_run:
        cmd.append("--dry-run")
    run(cmd, cwd=root, env=env, dry_run=False)


def task_explain_35t(root: Path, args: argparse.Namespace) -> None:
    from rv_maltrace.explain import (
        build_explanation,
        build_process_view,
        load_run_artifacts,
        load_sample_artifacts,
        render_console,
        render_markdown,
        render_process_console,
        render_process_markdown,
    )

    if args.flow:
        run_artifacts = load_run_artifacts(root, args.run_id)
        view = build_process_view(run_artifacts, strict=args.strict)
        if args.format == "json":
            text = json.dumps(view, indent=2, sort_keys=True) + "\n"
        elif args.format == "markdown":
            text = render_process_markdown(view)
        else:
            text = render_process_console(view, detail=args.detail)
    elif not args.sample:
        raise TaskError("explain:35t requires --sample")
    else:
        artifacts = load_sample_artifacts(root, args.run_id, args.sample[0], args.rep)
        explanation = build_explanation(artifacts, strict=args.strict)
        if args.format == "json":
            text = json.dumps(explanation, indent=2, sort_keys=True) + "\n"
        elif args.format == "markdown":
            text = render_markdown(explanation)
        else:
            text = render_console(explanation)

    if args.out:
        Path(args.out).write_text(text, encoding="utf-8", newline="\n")
        return
    print(text, end="")
    if args.tee_out:
        Path(args.tee_out).write_text(text, encoding="utf-8", newline="\n")


def show_config(root: Path, config: dict) -> None:
    cva6_dir = configured_path(root, str(config.get("cva6_dir", "rtl/cva6")))
    print(f"repo_root            = {root}")
    print(f"vivado_work_root     = {vivado_work_root(root, config, dry_run=True)}")
    print(f"docker              = {config.get('docker', 'docker')}")
    print(f"docker_compose_file = {config.get('docker_compose_file', 'docker-compose.toolchain.yml')}")
    print(f"docker_service      = {config.get('docker_service', 'cva6-toolchain')}")
    print(f"vivado              = {config.get('vivado', 'vivado')}")
    print(f"vivado_board_repos  = {[str(path) for path in vivado_board_repo_paths(root, config)]}")
    print(f"build_dir           = {configured_path(root, str(config.get('build_dir', 'build')))}")
    print(f"vivado_artifacts    = {vivado_artifact_dir(root, config)}")
    print(f"trace_artifacts     = {trace_vivado_artifact_dir(root, config)}")
    print(f"trace_marker_artifacts = {trace_marker_vivado_artifact_dir(root, config)}")
    print(f"trace_source_line_artifacts = {trace_source_lines_vivado_artifact_dir(root, config)}")
    print(f"vivado_project      = {vivado_project_xpr(root, config)}")
    print(f"make                = {config.get('make', 'make')}")
    print(f"make_path_prepend   = {config.get('make_path_prepend', [])}")
    print(f"make_resolved       = {resolve_make(root, config)}")
    print(f"cva6_dir            = {cva6_dir}")
    print(f"board               = {config.get('board', 'genesys2')}")
    xpart, xboard = xilinx_settings(config)
    print(f"xilinx_part         = {xpart}")
    print(f"xilinx_board        = {xboard}")
    print(f"target              = {config.get('target', 'cv64a6_imafdc_sv39')}")
    print(f"xlen                = {config.get('xlen', 64)}")
    print(f"toolchain_config    = {config.get('toolchain_config', 'gcc-13.1.0-baremetal')}")
    print(f"baremetal_tool_prefix = {config.get('baremetal_tool_prefix', 'riscv-none-elf-')}")
    print(f"num_jobs            = {config.get('num_jobs', 8)}")


def ps_single_quoted(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def shell_single_quoted(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def print_completion(shell: str) -> None:
    if shell == "powershell":
        candidates = ", ".join(ps_single_quoted(item) for item in COMPLETION_CANDIDATES)
        print(
            f"""# rvmt completion for PowerShell.
# Supports both:
#   rvmt <TAB>
#   uv run rvmt <TAB>
$script:RvmtCompletions = @({candidates})

function script:Complete-RvmtTask {{
    param($wordToComplete)
    $script:RvmtCompletions |
        Where-Object {{ $_ -like "$wordToComplete*" }} |
        ForEach-Object {{
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }}
}}

Register-ArgumentCompleter -Native -CommandName 'rvmt' -ScriptBlock {{
    param($wordToComplete, $commandAst, $cursorPosition)
    Complete-RvmtTask $wordToComplete
}}

Register-ArgumentCompleter -Native -CommandName 'uv' -ScriptBlock {{
    param($wordToComplete, $commandAst, $cursorPosition)
    $words = @($commandAst.CommandElements | ForEach-Object {{ $_.Extent.Text }})
    if ($words.Count -ge 3 -and $words[0] -eq 'uv' -and $words[1] -eq 'run' -and $words[2] -eq 'rvmt') {{
        Complete-RvmtTask $wordToComplete
    }}
}}
"""
        )
    elif shell == "bash":
        words = " ".join(COMPLETION_CANDIDATES)
        print(
            f"""# rvmt completion for Bash.
_rvmt_complete() {{
    local cur="${{COMP_WORDS[COMP_CWORD]}}"
    local first="${{COMP_WORDS[0]}}"
    local enabled=0

    if [[ "$first" == "rvmt" ]]; then
        enabled=1
    elif [[ "$first" == "uv" && "${{COMP_WORDS[1]}}" == "run" && "${{COMP_WORDS[2]}}" == "rvmt" ]]; then
        enabled=1
    fi

    if [[ "$enabled" == "1" ]]; then
        COMPREPLY=( $(compgen -W {shell_single_quoted(words)} -- "$cur") )
    fi
}}

complete -F _rvmt_complete rvmt
complete -F _rvmt_complete uv
"""
        )
    elif shell == "zsh":
        words = " ".join(COMPLETION_CANDIDATES)
        print(
            f"""# rvmt completion for Zsh.
_rvmt_complete() {{
  local -a candidates
  candidates=({words})
  _describe 'rvmt task' candidates
}}

compdef _rvmt_complete rvmt
compdef _rvmt_complete uv
"""
        )
    else:
        raise TaskError(f"Unsupported completion shell: {shell}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="rvmt",
        description="rv-maltrace build helper. Example: uv run rvmt docker:build bootrom:build",
    )
    parser.add_argument(
        "tasks",
        nargs="*",
        help=(
            "Tasks to run. Supports docker:build, toolchain:build, bootrom:build, "
            "vivado:check, bitstream:build, bitstream:build-trace, bitstream:build-trace-marker, "
            "bitstream:build-trace-source-lines, sim:trace-unit, sim:cva6-smoke, "
            "sim:cva6-full-soc, sim:cva6-full-soc-tohost, sim:cva6-full-soc-rv64gc, sim:cva6-run, baremetal:build, "
            "board:artix7:jtag-scan, board:artix7:litex-build, exp:35t, run:35t, explain:35t, config:show, completion:powershell. Slash groups such as "
            "tool/bootrom are expanded."
        ),
    )
    parser.add_argument("--dry-run", action="store_true", help="Print commands without running them.")
    parser.add_argument("--asm", type=Path, help="For sim:cva6-run, compile and run a custom RISC-V assembly source.")
    parser.add_argument("--elf", type=Path, help="For sim:cva6-run, run a custom RISC-V ELF image.")
    parser.add_argument("--bin", type=Path, help="For sim:cva6-run, run a custom raw binary image.")
    parser.add_argument("--mem", type=Path, help="For sim:cva6-run, run a custom $readmemh memory image.")
    parser.add_argument("--name", help="For sim:cva6-run, result directory name under results/vivado_sim/.")
    parser.add_argument("--expected", type=Path, help="For sim:cva6-run, optional JSON golden to compare against.")
    parser.add_argument("--tool-prefix", help="For sim:cva6-run, RISC-V tool prefix for --asm/--elf.")
    parser.add_argument(
        "--tool-mode",
        choices=("auto", "local", "docker"),
        help="For sim:cva6-run, choose local or Docker RISC-V tools. auto uses local tools when present, otherwise Docker.",
    )
    parser.add_argument("--linker", type=Path, help="For sim:cva6-run --asm, linker script.")
    parser.add_argument("--include", type=Path, action="append", default=[], help="For sim:cva6-run --asm, extra include directory.")
    parser.add_argument("--cflag", action="append", default=[], help="For sim:cva6-run --asm, extra compiler flag.")
    parser.add_argument("--no-runtime", action="store_true", help="For sim:cva6-run --asm, do not link the rv-maltrace runtime.")
    parser.add_argument("--sample", action="append", help="For demo and exp:35t tasks, sample id. May repeat for exp:35t.")
    parser.add_argument("--rep", default="auto", help="For explain:35t, repetition to explain. Defaults to auto.")
    parser.add_argument("--format", choices=("console", "json", "markdown"), default="console", help="For explain:35t, output format.")
    parser.add_argument("--out", help="For explain:35t, write output only to this file.")
    parser.add_argument("--tee-out", help="For explain:35t, print output and save a copy to this file.")
    parser.add_argument("--strict", action="store_true", help="For explain:35t, fail when required artifacts are missing.")
    parser.add_argument("--flow", action="store_true", help="For explain:35t, render a run-level terminal process view instead of one sample.")
    parser.add_argument("--detail", choices=("compact", "full"), default="compact", help="For explain:35t --flow, choose compact dashboard or full evidence detail.")
    parser.add_argument(
        "--stage",
        choices=("groundtruth", "rootfs", "board", "analyze", "report", "board-analyze-report", "all", "self-test"),
        default="all",
        help="For exp:35t, experiment stage to run.",
    )
    parser.add_argument("--reps", type=int, default=5, help="For exp:35t, repetitions per workload and mode.")
    parser.add_argument(
        "--backend",
        choices=("fixture", "trace"),
        default="fixture",
        help="For demo:behavior, use a checked-in fixture trace or a user-provided trace.",
    )
    parser.add_argument("--trace", type=Path, help="For demo:behavior --backend trace, input RV-MalTrace JSONL trace.")
    parser.add_argument("--run-id", default="manual", help="For demo tasks, run directory under the output root.")
    parser.add_argument("--out-dir", type=Path, help="For demo tasks, output root. Defaults to results/demo.")
    parser.add_argument("--port", default="COM5", help="For Artix-7 board tasks, serial port. Defaults to COM5.")
    parser.add_argument(
        "--baud",
        type=int,
        help="For Artix-7 board tasks, serial baud rate. Defaults to 115200, except exp:35t defaults to 921600.",
    )
    parser.add_argument(
        "--duration",
        type=float,
        help="For Artix-7 serial capture, capture duration in seconds. Defaults to 60, except exp:35t defaults to 3600.",
    )
    parser.add_argument("--send", action="append", default=[], help="For Artix-7 serial capture, command to write to UART. May repeat.")
    parser.add_argument(
        "--send-char-delay",
        type=float,
        default=0.004,
        help="For Artix-7 serial capture, seconds to pause between transmitted shell characters.",
    )
    parser.add_argument(
        "--send-delay",
        type=float,
        default=1.0,
        help="For Artix-7 serial capture, seconds to capture after each sent shell command.",
    )
    parser.add_argument(
        "--trace-records",
        type=int,
        help=(
            "For Artix-7 trace-build/trace-dump and exp:35t, records to allocate/read from rvmt_trace. "
            "Defaults to 64 for trace-dump, 256 for trace-build, and 256 for exp:35t."
        ),
    )
    parser.add_argument(
        "--trace-profile",
        choices=profile_names(),
        help="For exp:35t, select the 35T trace profile recorded in run_config and enforced by the board profile mask.",
    )
    parser.add_argument(
        "--trace-profile-policy",
        choices=("uniform", "35t_small_capacity"),
        help="For exp:35t, choose per-sample trace profile policy.",
    )
    parser.add_argument(
        "--runtime-order",
        choices=("classic", "abba"),
        help="For exp:35t, choose classic trace-off/trace-on batches or ABBA timing order.",
    )
    parser.add_argument("--warmup", type=int, help="For exp:35t, warmup reps per sample/mode excluded from aggregate metrics.")
    parser.add_argument("--include-extension-samples", action="store_true", help="For exp:35t, allow explicitly selected extension samples.")
    parser.add_argument("--syscall-side-channel", action="store_true", help="For exp:35t, enable syscall side-channel logging from the board runner.")
    parser.add_argument("--live-flow", action="store_true", help="For exp:35t, show live board progress and a compact capture dashboard after analyze/report.")
    parser.add_argument("--flow-detail", choices=("compact", "full"), default="compact", help="For exp:35t --live-flow, choose compact or full final dashboard.")
    parser.add_argument(
        "--board-step",
        choices=("03_uart_hello", "04_litex_ddr", "05_baremetal", "06_linux_boot", "07_trace_minimal", "08_trace_jsonl_compare"),
        default="03_uart_hello",
        help="For Artix-7 serial capture, evidence step directory.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    root = repo_root()
    config = load_config(root)
    env = merged_env(config)

    try:
        tasks = task_list(args.tasks or ["config:show"])
        exp_only = len(tasks) == 1 and tasks[0] == "exp:35t"
        if args.baud is None and not exp_only:
            args.baud = 115200
        if args.duration is None and not exp_only:
            args.duration = 60.0
        if args.trace_records is None and not exp_only:
            args.trace_records = 64 if "board:artix7:trace-dump" in tasks else 256
        for task in tasks:
            if task == "config:show":
                show_config(root, config)
            elif task == "help":
                parse_args(["--help"])
            elif task == "tasks:list":
                print_task_list()
            elif task == "completion:powershell":
                print_completion("powershell")
            elif task == "completion:bash":
                print_completion("bash")
            elif task == "completion:zsh":
                print_completion("zsh")
            elif task == "docker:build":
                task_docker_build(root, config, env, args.dry_run)
            elif task == "toolchain:build":
                task_toolchain_build(root, config, env, args.dry_run)
            elif task == "bootrom:build":
                task_bootrom_build(root, config, env, args.dry_run)
            elif task == "vivado:check":
                task_vivado_check(root, config, env, args.dry_run)
            elif task == "vivado:project":
                task_vivado_project(root, config, env, args.dry_run)
            elif task == "board:artix7:jtag-scan":
                task_artix7_jtag_scan(root, config, env, args)
            elif task == "board:artix7:led-build":
                task_artix7_led_build(root, config, env, args)
            elif task == "board:artix7:led-load":
                task_artix7_led_load(root, config, env, args)
            elif task == "board:artix7:litex-prep-docker":
                task_artix7_litex_prep_docker(root, config, env, args)
            elif task == "board:artix7:litex-build":
                task_artix7_litex_build(root, config, env, args)
            elif task == "board:artix7:litex-load":
                task_artix7_litex_load(root, config, env, args)
            elif task == "board:artix7:serial-capture":
                task_artix7_serial_capture(root, config, env, args)
            elif task == "board:artix7:baremetal-build":
                task_artix7_baremetal_build(root, config, env, args)
            elif task == "board:artix7:baremetal-load":
                task_artix7_baremetal_load(root, config, env, args)
            elif task == "board:artix7:baremetal-run":
                task_artix7_baremetal_run(root, config, env, args)
            elif task == "board:artix7:linux-images-prep":
                task_artix7_linux_images_prep(root, config, env, args)
            elif task == "board:artix7:linux-build":
                task_artix7_linux_build(root, config, env, args)
            elif task == "board:artix7:linux-load":
                task_artix7_linux_load(root, config, env, args)
            elif task == "board:artix7:linux-boot-capture":
                task_artix7_linux_boot_capture(root, config, env, args)
            elif task == "board:artix7:trace-build":
                task_artix7_trace_build(root, config, env, args)
            elif task == "board:artix7:trace-load":
                task_artix7_trace_load(root, config, env, args)
            elif task == "board:artix7:trace-dump":
                task_artix7_trace_dump(root, config, env, args)
            elif task == "board:artix7:trace-jsonl-compare":
                task_artix7_trace_jsonl_compare(root, config, env, args)
            elif task == "bitstream:build":
                task_bitstream_build(root, config, env, args.dry_run)
            elif task == "bitstream:build-trace":
                task_bitstream_build(root, config, env, args.dry_run, trace_enabled=True)
            elif task == "bitstream:build-trace-marker":
                task_bitstream_build(root, config, env, args.dry_run, trace_enabled=True, trace_marker_scope=True)
            elif task == "bitstream:build-trace-source-lines":
                task_bitstream_build(
                    root,
                    config,
                    env,
                    args.dry_run,
                    trace_enabled=True,
                    trace_marker_scope=True,
                    trace_source_lines=True,
                )
            elif task == "bitstream:collect":
                task_bitstream_collect(root, config, args.dry_run)
            elif task == "sim:trace-unit":
                task_sim_trace_unit(root, config, env, args.dry_run)
            elif task == "sim:cva6-smoke":
                task_sim_cva6_smoke(root, config, env, args.dry_run)
            elif task == "sim:cva6-full-soc":
                task_sim_cva6_full_soc(root, config, env, args.dry_run)
            elif task == "sim:cva6-full-soc-store":
                task_sim_cva6_full_soc_store(root, config, env, args.dry_run)
            elif task == "sim:cva6-full-soc-tohost":
                task_sim_cva6_full_soc_tohost(root, config, env, args.dry_run)
            elif task == "sim:cva6-full-soc-rv64gc":
                task_sim_cva6_full_soc_rv64gc(root, config, env, args.dry_run)
            elif task == "sim:cva6-run":
                task_sim_cva6_smoke(root, config, env, args.dry_run, custom_cva6_runner_args(args, config))
            elif task == "sim:summary":
                task_sim_summary(root, env, args.dry_run)
            elif task == "baremetal:build":
                task_baremetal_build(root, config, env, args.dry_run)
            elif task == "demo:behavior":
                task_demo_behavior(root, env, args)
            elif task == "demo:groundtruth":
                task_demo_groundtruth(root, config, env, args)
            elif task == "exp:35t":
                task_exp_35t(root, env, args)
            elif task == "explain:35t":
                task_explain_35t(root, args)
            else:
                raise TaskError(f"Unhandled task: {task}")
    except TaskError as exc:
        print(f"rvmt: error: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
