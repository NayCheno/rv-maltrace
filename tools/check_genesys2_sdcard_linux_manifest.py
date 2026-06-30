from __future__ import annotations

import argparse
import hashlib
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    as_dict,
    as_list,
    load_json,
    repo_path,
    repo_rel,
    require,
    sha256_file,
    write_json,
)


DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/sdcard_linux_manifest.json")
DEFAULT_LOG = Path("results/board/genesys2_trace_validation/20260623-sdcard-linux-manifest/uart.log")
SCHEMA = "rvmt.genesys2.sdcard_linux_manifest.v1"
PASS_STATUS = "PASS"
CAPTURE_PASS_STATUS = "PASS_LIVE_SDCARD_MANIFEST_CAPTURED"
BLOCKED_STATUS = "BLOCKED_BOARD_SDCARD_MANIFEST_CAPTURE_INCOMPLETE"
ACCEPTED_STATUSES = {PASS_STATUS, BLOCKED_STATUS}
REQUIRED_PASS_SECTIONS = {
    "uname_a",
    "uname_r",
    "id",
    "proc_cmdline",
    "proc_version",
    "etc_os_release",
    "proc_cpuinfo",
    "proc_mounts",
    "proc_partitions",
    "block_inventory",
    "rootfs_identity_hashes",
    "boot_file_hashes",
    "dtb_identity_hashes",
    "dtb_readable_identity",
    "kernel_config_probe",
    "sbi_pmu_dmesg_probe",
}


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def extract_sections(text: str) -> tuple[dict[str, str], bool, bool]:
    sections: dict[str, list[str]] = {}
    active: str | None = None
    begin_seen = False
    done_seen = False
    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r")
        stripped = line.strip()
        if stripped.startswith("RVMT_SEND "):
            continue
        if stripped == "RVMT_SDCARD_MANIFEST_BEGIN":
            begin_seen = True
            continue
        if stripped == "RVMT_SDCARD_MANIFEST_DONE":
            done_seen = True
            active = None
            continue
        if stripped.startswith("RVMT_SECTION_BEGIN "):
            active = stripped.split(maxsplit=1)[1].strip()
            sections.setdefault(active, [])
            continue
        if stripped.startswith("RVMT_SECTION_END "):
            ended = stripped.split(maxsplit=1)[1].strip()
            if active == ended:
                active = None
            continue
        if active:
            sections.setdefault(active, []).append(line)
    return {name: "\n".join(lines).strip() for name, lines in sections.items()}, begin_seen, done_seen


def first_nonempty_line(text: str) -> str | None:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return None


def section_row(name: str, text: str) -> dict[str, Any]:
    lines = text.splitlines()
    return {
        "id": name,
        "line_count": len(lines),
        "sha256": sha256_text(text),
        "first_nonempty_line": first_nonempty_line(text),
    }


def parse_bool_from_section(text: str, needle: str) -> bool:
    return any(needle in line for line in text.splitlines())


def parse_key_value_section(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("RVMT_") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key:
            continue
        result[key] = value.strip().strip('"')
    return result


def parse_proc_version(text: str) -> dict[str, str | None]:
    line = first_nonempty_line(text) or ""
    kernel_match = re.search(r"Linux version\s+(\S+)", line)
    buildroot_match = re.search(r"\(Buildroot\s+([^)]+)\)", line)
    gcc_match = re.search(r"\(Buildroot\s+[^)]+\)\s+([0-9][^,\s]*)", line)
    binutils_match = re.search(r"GNU Binutils\)\s+([0-9][^) ]*)", line)
    timestamp_match = re.search(r"#\d+\s+(.+)$", line)
    return {
        "raw": line or None,
        "kernel_release": kernel_match.group(1) if kernel_match else None,
        "buildroot_version": buildroot_match.group(1) if buildroot_match else None,
        "gcc_version": gcc_match.group(1) if gcc_match else None,
        "binutils_version": binutils_match.group(1) if binutils_match else None,
        "kernel_build_timestamp": timestamp_match.group(1).strip() if timestamp_match else None,
    }


def parse_kernel_config_probe(text: str) -> dict[str, Any]:
    present: list[str] = []
    missing: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("RVMT_KERNEL_CONFIG_PATH "):
            present.append(line.split(maxsplit=1)[1])
        elif line.startswith("RVMT_KERNEL_CONFIG_MISSING "):
            missing.append(line.split(maxsplit=1)[1])
    candidates = sorted(dict.fromkeys(present + missing))
    return {
        "kernel_config_candidate_paths": candidates,
        "kernel_config_paths_present": sorted(dict.fromkeys(present)),
        "kernel_config_paths_missing": sorted(dict.fromkeys(missing)),
        "live_kernel_config_export_available": bool(present),
    }


def parse_root_mount(text: str) -> dict[str, str | None]:
    for raw_line in text.splitlines():
        parts = raw_line.split()
        if len(parts) >= 3 and parts[1] == "/":
            return {
                "root_mount_source": parts[0],
                "root_mount_kind": parts[2],
            }
    return {"root_mount_source": None, "root_mount_kind": None}


def parse_block_inventory(text: str, proc_partitions: str) -> dict[str, Any]:
    block_devices: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("RVMT_BLOCK_DEVICE "):
            device = line.split(maxsplit=1)[1].strip()
            if device and device != "*":
                block_devices.append(device)
    partition_rows = [
        line.strip()
        for line in proc_partitions.splitlines()
        if line.strip() and not line.lower().startswith("major minor")
    ]
    observed = sorted(dict.fromkeys(block_devices))
    return {
        "block_devices_observed": observed,
        "proc_partitions_empty": not partition_rows,
        "sd_or_mmc_block_device_observed": any(re.match(r"^(mmcblk|sd[a-z])", device) for device in observed),
        "dev_mmc_or_sd_nodes_missing": "No such file or directory" in text and ("/dev/mmc" in text or "/dev/sd" in text),
    }


def parse_rootfs_identity(text: str) -> dict[str, Any]:
    missing: list[str] = []
    present_hashes: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("RVMT_FILE_MISSING "):
            missing.append(line.split(maxsplit=1)[1])
            continue
        parts = line.split()
        if len(parts) >= 2 and re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]):
            present_hashes[parts[-1]] = parts[0].lower()
    return {
        "rootfs_files_hashed": present_hashes,
        "rootfs_files_missing": sorted(dict.fromkeys(missing)),
        "buildroot_release_file_missing": "/etc/buildroot-release" in missing,
    }


def parse_dtb_hashes(text: str) -> dict[str, Any]:
    present: dict[str, dict[str, Any]] = {}
    missing: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("RVMT_DTB_FILE_MISSING "):
            missing.append(line.split(maxsplit=1)[1])
            continue
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "RVMT_DTB_FILE" and re.fullmatch(r"[0-9a-fA-F]{64}", parts[1]):
            size_value: int | None
            try:
                size_value = int(parts[2])
            except ValueError:
                size_value = None
            present[parts[3]] = {"sha256": parts[1].lower(), "size_bytes": size_value}
    return {
        "dtb_files_hashed": present,
        "dtb_files_missing": sorted(dict.fromkeys(missing)),
        "dtb_cpu_isa_file_missing": "/proc/device-tree/cpus/cpu@0/riscv,isa" in missing,
    }


def parse_dtb_readable_identity(text: str) -> dict[str, Any]:
    values: dict[str, list[str]] = {}
    missing: list[str] = []
    current_file: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if "RVMT_SECTION_END " in line:
            line = line.split("RVMT_SECTION_END ", 1)[0].strip()
        if line.startswith("RVMT_DTB_VALUE_FILE "):
            current_file = line.split(maxsplit=1)[1]
            values.setdefault(current_file, [])
        elif line.startswith("RVMT_DTB_VALUE_MISSING "):
            missing.append(line.split(maxsplit=1)[1])
            current_file = None
        elif line.startswith("RVMT_DTB_VALUE ") and current_file:
            value = line.split(maxsplit=1)[1].strip()
            if value:
                values.setdefault(current_file, []).append(value)
    return {
        "dtb_readable_values": values,
        "dtb_readable_missing": sorted(dict.fromkeys(missing)),
        "dtb_compatible": values.get("/proc/device-tree/compatible", []),
        "dtb_model": (values.get("/proc/device-tree/model") or [None])[0],
    }


def parse_sbi_probe(text: str) -> dict[str, Any]:
    spec: str | None = None
    implementation: str | None = None
    extensions: list[str] = []
    pmu_or_perf_lines: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        spec_match = re.search(r"SBI specification\s+(v[0-9.]+)\s+detected", line)
        implementation_match = re.search(r"SBI implementation\s+(.+)$", line)
        extension_match = re.search(r"SBI\s+([A-Z0-9_]+)\s+extension detected", line)
        if spec_match:
            spec = spec_match.group(1)
        if implementation_match:
            implementation = implementation_match.group(1)
        if extension_match:
            extensions.append(extension_match.group(1))
        if re.search(r"\b(pmu|perf)\b", line, re.IGNORECASE):
            pmu_or_perf_lines.append(line)
    unique_extensions = sorted(dict.fromkeys(extensions))
    return {
        "sbi_spec_detected": spec,
        "sbi_implementation": implementation,
        "sbi_extensions_observed": unique_extensions,
        "sbi_pmu_extension_observed": "PMU" in unique_extensions,
        "pmu_or_perf_dmesg_lines": pmu_or_perf_lines,
    }


def summarize_manifest(root: Path, log: Path, summary: Path) -> dict[str, Any]:
    log_path = log if log.is_absolute() else root / log
    text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.is_file() else ""
    sections, begin_seen, done_seen = extract_sections(text)
    missing_sections = sorted(REQUIRED_PASS_SECTIONS - set(sections))
    rootfs_hash_lines = [
        line
        for line in sections.get("rootfs_identity_hashes", "").splitlines()
        if line.strip() and "RVMT_FILE_MISSING" not in line and "RVMT_HASH_UNAVAILABLE" not in line
    ]
    dtb_hash_lines = [
        line
        for line in sections.get("dtb_identity_hashes", "").splitlines()
        if line.strip().startswith("RVMT_DTB_FILE ")
    ]
    boot_dir_missing = parse_bool_from_section(sections.get("boot_file_hashes", ""), "RVMT_BOOT_DIR_MISSING")
    kernel_config = parse_kernel_config_probe(sections.get("kernel_config_probe", ""))
    kernel_config_missing = not kernel_config["live_kernel_config_export_available"]
    os_release = parse_key_value_section(sections.get("etc_os_release", ""))
    proc_version = parse_proc_version(sections.get("proc_version", ""))
    root_mount = parse_root_mount(sections.get("proc_mounts", ""))
    block_inventory = parse_block_inventory(sections.get("block_inventory", ""), sections.get("proc_partitions", ""))
    rootfs_identity = parse_rootfs_identity(sections.get("rootfs_identity_hashes", ""))
    dtb_hashes = parse_dtb_hashes(sections.get("dtb_identity_hashes", ""))
    dtb_readable = parse_dtb_readable_identity(sections.get("dtb_readable_identity", ""))
    sbi_probe = parse_sbi_probe(sections.get("sbi_pmu_dmesg_probe", ""))
    source_provenance = {
        "buildroot_os_release": os_release,
        "proc_version": proc_version,
        "buildroot_version_observed_from_live_image": bool(os_release.get("VERSION_ID") or proc_version.get("buildroot_version")),
        "kernel_release": first_nonempty_line(sections.get("uname_r", "")) or proc_version.get("kernel_release"),
        "kernel_build_timestamp": proc_version.get("kernel_build_timestamp"),
        **kernel_config,
        "boot_directory_missing": boot_dir_missing,
        **root_mount,
        **block_inventory,
        **rootfs_identity,
        **dtb_hashes,
        **dtb_readable,
        **sbi_probe,
        "source_locked_rebuild_artifacts_available_on_live_image": False,
    }
    status = PASS_STATUS
    blocked_reason = None
    if not log_path.is_file() or not begin_seen or not done_seen or missing_sections:
        status = BLOCKED_STATUS
        blocked_reason = "live board UART manifest capture is missing required markers or sections"
    data: dict[str, Any] = {
        "schema": SCHEMA,
        "status": status,
        "capture_status": CAPTURE_PASS_STATUS if status == PASS_STATUS else BLOCKED_STATUS,
        "canonical_evaluation_root": "results/evaluation/genesys2-cva6/current",
        "scope": "live Genesys2/CVA6 SD-card Linux identity manifest captured over UART",
        "raw_uart_log": {
            "path": repo_rel(root, log_path),
            "exists": log_path.is_file(),
            "sha256": sha256_file(log_path) if log_path.is_file() else None,
            "size_bytes": log_path.stat().st_size if log_path.is_file() else None,
        },
        "markers": {
            "begin_seen": begin_seen,
            "done_seen": done_seen,
        },
        "section_count": len(sections),
        "missing_required_sections": missing_sections,
        "sections": [section_row(name, text) for name, text in sorted(sections.items())],
        "observed_identity": {
            "uname_a": first_nonempty_line(sections.get("uname_a", "")),
            "kernel_release": first_nonempty_line(sections.get("uname_r", "")),
            "id": first_nonempty_line(sections.get("id", "")),
            "cmdline": first_nonempty_line(sections.get("proc_cmdline", "")),
            "proc_version": first_nonempty_line(sections.get("proc_version", "")),
            "rootfs_identity_hash_line_count": len(rootfs_hash_lines),
            "dtb_identity_hash_line_count": len(dtb_hash_lines),
            "boot_directory_missing": boot_dir_missing,
            "kernel_config_export_missing": kernel_config_missing,
            "buildroot_version": os_release.get("VERSION_ID") or proc_version.get("buildroot_version"),
            "dtb_compatible": dtb_readable["dtb_compatible"],
            "sbi_extensions_observed": sbi_probe["sbi_extensions_observed"],
        },
        "source_provenance_observations": source_provenance,
        "claim_boundary": {
            "live_sd_card_manifest_captured": status == PASS_STATUS,
            "buildroot_version_observed_from_live_image": source_provenance["buildroot_version_observed_from_live_image"],
            "hardware_live_image_identity_only": True,
            "source_locked_rebuild_artifacts_available": False,
            "sd_card_image_rebuild_path_claimed": False,
            "buildroot_source_claimed": False,
            "opensbi_source_claimed": False,
            "live_kernel_config_export_claimed": False,
            "board_cycle_source_claimed": False,
            "cycle_level_overhead_claimed": False,
            "qemu_or_strace_substitution_allowed": False,
            "manifest_only": True,
        },
        "non_claims": [
            "This manifest records live SD-card Linux identity observed through Genesys2 UART; it does not build or replace the SD-card image.",
            "A Buildroot version observed from /etc/os-release or /proc/version is live image identity evidence, not Buildroot source, defconfig, OpenSBI source, or kernel config provenance.",
            "Missing /boot files, kernel config, OpenSBI source, Buildroot source, or PMU device-tree support remain blockers when absent.",
            "This manifest does not claim user rdcycle, kernel perf cycles, cycle-level overhead, production runtime overhead, or malware validation.",
            "QEMU and strace cannot substitute for this live board manifest or for board cycle-source probes.",
        ],
        "validation_commands": [
            "uv run rvmt ndss:sdcard-linux-manifest --port COM7 --baud 115200",
            "uv run python tools/check_genesys2_sdcard_linux_manifest.py --root .",
            "uv run rvmt ndss:linux-counter-preflight",
        ],
    }
    if blocked_reason:
        data["blocked_reason"] = blocked_reason
    write_json(summary if summary.is_absolute() else root / summary, data)
    return data


def section_map(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("id")): row
        for row in as_list(data.get("sections"))
        if isinstance(row, dict) and isinstance(row.get("id"), str)
    }


def check_summary(data: dict[str, Any], root: Path, *, require_pass: bool) -> list[str]:
    errors: list[str] = []
    raw_sections: dict[str, str] = {}
    require(errors, data.get("schema") == SCHEMA, f"schema must be {SCHEMA}")
    status = str(data.get("status") or "")
    if require_pass:
        require(errors, status == PASS_STATUS, f"status must be {PASS_STATUS} under --require-pass, got {status}")
    else:
        require(errors, status in ACCEPTED_STATUSES, f"unexpected status: {status}")
    require(errors, data.get("canonical_evaluation_root") == "results/evaluation/genesys2-cva6/current", "canonical evidence root mismatch")
    raw = as_dict(data.get("raw_uart_log"))
    raw_path_value = raw.get("path")
    require(errors, bool(raw_path_value), "raw_uart_log.path missing")
    raw_path = repo_path(root, raw_path_value) if raw_path_value else root / "__missing__"
    require(errors, raw_path.is_file(), f"raw UART log missing: {raw_path_value}")
    if raw_path.is_file():
        require(errors, raw.get("sha256") == sha256_file(raw_path), "raw UART log sha256 mismatch")
        require(errors, int(raw.get("size_bytes") or -1) == raw_path.stat().st_size, "raw UART log size_bytes mismatch")
        raw_sections, begin_seen, done_seen = extract_sections(raw_path.read_text(encoding="utf-8", errors="replace"))
        markers = as_dict(data.get("markers"))
        require(errors, markers.get("begin_seen") is begin_seen, "begin marker metadata mismatch")
        require(errors, markers.get("done_seen") is done_seen, "done marker metadata mismatch")
        rows = section_map(data)
        for name, text in raw_sections.items():
            row = rows.get(name)
            require(errors, row is not None, f"section row missing: {name}")
            if row is not None:
                require(errors, row.get("sha256") == sha256_text(text), f"section sha256 mismatch: {name}")
                row_line_count = row.get("line_count")
                require(
                    errors,
                    isinstance(row_line_count, int) and row_line_count == len(text.splitlines()),
                    f"section line_count mismatch: {name}",
                )
    missing_sections = sorted(REQUIRED_PASS_SECTIONS - set(section_map(data)))
    require(errors, sorted(as_list(data.get("missing_required_sections"))) == missing_sections, "missing_required_sections mismatch")
    if status == PASS_STATUS:
        require(errors, data.get("capture_status") == CAPTURE_PASS_STATUS, f"capture_status must be {CAPTURE_PASS_STATUS}")
        require(errors, not missing_sections, "PASS manifest cannot have missing required sections")
        require(errors, as_dict(data.get("markers")).get("begin_seen") is True, "PASS manifest requires begin marker")
        require(errors, as_dict(data.get("markers")).get("done_seen") is True, "PASS manifest requires done marker")
    else:
        require(errors, bool(data.get("blocked_reason")), "blocked manifest requires blocked_reason")
    identity = as_dict(data.get("observed_identity"))
    if status == PASS_STATUS:
        require(errors, bool(identity.get("kernel_release")), "kernel_release missing")
        require(errors, bool(identity.get("cmdline")), "proc cmdline missing")
        require(errors, int(identity.get("dtb_identity_hash_line_count") or 0) > 0, "DTB identity hash rows missing")
        require(errors, bool(identity.get("buildroot_version")), "Buildroot live-image version missing")
        require(errors, bool(identity.get("dtb_compatible")), "DTB compatible values missing")
    observations = as_dict(data.get("source_provenance_observations"))
    if status == PASS_STATUS:
        require(errors, bool(observations), "source_provenance_observations missing")
        os_release = as_dict(observations.get("buildroot_os_release"))
        require(errors, os_release.get("NAME") == "Buildroot" or os_release.get("ID") == "buildroot", "Buildroot os-release identity missing")
        require(errors, observations.get("buildroot_version_observed_from_live_image") is True, "Buildroot version must be marked as live-image observation")
        require(errors, observations.get("kernel_release") == identity.get("kernel_release"), "source provenance kernel_release mismatch")
        require(
            errors,
            observations.get("live_kernel_config_export_available") is (len(as_list(observations.get("kernel_config_paths_present"))) > 0),
            "kernel config availability does not match present paths",
        )
        if identity.get("kernel_config_export_missing") is True:
            require(errors, observations.get("live_kernel_config_export_available") is False, "missing kernel config cannot be marked available")
        require(
            errors,
            observations.get("source_locked_rebuild_artifacts_available_on_live_image") is False,
            "live manifest must not claim source-locked rebuild artifacts",
        )
        require(errors, isinstance(observations.get("block_devices_observed"), list), "block device observations must be a list")
        require(errors, isinstance(observations.get("sd_or_mmc_block_device_observed"), bool), "SD/MMC observation must be boolean")
        require(errors, isinstance(observations.get("dtb_files_hashed"), dict), "DTB hash provenance missing")
        require(errors, bool(observations.get("dtb_compatible")), "DTB compatible provenance missing")
        require(errors, isinstance(observations.get("sbi_extensions_observed"), list), "SBI extension observations must be a list")
        if raw_sections:
            parsed_kernel = parse_kernel_config_probe(raw_sections.get("kernel_config_probe", ""))
            require(
                errors,
                observations.get("kernel_config_paths_present") == parsed_kernel["kernel_config_paths_present"],
                "kernel config present paths do not match raw UART section",
            )
            require(
                errors,
                observations.get("kernel_config_paths_missing") == parsed_kernel["kernel_config_paths_missing"],
                "kernel config missing paths do not match raw UART section",
            )
            parsed_sbi = parse_sbi_probe(raw_sections.get("sbi_pmu_dmesg_probe", ""))
            require(
                errors,
                observations.get("sbi_pmu_extension_observed") is parsed_sbi["sbi_pmu_extension_observed"],
                "SBI PMU observation does not match raw UART dmesg section",
            )
            parsed_blocks = parse_block_inventory(raw_sections.get("block_inventory", ""), raw_sections.get("proc_partitions", ""))
            require(
                errors,
                observations.get("sd_or_mmc_block_device_observed") is parsed_blocks["sd_or_mmc_block_device_observed"],
                "SD/MMC block-device observation does not match raw UART section",
            )
    boundary = as_dict(data.get("claim_boundary"))
    require(errors, boundary.get("manifest_only") is True, "manifest_only boundary missing")
    require(errors, boundary.get("hardware_live_image_identity_only") is True, "hardware live-image identity boundary missing")
    require(errors, boundary.get("source_locked_rebuild_artifacts_available") is False, "manifest must not claim source-locked rebuild artifacts")
    require(errors, boundary.get("sd_card_image_rebuild_path_claimed") is False, "manifest must not claim SD-card rebuild path")
    require(errors, boundary.get("buildroot_source_claimed") is False, "manifest must not claim Buildroot source")
    require(errors, boundary.get("opensbi_source_claimed") is False, "manifest must not claim OpenSBI source")
    require(errors, boundary.get("live_kernel_config_export_claimed") is False, "manifest must not claim kernel config export")
    require(errors, boundary.get("board_cycle_source_claimed") is False, "manifest must not claim board cycle source")
    require(errors, boundary.get("cycle_level_overhead_claimed") is False, "manifest must not claim cycle-level overhead")
    require(errors, boundary.get("qemu_or_strace_substitution_allowed") is False, "QEMU/strace substitution must be forbidden")
    non_claims = " ".join(str(item).lower() for item in as_list(data.get("non_claims")))
    require(errors, "does not build or replace the sd-card image" in non_claims, "non_claims must reject SD-card rebuild claim")
    require(errors, "live image identity evidence" in non_claims, "non_claims must classify Buildroot version as identity evidence")
    require(errors, "does not claim user rdcycle" in non_claims, "non_claims must reject cycle-source claim")
    commands = " ".join(str(item) for item in as_list(data.get("validation_commands")))
    require(errors, "rvmt ndss:sdcard-linux-manifest" in commands, "validation command missing sdcard manifest task")
    require(errors, "check_genesys2_sdcard_linux_manifest.py --root ." in commands, "validation command missing checker")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="rvmt-sdcard-manifest-") as tmp:
        root = Path(tmp)
        log = root / DEFAULT_LOG
        log.parent.mkdir(parents=True, exist_ok=True)
        lines = ["RVMT_SDCARD_MANIFEST_BEGIN"]
        for name, payload in {
            "uname_a": "Linux rvmt 6.19.6 #1 SMP riscv64 GNU/Linux",
            "uname_r": "6.19.6",
            "id": "uid=0(root) gid=0(root)",
            "proc_cmdline": "console=ttyS0 root=/dev/mmcblk0p2 rw",
            "proc_version": "Linux version 6.19.6 (root@buildkitsandbox) (riscv64-buildroot-linux-gnu-gcc.br_real (Buildroot 2026.02) 14.3.0, GNU ld (GNU Binutils) 2.44) #1 Tue Jun  9 06:02:04 UTC 2026",
            "etc_os_release": "\n".join(
                [
                    "NAME=Buildroot",
                    "VERSION=2026.02",
                    "ID=buildroot",
                    "VERSION_ID=2026.02",
                    'PRETTY_NAME="Buildroot 2026.02"',
                ]
            ),
            "proc_cpuinfo": "isa\t: rv64imafdc_zicntr_zihpm",
            "proc_mounts": "/dev/root / ext2 rw 0 0",
            "proc_partitions": "179 0 1024 mmcblk0",
            "block_inventory": "RVMT_BLOCK_DEVICE mmcblk0",
            "rootfs_identity_hashes": "0" * 64 + "  /bin/busybox",
            "boot_file_hashes": "RVMT_BOOT_DIR_MISSING /boot",
            "dtb_identity_hashes": "RVMT_DTB_FILE " + "1" * 64 + " 16 /proc/device-tree/compatible",
            "dtb_readable_identity": "\n".join(
                [
                    "RVMT_DTB_VALUE_FILE /proc/device-tree/compatible",
                    "RVMT_DTB_VALUE eth,cva6-bare-dev",
                    "RVMT_DTB_VALUE_FILE /proc/device-tree/model",
                    "RVMT_DTB_VALUE eth,cva6-bare",
                    "RVMT_DTB_VALUE_MISSING /proc/device-tree/cpus/cpu@0/riscv,isa",
                ]
            ),
            "kernel_config_probe": "RVMT_KERNEL_CONFIG_MISSING /proc/config.gz",
            "sbi_pmu_dmesg_probe": "\n".join(
                [
                    "[    0.000000] SBI specification v3.0 detected",
                    "[    0.000000] SBI implementation ID=0x1 Version=0x10007",
                    "[    0.000000] SBI TIME extension detected",
                    "[    0.000000] SBI IPI extension detected",
                ]
            ),
        }.items():
            lines.extend([f"RVMT_SECTION_BEGIN {name}", payload, f"RVMT_SECTION_END {name}"])
        lines.append("RVMT_SDCARD_MANIFEST_DONE")
        log.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        summary_path = root / DEFAULT_SUMMARY
        data = summarize_manifest(root, DEFAULT_LOG, DEFAULT_SUMMARY)
        errors = check_summary(data, root, require_pass=False)
        if errors:
            print("[FAIL] sdcard manifest checker good fixture failed", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        require_pass_errors = check_summary(data, root, require_pass=True)
        if require_pass_errors:
            print("[FAIL] --require-pass rejected good fixture", file=sys.stderr)
            for error in require_pass_errors:
                print(error, file=sys.stderr)
            return 1
        data["claim_boundary"]["board_cycle_source_claimed"] = True
        errors = check_summary(data, root, require_pass=False)
        if not any("must not claim board cycle source" in error for error in errors):
            print("[FAIL] checker missed cycle-source overclaim", file=sys.stderr)
            return 1
        data["claim_boundary"]["board_cycle_source_claimed"] = False
        data["claim_boundary"]["source_locked_rebuild_artifacts_available"] = True
        errors = check_summary(data, root, require_pass=False)
        if not any("must not claim source-locked rebuild artifacts" in error for error in errors):
            print("[FAIL] checker missed source-lock overclaim", file=sys.stderr)
            return 1
        bad_log = root / "bad.log"
        bad_log.write_text("RVMT_SDCARD_MANIFEST_BEGIN\n", encoding="utf-8", newline="\n")
        bad_summary = root / "bad.json"
        bad = summarize_manifest(root, bad_log, bad_summary)
        if bad.get("status") != BLOCKED_STATUS:
            print("[FAIL] incomplete fixture did not block", file=sys.stderr)
            return 1
        if not summary_path.is_file():
            print("[FAIL] summary fixture was not written", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 SD-card Linux manifest checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check a live Genesys2/CVA6 SD-card Linux manifest captured over UART.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--require-pass", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    summary = repo_path(root, args.summary)
    if not summary.is_file():
        if args.require_pass:
            print(f"[FAIL] SD-card Linux manifest missing: {summary}", file=sys.stderr)
            return 1
        print(f"[{BLOCKED_STATUS}] SD-card Linux manifest missing: {summary}")
        return 0
    try:
        errors = check_summary(load_json(summary), root, require_pass=args.require_pass)
    except Exception as exc:
        print(f"[FAIL] SD-card Linux manifest checker error: {exc}", file=sys.stderr)
        return 2
    if errors:
        print("[FAIL] SD-card Linux manifest is not acceptable", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    data = load_json(summary)
    print(f"[PASS] SD-card Linux manifest accepted: {summary} status={data.get('status')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
