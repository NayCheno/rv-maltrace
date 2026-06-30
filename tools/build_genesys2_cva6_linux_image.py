from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from experiment_common import (
    repo_path,
    repo_rel,
    sha256_file,
    write_json,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = Path("build/linux/genesys2-cva6/source_lock_manifest.json")
SCHEMA = "rvmt.genesys2.cva6_linux_source_lock.v1"

SOURCE_INPUTS = {
    "buildroot_defconfig": Path("board/genesys2-cva6/linux/buildroot_defconfig"),
    "linux_kernel_config": Path("board/genesys2-cva6/linux/linux.config"),
    "opensbi_manifest": Path("board/genesys2-cva6/linux/opensbi_manifest.json"),
    "opensbi_source_lock": Path("board/genesys2-cva6/linux/opensbi_source_lock.txt"),
    "device_tree_template": Path("rtl/cva6/corev_apu/fpga/src/bootrom/cv64a6.dts.in"),
    "live_sdcard_identity_manifest": Path("results/evaluation/genesys2-cva6/current/sdcard_linux_manifest.json"),
}

REQUIRED_KERNEL_OPTIONS = {
    "CONFIG_PERF_EVENTS": "y",
    "CONFIG_IKCONFIG": "y",
    "CONFIG_IKCONFIG_PROC": "y",
}
PMU_KERNEL_OPTIONS = {"CONFIG_RISCV_PMU", "CONFIG_RISCV_PMU_SBI", "CONFIG_HW_PERF_EVENTS"}



def read_text(path: Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def lower_config_text(path: Path) -> str:
    return read_text(path).lower().replace("-", "_")


def source_row(root: Path, name: str, rel_path: Path) -> dict[str, Any]:
    path = repo_path(root, rel_path)
    row: dict[str, Any] = {
        "id": name,
        "path": rel_path.as_posix(),
        "exists": path.is_file(),
    }
    if path.is_file():
        row["sha256"] = sha256_file(path)
        row["size_bytes"] = path.stat().st_size
    return row


def validate_buildroot(root: Path) -> list[str]:
    text = lower_config_text(repo_path(root, SOURCE_INPUTS["buildroot_defconfig"]))
    checks = {
        "BR2_riscv": "br2_riscv" in text,
        "BR2_LINUX_KERNEL": "br2_linux_kernel" in text,
        "BR2_TARGET_OPENSBI": "br2_target_opensbi" in text or "opensbi" in text,
        "Genesys2_CVA6_identity": ("genesys2" in text and "cva6" in text) or "cv64a6" in text,
    }
    return [name for name, ok in checks.items() if not ok]


def parse_kernel_options(path: Path) -> dict[str, str]:
    options: dict[str, str] = {}
    for raw_line in read_text(path).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        options[key.strip()] = value.strip()
    return options


def validate_kernel(root: Path) -> list[str]:
    options = parse_kernel_options(repo_path(root, SOURCE_INPUTS["linux_kernel_config"]))
    missing = [key for key, value in REQUIRED_KERNEL_OPTIONS.items() if options.get(key) != value]
    if not any(options.get(key) in {"y", "m"} for key in PMU_KERNEL_OPTIONS):
        missing.append("one of CONFIG_RISCV_PMU/CONFIG_RISCV_PMU_SBI/CONFIG_HW_PERF_EVENTS")
    return missing


def validate_opensbi(root: Path) -> list[str]:
    manifest_path = repo_path(root, SOURCE_INPUTS["opensbi_manifest"])
    errors: list[str] = []
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [f"opensbi_manifest_json: {exc}"]
    if manifest.get("schema") != "rvmt.genesys2.opensbi_source_manifest.v1":
        errors.append("opensbi_manifest_schema")
    source = manifest.get("source") if isinstance(manifest.get("source"), dict) else {}
    if not source.get("commit"):
        errors.append("opensbi_source_commit")
    artifacts = manifest.get("artifacts") if isinstance(manifest.get("artifacts"), list) else []
    if not artifacts:
        errors.append("opensbi_artifacts")
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            errors.append(f"opensbi_artifact_{index}_type")
            continue
        rel_path = artifact.get("path")
        expected_sha = artifact.get("sha256")
        if not rel_path or not expected_sha:
            errors.append(f"opensbi_artifact_{index}_path_or_sha")
            continue
        path = repo_path(root, str(rel_path))
        if not path.is_file():
            errors.append(f"opensbi_artifact_{index}_missing")
            continue
        actual_sha = sha256_file(path)
        if actual_sha != expected_sha:
            errors.append(f"opensbi_artifact_{index}_sha256")
    return errors


def summarize(root: Path, out_path: Path, execute: bool) -> dict[str, Any]:
    missing_files = [
        name for name, rel_path in SOURCE_INPUTS.items() if not repo_path(root, rel_path).is_file()
    ]
    validation_errors: dict[str, list[str]] = {}
    if "buildroot_defconfig" not in missing_files:
        validation_errors["buildroot_defconfig"] = validate_buildroot(root)
    if "linux_kernel_config" not in missing_files:
        validation_errors["linux_kernel_config"] = validate_kernel(root)
    if "opensbi_manifest" not in missing_files:
        validation_errors["opensbi_manifest"] = validate_opensbi(root)
    validation_errors = {key: value for key, value in validation_errors.items() if value}

    blocked_reasons: list[str] = []
    if missing_files:
        blocked_reasons.append("source input files are missing")
    if validation_errors:
        blocked_reasons.append("source input validation failed")
    if execute:
        blocked_reasons.append(
            "image build execution is not enabled by this repo-local source-lock entrypoint; run Buildroot/OpenSBI in Docker after adding the external source trees"
        )

    status = "PASS_SOURCE_LOCK_VALIDATED" if not blocked_reasons else "BLOCKED_SOURCE_LOCK_INCOMPLETE"
    data: dict[str, Any] = {
        "schema": SCHEMA,
        "status": status,
        "scope": "Genesys2/CVA6 Buildroot OpenSBI SD-card Linux source-lock preflight",
        "output_manifest": repo_rel(root, out_path),
        "source_inputs": [source_row(root, name, rel_path) for name, rel_path in SOURCE_INPUTS.items()],
        "validation_errors": validation_errors,
        "next_build_boundary": {
            "buildroot_tree_required": "external/buildroot or vendor/buildroot",
            "opensbi_tree_required": "external/opensbi or vendor/opensbi",
            "docker_rebuild_preparer": "tools/prepare_genesys2_cva6_linux_rebuild.py",
            "boot_payload_required": "OpenSBI fw_payload.bin or equivalent payload that jumps into Linux",
            "bootrom_sdcard_image_builder": "tools/create_genesys2_boot_sdcard_image.py",
            "sdcard_image_output_required": "build/linux/genesys2-cva6/sdcard.img",
            "live_kernel_config_export_required": "results/evaluation/genesys2-cva6/current/live_kernel_config.txt",
        },
        "claim_boundary": {
            "source_lock_only": True,
            "buildroot_defconfig_claimed": not validation_errors.get("buildroot_defconfig") and "buildroot_defconfig" not in missing_files,
            "opensbi_source_lock_claimed": not validation_errors.get("opensbi_manifest") and "opensbi_manifest" not in missing_files,
            "sd_card_image_built": False,
            "current_live_sd_card_rebuilt_from_these_sources": False,
            "live_board_counter_source_claimed": False,
            "cycle_level_overhead_claimed": False,
            "qemu_or_strace_substitution_allowed": False,
        },
        "validation_commands": [
            "uv run rvmt ndss:linux-source-lock",
            "uv run rvmt ndss:linux-rebuild-prep --fetch --configure",
            "uv run rvmt ndss:boot-sdcard-image --payload <fw_payload.bin>",
            "uv run rvmt ndss:linux-counter-preflight",
            "uv run python tools/check_genesys2_linux_counter_path_preflight.py --root .",
        ],
    }
    if blocked_reasons:
        data["blocked_reasons"] = blocked_reasons
    write_json(out_path, data)
    return data


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate repo-owned Genesys2/CVA6 Buildroot/OpenSBI/sdcard Linux source-lock inputs."
    )
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Require an actual SD-card Linux image build. This currently reports BLOCKED unless external source trees are added.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = args.root.resolve()
    out_path = repo_path(root, args.out)
    data = summarize(root, out_path, args.execute)
    print(json.dumps({"status": data["status"], "manifest": repo_rel(root, out_path)}, sort_keys=True))
    if data["status"].startswith("PASS"):
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
