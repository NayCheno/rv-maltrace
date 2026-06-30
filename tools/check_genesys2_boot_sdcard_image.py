from __future__ import annotations

import argparse
import struct
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    as_dict,
    as_list,
    load_json,
    repo_path,
    require,
    sha256_file,
)


DEFAULT_MANIFEST = Path("results/evaluation/genesys2-cva6/current/sdcard_image_manifest.json")
SCHEMA = "rvmt.genesys2.boot_sdcard_image.v1"
PASS_STATUS = "PASS_LOCAL_SDCARD_IMAGE_CREATED"
SECTOR_SIZE = 512


def compare_partition_prefix(errors: list[str], image: Path, source: Path, first_lba: int, partition_bytes: int, label: str) -> None:
    source_size = source.stat().st_size
    require(errors, source_size <= partition_bytes, f"{label}: source larger than partition")
    if source_size > partition_bytes:
        return
    with image.open("rb") as image_handle, source.open("rb") as source_handle:
        image_handle.seek(first_lba * SECTOR_SIZE)
        remaining = source_size
        while remaining:
            chunk = source_handle.read(min(1024 * 1024, remaining))
            image_chunk = image_handle.read(len(chunk))
            if image_chunk != chunk:
                errors.append(f"{label}: partition bytes do not match source")
                return
            remaining -= len(chunk)
        padding = partition_bytes - source_size
        while padding:
            chunk = image_handle.read(min(1024 * 1024, padding))
            if any(chunk):
                errors.append(f"{label}: partition padding is not zero")
                return
            padding -= len(chunk)


def check_manifest(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    require(errors, data.get("schema") == SCHEMA, f"schema must be {SCHEMA}")
    require(errors, data.get("status") == PASS_STATUS, f"status must be {PASS_STATUS}")

    image_row = as_dict(data.get("image"))
    image_path_value = image_row.get("path")
    require(errors, bool(image_path_value), "image.path missing")
    if not image_path_value:
        return errors
    image_path = repo_path(root, image_path_value)
    require(errors, image_path.is_file(), f"image missing: {image_path_value}")
    if not image_path.is_file():
        return errors
    require(errors, image_row.get("sha256") == sha256_file(image_path), "image sha256 mismatch")
    require(errors, int(image_row.get("size_bytes") or -1) == image_path.stat().st_size, "image size_bytes mismatch")
    require(errors, int(image_row.get("sector_size") or -1) == SECTOR_SIZE, "image sector_size mismatch")
    total_lbas = int(image_row.get("total_lbas") or 0)
    require(errors, total_lbas * SECTOR_SIZE == image_path.stat().st_size, "image total_lbas/size mismatch")

    with image_path.open("rb") as handle:
        first_sector = handle.read(SECTOR_SIZE)
        require(errors, first_sector[510:512] == b"\x55\xaa", "protective MBR signature missing")
        primary = handle.read(SECTOR_SIZE)
        require(errors, primary[:8] == b"EFI PART", "primary GPT signature missing")
        if total_lbas:
            handle.seek((total_lbas - 1) * SECTOR_SIZE)
            backup = handle.read(SECTOR_SIZE)
            require(errors, backup[:8] == b"EFI PART", "backup GPT signature missing")

    partitions = as_list(data.get("partitions"))
    require(errors, bool(partitions), "partitions missing")
    require(errors, partitions and as_dict(partitions[0]).get("id") == "boot_payload", "first partition must be boot_payload")

    for index, raw_row in enumerate(partitions):
        row = as_dict(raw_row)
        label = str(row.get("id") or f"partition_{index}")
        source_path_value = row.get("source_path")
        require(errors, bool(source_path_value), f"{label}: source_path missing")
        if not source_path_value:
            continue
        source_path = repo_path(root, source_path_value)
        require(errors, source_path.is_file(), f"{label}: source missing: {source_path_value}")
        if not source_path.is_file():
            continue
        require(errors, row.get("source_sha256") == sha256_file(source_path), f"{label}: source sha256 mismatch")
        require(errors, int(row.get("source_size_bytes") or -1) == source_path.stat().st_size, f"{label}: source_size_bytes mismatch")
        first_lba = int(row.get("first_lba") or 0)
        last_lba = int(row.get("last_lba") or -1)
        partition_bytes = int(row.get("partition_bytes") or -1)
        require(errors, first_lba >= 2048, f"{label}: first_lba must be at or after 2048")
        require(errors, last_lba >= first_lba, f"{label}: invalid last_lba")
        require(errors, partition_bytes == (last_lba - first_lba + 1) * SECTOR_SIZE, f"{label}: partition_bytes mismatch")
        require(errors, (last_lba + 1) * SECTOR_SIZE <= image_path.stat().st_size, f"{label}: partition extends past image")
        if partition_bytes > 0 and (last_lba + 1) * SECTOR_SIZE <= image_path.stat().st_size:
            compare_partition_prefix(errors, image_path, source_path, first_lba, partition_bytes, label)

    bootrom = as_dict(data.get("bootrom_contract"))
    require(errors, bootrom.get("loader") == "rtl/cva6/corev_apu/fpga/src/bootrom/src/gpt.c", "bootrom loader path mismatch")
    require(errors, bootrom.get("loads_first_gpt_entry_to") == "0x80000000", "bootrom load address mismatch")
    require(errors, bootrom.get("first_partition_must_be_boot_payload_only") is True, "bootrom first-partition contract missing")

    boundary = as_dict(data.get("claim_boundary"))
    require(errors, boundary.get("local_sdcard_image_created") is True, "local image claim boundary missing")
    require(errors, boundary.get("buildroot_or_opensbi_compiled") is False, "SD image manifest must not claim compilation")
    require(errors, boundary.get("genesys2_sd_card_written") is False, "SD image manifest must not claim physical SD write")
    require(errors, boundary.get("genesys2_board_booted_from_this_image") is False, "SD image manifest must not claim board boot")
    require(errors, boundary.get("live_kernel_config_export_claimed") is False, "SD image manifest must not claim live kernel config")
    require(errors, boundary.get("board_cycle_source_claimed") is False, "SD image manifest must not claim cycle source")

    commands = " ".join(str(item) for item in as_list(data.get("validation_commands")))
    require(errors, "tools/check_genesys2_boot_sdcard_image.py --root ." in commands, "validation command missing checker")
    require(errors, "rvmt ndss:sdcard-linux-manifest" in commands, "validation command missing live SD-card manifest capture")
    require(errors, "rvmt ndss:live-kernel-config-export" in commands, "validation command missing live kernel config export")

    non_claims = " ".join(str(item).lower() for item in as_list(data.get("non_claims")))
    require(errors, "physical sd-card write" in non_claims, "non_claims must reject physical SD-card write")
    require(errors, "board boot" in non_claims, "non_claims must reject board boot")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="rvmt-sdcard-image-check-") as tmp:
        root = Path(tmp)
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import create_genesys2_boot_sdcard_image as builder

        payload = root / "fw_payload.bin"
        rootfs = root / "rootfs.ext2"
        payload.write_bytes(b"RVMT-PAYLOAD" * 31)
        rootfs.write_bytes(b"RVMT-ROOTFS" * 257)
        manifest_path = root / DEFAULT_MANIFEST
        builder.build_image(root, payload, root / "build/linux/genesys2-cva6/sdcard.img", manifest_path, rootfs)
        data = load_json(manifest_path)
        errors = check_manifest(data, root)
        if errors:
            print("[FAIL] good SD-card image fixture rejected", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        data["claim_boundary"]["genesys2_sd_card_written"] = True
        if not check_manifest(data, root):
            print("[FAIL] bad SD-card image fixture accepted", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 boot SD-card image checker self-test")
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check the local Genesys2/CVA6 boot SD-card image manifest.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    manifest = repo_path(root, args.manifest)
    if not manifest.is_file():
        print(f"[FAIL] missing SD-card image manifest: {manifest}", file=sys.stderr)
        return 1
    try:
        data = load_json(manifest)
        errors = check_manifest(data, root)
    except Exception as exc:
        print(f"[FAIL] SD-card image checker error: {exc}", file=sys.stderr)
        return 1
    if errors:
        print("[FAIL] SD-card image manifest is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] SD-card image manifest accepted: {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
