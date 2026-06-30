from __future__ import annotations

import argparse
import binascii
import json
import math
import struct
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any

from experiment_common import (
    repo_path,
    repo_rel,
    sha256_file,
    write_json,
)


SCHEMA = "rvmt.genesys2.boot_sdcard_image.v1"
PASS_STATUS = "PASS_LOCAL_SDCARD_IMAGE_CREATED"
SECTOR_SIZE = 512
ENTRY_COUNT = 128
ENTRY_SIZE = 128
FIRST_USABLE_LBA = 2048
ALIGN_LBA = 2048
LINUX_DATA_GUID = uuid.UUID("0fc63daf-8483-4772-8e79-3d69d8477de4")
RVMT_BOOT_GUID = uuid.UUID("b69d2f6d-09a8-42a1-a18b-ecf4dbe7369c")
RVMT_ROOTFS_GUID = uuid.UUID("a19d880f-05fc-4d3b-8e24-1568f8765f90")
DEFAULT_OUT = Path("build/linux/genesys2-cva6/sdcard.img")
DEFAULT_MANIFEST = Path("results/evaluation/genesys2-cva6/current/sdcard_image_manifest.json")



def sectors_for(size_bytes: int) -> int:
    return max(1, math.ceil(size_bytes / SECTOR_SIZE))


def align_lba(value: int, align: int = ALIGN_LBA) -> int:
    return ((value + align - 1) // align) * align


def guid_bytes(value: uuid.UUID) -> bytes:
    return value.bytes_le


def partition_name(value: str) -> bytes:
    raw = value.encode("utf-16le")[:72]
    return raw + b"\x00" * (72 - len(raw))


def make_entry(type_guid: uuid.UUID, unique_guid: uuid.UUID, first_lba: int, last_lba: int, name: str) -> bytes:
    return (
        guid_bytes(type_guid)
        + guid_bytes(unique_guid)
        + struct.pack("<QQQ", first_lba, last_lba, 0)
        + partition_name(name)
    )


def make_gpt_header(
    current_lba: int,
    backup_lba: int,
    first_usable: int,
    last_usable: int,
    disk_guid: uuid.UUID,
    entries_lba: int,
    entry_count: int,
    entry_size: int,
    entries_crc: int,
) -> bytes:
    header_size = 92
    header = struct.pack(
        "<8sIIIIQQQQ16sQIII",
        b"EFI PART",
        0x00010000,
        header_size,
        0,
        0,
        current_lba,
        backup_lba,
        first_usable,
        last_usable,
        guid_bytes(disk_guid),
        entries_lba,
        entry_count,
        entry_size,
        entries_crc,
    )
    header += b"\x00" * (SECTOR_SIZE - len(header))
    crc = binascii.crc32(header[:header_size]) & 0xFFFFFFFF
    header = header[:16] + struct.pack("<I", crc) + header[20:]
    return header


def protective_mbr(total_lbas: int) -> bytes:
    mbr = bytearray(SECTOR_SIZE)
    size = min(total_lbas - 1, 0xFFFFFFFF)
    mbr[446:462] = b"\x00\x00\x02\x00\xee\xff\xff\xff" + struct.pack("<II", 1, size)
    mbr[510:512] = b"\x55\xaa"
    return bytes(mbr)


def zero_pad(handle, current_size: int, target_size: int) -> None:
    if target_size <= current_size:
        return
    handle.write(b"\x00" * (target_size - current_size))


def copy_padded(handle, source: Path, partition_bytes: int) -> None:
    written = 0
    with source.open("rb") as src:
        for chunk in iter(lambda: src.read(1024 * 1024), b""):
            handle.write(chunk)
            written += len(chunk)
    zero_pad(handle, written, partition_bytes)


def build_image(root: Path, payload: Path, output: Path, manifest: Path, rootfs: Path | None = None) -> dict[str, Any]:
    payload = repo_path(root, payload)
    output = repo_path(root, output)
    manifest = repo_path(root, manifest)
    rootfs = repo_path(root, rootfs) if rootfs is not None else None
    if not payload.is_file():
        raise FileNotFoundError(f"payload missing: {payload}")
    if rootfs is not None and not rootfs.is_file():
        raise FileNotFoundError(f"rootfs missing: {rootfs}")

    payload_size = payload.stat().st_size
    payload_sectors = sectors_for(payload_size)
    payload_first = FIRST_USABLE_LBA
    payload_last = payload_first + payload_sectors - 1
    partitions: list[dict[str, Any]] = [
        {
            "id": "boot_payload",
            "source_path": repo_rel(root, payload),
            "source_sha256": sha256_file(payload),
            "source_size_bytes": payload_size,
            "first_lba": payload_first,
            "last_lba": payload_last,
            "partition_bytes": payload_sectors * SECTOR_SIZE,
            "bootrom_load_address": "0x80000000",
            "bootrom_reads_entire_partition": True,
        }
    ]
    next_lba = align_lba(payload_last + 1)
    if rootfs is not None:
        rootfs_size = rootfs.stat().st_size
        rootfs_sectors = sectors_for(rootfs_size)
        rootfs_first = next_lba
        rootfs_last = rootfs_first + rootfs_sectors - 1
        partitions.append(
            {
                "id": "rootfs_optional",
                "source_path": repo_rel(root, rootfs),
                "source_sha256": sha256_file(rootfs),
                "source_size_bytes": rootfs_size,
                "first_lba": rootfs_first,
                "last_lba": rootfs_last,
                "partition_bytes": rootfs_sectors * SECTOR_SIZE,
                "bootrom_load_address": None,
                "bootrom_reads_entire_partition": False,
            }
        )
        next_lba = align_lba(rootfs_last + 1)

    backup_entries_lba = next_lba
    backup_header_lba = backup_entries_lba + (ENTRY_COUNT * ENTRY_SIZE // SECTOR_SIZE)
    total_lbas = backup_header_lba + 1
    last_usable = backup_entries_lba - 1
    entries = bytearray(ENTRY_COUNT * ENTRY_SIZE)
    entries[0:ENTRY_SIZE] = make_entry(
        LINUX_DATA_GUID,
        RVMT_BOOT_GUID,
        payload_first,
        payload_last,
        "rvmt-fw-payload",
    )
    if len(partitions) > 1:
        row = partitions[1]
        entries[ENTRY_SIZE : 2 * ENTRY_SIZE] = make_entry(
            LINUX_DATA_GUID,
            RVMT_ROOTFS_GUID,
            int(row["first_lba"]),
            int(row["last_lba"]),
            "rvmt-rootfs",
        )
    entries_crc = binascii.crc32(entries) & 0xFFFFFFFF
    disk_guid = uuid.UUID("f91d7ca9-32fd-4744-b5e8-9cc7f4e5d205")
    primary_header = make_gpt_header(
        1,
        backup_header_lba,
        FIRST_USABLE_LBA,
        last_usable,
        disk_guid,
        2,
        ENTRY_COUNT,
        ENTRY_SIZE,
        entries_crc,
    )
    backup_header = make_gpt_header(
        backup_header_lba,
        1,
        FIRST_USABLE_LBA,
        last_usable,
        disk_guid,
        backup_entries_lba,
        ENTRY_COUNT,
        ENTRY_SIZE,
        entries_crc,
    )

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as out:
        out.write(protective_mbr(total_lbas))
        out.write(primary_header)
        out.write(entries)
        zero_pad(out, out.tell(), payload_first * SECTOR_SIZE)
        copy_padded(out, payload, payload_sectors * SECTOR_SIZE)
        if rootfs is not None:
            row = partitions[1]
            zero_pad(out, out.tell(), int(row["first_lba"]) * SECTOR_SIZE)
            copy_padded(out, rootfs, int(row["partition_bytes"]))
        zero_pad(out, out.tell(), backup_entries_lba * SECTOR_SIZE)
        out.write(entries)
        out.write(backup_header)

    data = {
        "schema": SCHEMA,
        "status": PASS_STATUS,
        "image": {
            "path": repo_rel(root, output),
            "sha256": sha256_file(output),
            "size_bytes": output.stat().st_size,
            "sector_size": SECTOR_SIZE,
            "total_lbas": total_lbas,
        },
        "partitions": partitions,
        "bootrom_contract": {
            "loader": "rtl/cva6/corev_apu/fpga/src/bootrom/src/gpt.c",
            "loads_first_gpt_entry_to": "0x80000000",
            "first_partition_must_be_boot_payload_only": True,
            "rootfs_partition_optional_and_not_loaded_by_bootrom": rootfs is not None,
        },
        "claim_boundary": {
            "local_sdcard_image_created": True,
            "buildroot_or_opensbi_compiled": False,
            "genesys2_sd_card_written": False,
            "genesys2_board_booted_from_this_image": False,
            "live_kernel_config_export_claimed": False,
            "board_cycle_source_claimed": False,
        },
        "non_claims": [
            "This manifest records a local image file only; it is not a physical SD-card write.",
            "A board boot claim requires a separate COM7/JTAG capture from the written image.",
            "Cycle-source and live-kernel-config claims require the dedicated board checkers.",
        ],
        "validation_commands": [
            "uv run python tools/create_genesys2_boot_sdcard_image.py --self-test",
            "uv run python tools/create_genesys2_boot_sdcard_image.py --payload <fw_payload.bin>",
            "uv run python tools/check_genesys2_boot_sdcard_image.py --root .",
            "uv run rvmt ndss:sdcard-linux-manifest --port COM7 --baud 115200",
            "uv run rvmt ndss:live-kernel-config-export --port COM7 --baud 115200",
            "uv run rvmt ndss:linux-counter-preflight",
        ],
    }
    write_json(manifest, data)
    return data


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="rvmt-sdcard-image-") as tmp:
        root = Path(tmp)
        payload = root / "fw_payload.bin"
        payload.write_bytes(b"RVMT-PAYLOAD" * 37)
        output = root / "build/linux/genesys2-cva6/sdcard.img"
        manifest = root / "results/evaluation/genesys2-cva6/current/sdcard_image_manifest.json"
        data = build_image(root, payload, output, manifest)
        if data["status"] != PASS_STATUS:
            print("[FAIL] sdcard image builder did not report PASS", file=sys.stderr)
            return 1
        image = output.read_bytes()
        if image[512:520] != b"EFI PART":
            print("[FAIL] primary GPT signature missing", file=sys.stderr)
            return 1
        entry = image[2 * SECTOR_SIZE : 2 * SECTOR_SIZE + ENTRY_SIZE]
        first_lba, last_lba = struct.unpack("<QQ", entry[32:48])
        partition = image[first_lba * SECTOR_SIZE : (last_lba + 1) * SECTOR_SIZE]
        if not partition.startswith(payload.read_bytes()):
            print("[FAIL] boot payload partition does not contain payload prefix", file=sys.stderr)
            return 1
        if any(partition[payload.stat().st_size :]):
            print("[FAIL] boot payload partition padding is not zero", file=sys.stderr)
            return 1
        loaded = json.loads(manifest.read_text(encoding="utf-8"))
        if loaded["image"]["sha256"] != sha256_file(output):
            print("[FAIL] manifest image sha256 mismatch", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 boot SD-card image builder self-test")
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create a GPT SD-card image layout for the Genesys2/CVA6 bootrom payload.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--payload", type=Path, help="OpenSBI fw_payload.bin or equivalent first-partition boot payload.")
    parser.add_argument("--rootfs", type=Path, help="Optional rootfs image placed after the boot payload partition.")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return self_test()
    if args.payload is None:
        print("[FAIL] --payload is required unless --self-test is used", file=sys.stderr)
        return 2
    root = args.root.resolve()
    try:
        data = build_image(root, args.payload, args.out, args.manifest, args.rootfs)
    except Exception as exc:
        print(f"[FAIL] SD-card image creation failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"status": data["status"], "image": data["image"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
