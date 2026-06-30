from __future__ import annotations

import argparse
import datetime as dt
import json
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
DEFAULT_IMAGE = Path("build/linux/genesys2-cva6/sdcard.img")
DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/sdcard_write_preflight_summary.json")
SCHEMA = "rvmt.genesys2.sdcard_write_preflight.v1"
PASS_STATUS = "PASS_SDCARD_WRITE_TARGET_PREFLIGHT_READY"
DEFAULT_MAX_TARGET_SIZE_GIB = 128
SAFE_BUS_TYPES = {"USB", "SD", "MMC", "SecureDigital"}


def as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return False


def as_int(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def status_text(value: Any) -> str:
    if isinstance(value, list):
        return ",".join(str(item) for item in value)
    return str(value or "")


def normalize_disk(raw: dict[str, Any]) -> dict[str, Any]:
    size = as_int(raw.get("Size"))
    number = as_int(raw.get("Number"))
    return {
        "number": number,
        "friendly_name": str(raw.get("FriendlyName") or ""),
        "serial_number_present": bool(str(raw.get("SerialNumber") or "").strip()),
        "operational_status": status_text(raw.get("OperationalStatus")),
        "size_bytes": size,
        "size_gib": round(size / (1024**3), 3) if size is not None else None,
        "bus_type": str(raw.get("BusType") or ""),
        "partition_style": str(raw.get("PartitionStyle") or ""),
        "is_boot": as_bool(raw.get("IsBoot")),
        "is_system": as_bool(raw.get("IsSystem")),
        "is_offline": as_bool(raw.get("IsOffline")),
        "is_read_only": as_bool(raw.get("IsReadOnly")),
    }


def evaluate_disk(
    disk: dict[str, Any],
    *,
    image_size_bytes: int | None,
    max_target_size_bytes: int,
    allow_large_target: bool,
) -> dict[str, Any]:
    reasons: list[str] = []
    warnings: list[str] = []
    number = disk.get("number")
    size = disk.get("size_bytes")
    bus_type = str(disk.get("bus_type") or "")
    operational = str(disk.get("operational_status") or "")

    if number is None:
        reasons.append("disk number unavailable")
    elif number == 0:
        reasons.append("disk 0 is never accepted as an SD-card write target")
    if disk.get("is_boot") is True:
        reasons.append("disk is marked as boot")
    if disk.get("is_system") is True:
        reasons.append("disk is marked as system")
    if disk.get("is_offline") is True:
        reasons.append("disk is offline")
    if disk.get("is_read_only") is True:
        reasons.append("disk is read-only")
    if "online" not in operational.lower():
        reasons.append("disk operational status is not Online")
    if bus_type not in SAFE_BUS_TYPES:
        reasons.append(f"disk bus type is {bus_type or 'unknown'}, not an accepted SD/USB removable class")
    if size is None or size <= 0:
        reasons.append("disk size unavailable")
    elif image_size_bytes is not None and size < image_size_bytes:
        reasons.append("disk is smaller than the SD-card image")
    if size is not None and not allow_large_target and size > max_target_size_bytes:
        reasons.append("disk is larger than the configured SD-card safety limit")
    if str(disk.get("partition_style") or "").upper() not in {"RAW", "MBR", "GPT"}:
        warnings.append("partition style is unknown to the preflight")

    return {
        "safe_preflight_candidate": not reasons,
        "blocking_reasons": reasons,
        "warnings": warnings,
    }


def powershell_disk_inventory() -> tuple[list[dict[str, Any]], str, str | None]:
    executable = "powershell.exe" if sys.platform.startswith("win") else "powershell"
    command = [
        executable,
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        (
            "$ErrorActionPreference = 'Stop'; "
            "Get-Disk | Sort-Object Number | "
            "Select-Object Number,FriendlyName,SerialNumber,OperationalStatus,Size,BusType,PartitionStyle,IsBoot,IsSystem,IsOffline,IsReadOnly | "
            "ConvertTo-Json -Depth 4"
        ),
    ]
    display = " ".join(command)
    try:
        completed = subprocess.run(
            command,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        return [], display, f"failed to start PowerShell disk inventory: {exc}"
    if completed.returncode != 0:
        return [], display, completed.stderr.strip() or f"PowerShell disk inventory exited {completed.returncode}"
    text = completed.stdout.strip()
    if not text:
        return [], display, "PowerShell disk inventory returned no JSON"
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        return [], display, f"PowerShell disk inventory returned invalid JSON: {exc}"
    rows = payload if isinstance(payload, list) else [payload]
    disks = [normalize_disk(row) for row in rows if isinstance(row, dict)]
    return disks, display, None


def image_row(root: Path, image: Path, expected_sha256: str | None) -> tuple[dict[str, Any], str | None]:
    row: dict[str, Any] = {
        "path": repo_rel(root, image),
        "exists": image.is_file(),
        "expected_sha256": expected_sha256,
    }
    if not image.is_file():
        return row, "BLOCKED_SDCARD_IMAGE_MISSING"
    actual = sha256_file(image)
    row.update(
        {
            "sha256": actual,
            "size_bytes": image.stat().st_size,
        }
    )
    if expected_sha256 and expected_sha256 != actual:
        return row, "BLOCKED_SDCARD_IMAGE_HASH_MISMATCH"
    if not expected_sha256:
        row["expected_sha256"] = actual
    return row, None


def build_summary(
    *,
    root: Path,
    image: Path,
    expected_sha256: str | None,
    disk_number: int | None,
    max_target_size_gib: int,
    allow_large_target: bool,
    disks: list[dict[str, Any]],
    inventory_command: str,
    inventory_error: str | None,
) -> dict[str, Any]:
    max_target_size_bytes = max_target_size_gib * 1024**3
    image_info, image_blocker = image_row(root, image, expected_sha256)
    image_size = image_info.get("size_bytes") if isinstance(image_info.get("size_bytes"), int) else None
    evaluated_disks: list[dict[str, Any]] = []
    for disk in disks:
        row = dict(disk)
        row["preflight"] = evaluate_disk(
            row,
            image_size_bytes=image_size,
            max_target_size_bytes=max_target_size_bytes,
            allow_large_target=allow_large_target,
        )
        evaluated_disks.append(row)

    selected_disk = None
    if disk_number is not None:
        selected_disk = next((row for row in evaluated_disks if row.get("number") == disk_number), None)

    safe_candidates = [
        row for row in evaluated_disks if row.get("preflight", {}).get("safe_preflight_candidate") is True
    ]
    if image_blocker is not None:
        status = image_blocker
        blocked_reason = "SD-card image is missing or does not match the expected hash"
    elif inventory_error is not None:
        status = "BLOCKED_HOST_DISK_ENUMERATION_UNAVAILABLE"
        blocked_reason = inventory_error
    elif disk_number is None and not safe_candidates:
        status = "BLOCKED_NO_SAFE_SDCARD_TARGET"
        blocked_reason = "No enumerated host disk satisfies the read-only SD-card target safety preflight"
    elif disk_number is None:
        status = "BLOCKED_SDCARD_WRITE_TARGET_NOT_SELECTED"
        blocked_reason = "At least one candidate exists, but a destructive write target must be selected explicitly"
    elif selected_disk is None:
        status = "BLOCKED_SDCARD_WRITE_TARGET_NOT_FOUND"
        blocked_reason = f"Requested disk number {disk_number} was not found in the read-only inventory"
    elif selected_disk.get("preflight", {}).get("safe_preflight_candidate") is True:
        status = PASS_STATUS
        blocked_reason = None
    else:
        status = "BLOCKED_SDCARD_WRITE_TARGET_UNSAFE"
        blocked_reason = "; ".join(str(item) for item in selected_disk.get("preflight", {}).get("blocking_reasons", []))

    return {
        "schema": SCHEMA,
        "status": status,
        "generated_utc": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat(),
        "canonical_evaluation_root": "results/evaluation/genesys2-cva6/current",
        "scope": "read-only host preflight for selecting a physical SD-card target for the Genesys2/CVA6 image",
        "image": image_info,
        "target_policy": {
            "target_disk_number": disk_number,
            "explicit_target_required_for_pass": True,
            "max_target_size_gib": max_target_size_gib,
            "allow_large_target": allow_large_target,
            "accepted_bus_types": sorted(SAFE_BUS_TYPES),
        },
        "host_disk_inventory": {
            "method": "PowerShell Get-Disk read-only inventory",
            "command": inventory_command,
            "error": inventory_error,
            "disk_count": len(evaluated_disks),
            "safe_candidate_count": len(safe_candidates),
            "disks": evaluated_disks,
        },
        "selected_disk": selected_disk,
        "blocked_reason": blocked_reason,
        "claim_boundary": {
            "disk_inventory_read_only": True,
            "sdcard_write_target_preflight_ready": status == PASS_STATUS,
            "destructive_write_performed": False,
            "physical_sd_card_written": False,
            "genesys2_board_booted_written_image": False,
            "live_kernel_config_export_claimed": False,
            "board_cycle_source_claimed": False,
        },
        "non_claims": [
            "This preflight performs no physical SD-card write and runs only read-only host disk inventory.",
            "A PASS preflight only means a target disk is safe enough to proceed manually; it is not a board boot claim.",
            "Genesys2 boot, live kernel config, and cycle-source evidence require separate UART/JTAG captures after a real SD-card write.",
        ],
        "validation_commands": [
            "uv run rvmt ndss:boot-sdcard-image --payload build/linux/genesys2-cva6/images/fw_payload.bin",
            "uv run rvmt ndss:sdcard-write-preflight --image build/linux/genesys2-cva6/sdcard.img",
            "uv run python tools/check_genesys2_sdcard_write_preflight.py --root .",
            "uv run python tools/check_genesys2_sdcard_write_preflight.py --root . --require-pass",
            "uv run rvmt ndss:sdcard-linux-manifest --port COM7 --baud 115200",
            "uv run rvmt ndss:live-kernel-config-export --port COM7 --baud 115200",
        ],
    }


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="rvmt-sdcard-write-preflight-") as tmp:
        root = Path(tmp)
        image = root / DEFAULT_IMAGE
        image.parent.mkdir(parents=True)
        image.write_bytes(b"RVMT-SDCARD-IMAGE\n" * 512)
        base_disks = [
            {
                "number": 0,
                "friendly_name": "System NVMe",
                "serial_number_present": True,
                "operational_status": "Online",
                "size_bytes": 512 * 1024**3,
                "size_gib": 512,
                "bus_type": "NVMe",
                "partition_style": "GPT",
                "is_boot": True,
                "is_system": True,
                "is_offline": False,
                "is_read_only": False,
            },
            {
                "number": 4,
                "friendly_name": "USB SD Reader",
                "serial_number_present": True,
                "operational_status": "Online",
                "size_bytes": 8 * 1024**3,
                "size_gib": 8,
                "bus_type": "USB",
                "partition_style": "MBR",
                "is_boot": False,
                "is_system": False,
                "is_offline": False,
                "is_read_only": False,
            },
        ]
        blocked = build_summary(
            root=root,
            image=image,
            expected_sha256=None,
            disk_number=None,
            max_target_size_gib=DEFAULT_MAX_TARGET_SIZE_GIB,
            allow_large_target=False,
            disks=base_disks,
            inventory_command="fixture",
            inventory_error=None,
        )
        if blocked.get("status") != "BLOCKED_SDCARD_WRITE_TARGET_NOT_SELECTED":
            print("[FAIL] expected fixture without explicit target to block", file=sys.stderr)
            return 1
        passed = build_summary(
            root=root,
            image=image,
            expected_sha256=None,
            disk_number=4,
            max_target_size_gib=DEFAULT_MAX_TARGET_SIZE_GIB,
            allow_large_target=False,
            disks=base_disks,
            inventory_command="fixture",
            inventory_error=None,
        )
        if passed.get("status") != PASS_STATUS:
            print("[FAIL] expected explicit safe fixture disk to pass", file=sys.stderr)
            return 1
        unsafe = build_summary(
            root=root,
            image=image,
            expected_sha256=None,
            disk_number=0,
            max_target_size_gib=DEFAULT_MAX_TARGET_SIZE_GIB,
            allow_large_target=False,
            disks=base_disks,
            inventory_command="fixture",
            inventory_error=None,
        )
        if unsafe.get("status") != "BLOCKED_SDCARD_WRITE_TARGET_UNSAFE":
            print("[FAIL] expected system disk fixture to block", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 SD-card write preflight runner self-test")
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create a read-only host SD-card write-target preflight summary.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--image", type=Path, default=DEFAULT_IMAGE)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--expected-image-sha256")
    parser.add_argument("--disk-number", type=int, help="Explicit Windows Get-Disk number to preflight as the SD-card write target.")
    parser.add_argument("--max-target-size-gib", type=int, default=DEFAULT_MAX_TARGET_SIZE_GIB)
    parser.add_argument("--allow-large-target", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    image = repo_path(root, args.image)
    summary = repo_path(root, args.summary)
    disks, inventory_command, inventory_error = powershell_disk_inventory()
    data = build_summary(
        root=root,
        image=image,
        expected_sha256=args.expected_image_sha256,
        disk_number=args.disk_number,
        max_target_size_gib=args.max_target_size_gib,
        allow_large_target=args.allow_large_target,
        disks=disks,
        inventory_command=inventory_command,
        inventory_error=inventory_error,
    )
    write_json(summary, data)
    print(f"[{data['status']}] wrote {summary}")
    if data.get("blocked_reason"):
        print(f"[BLOCKED] {data['blocked_reason']}")
    return 0 if data.get("status") == PASS_STATUS else 2


if __name__ == "__main__":
    raise SystemExit(main())
