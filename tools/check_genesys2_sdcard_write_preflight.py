from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/sdcard_write_preflight_summary.json")
SCHEMA = "rvmt.genesys2.sdcard_write_preflight.v1"
PASS_STATUS = "PASS_SDCARD_WRITE_TARGET_PREFLIGHT_READY"
BLOCKED_STATUSES = {
    "BLOCKED_SDCARD_IMAGE_MISSING",
    "BLOCKED_SDCARD_IMAGE_HASH_MISMATCH",
    "BLOCKED_HOST_DISK_ENUMERATION_UNAVAILABLE",
    "BLOCKED_NO_SAFE_SDCARD_TARGET",
    "BLOCKED_SDCARD_WRITE_TARGET_NOT_SELECTED",
    "BLOCKED_SDCARD_WRITE_TARGET_NOT_FOUND",
    "BLOCKED_SDCARD_WRITE_TARGET_UNSAFE",
}


def repo_path(root: Path, value: Any) -> Path:
    path = Path(str(value))
    return path if path.is_absolute() else root / path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def require(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def check_image(errors: list[str], data: dict[str, Any], root: Path) -> int | None:
    image = as_dict(data.get("image"))
    image_path_value = image.get("path")
    require(errors, isinstance(image_path_value, str) and bool(image_path_value), "image.path missing")
    if not isinstance(image_path_value, str) or not image_path_value:
        return None
    image_path = repo_path(root, image_path_value)
    exists = image_path.is_file()
    if data.get("status") != "BLOCKED_SDCARD_IMAGE_MISSING":
        require(errors, exists, f"SD-card image missing: {image_path_value}")
    require(errors, image.get("exists") is exists, "image.exists does not match filesystem")
    if not exists:
        return None
    actual = sha256_file(image_path)
    require(errors, image.get("sha256") == actual, "image.sha256 mismatch")
    require(errors, image.get("expected_sha256") == actual, "image.expected_sha256 mismatch")
    require(errors, int(image.get("size_bytes") or -1) == image_path.stat().st_size, "image.size_bytes mismatch")
    return image_path.stat().st_size


def disk_is_safe(row: dict[str, Any], image_size: int | None, policy: dict[str, Any], errors: list[str], prefix: str) -> None:
    preflight = as_dict(row.get("preflight"))
    require(errors, preflight.get("safe_preflight_candidate") is True, f"{prefix}: selected disk is not safe")
    require(errors, not as_list(preflight.get("blocking_reasons")), f"{prefix}: selected disk has blocking reasons")
    require(errors, row.get("is_boot") is False, f"{prefix}: selected disk is boot")
    require(errors, row.get("is_system") is False, f"{prefix}: selected disk is system")
    require(errors, row.get("is_offline") is False, f"{prefix}: selected disk is offline")
    require(errors, row.get("is_read_only") is False, f"{prefix}: selected disk is read-only")
    require(errors, "online" in str(row.get("operational_status") or "").lower(), f"{prefix}: selected disk is not online")
    accepted_bus_types = set(str(item) for item in as_list(policy.get("accepted_bus_types")))
    require(errors, str(row.get("bus_type") or "") in accepted_bus_types, f"{prefix}: selected disk bus type is not accepted")
    size = row.get("size_bytes")
    require(errors, isinstance(size, int) and size > 0, f"{prefix}: selected disk size invalid")
    if isinstance(size, int) and image_size is not None:
        require(errors, size >= image_size, f"{prefix}: selected disk is smaller than image")
    max_gib = int(policy.get("max_target_size_gib") or 0)
    if isinstance(size, int) and policy.get("allow_large_target") is not True and max_gib > 0:
        require(errors, size <= max_gib * 1024**3, f"{prefix}: selected disk exceeds max target size")


def check_manifest(data: dict[str, Any], root: Path, *, require_pass: bool = False) -> list[str]:
    errors: list[str] = []
    status = data.get("status")
    require(errors, data.get("schema") == SCHEMA, f"schema must be {SCHEMA}")
    require(errors, status == PASS_STATUS or status in BLOCKED_STATUSES, "status must be PASS or an accepted BLOCKED status")
    if require_pass:
        require(errors, status == PASS_STATUS, f"status must be {PASS_STATUS} when --require-pass is used")

    image_size = check_image(errors, data, root)
    policy = as_dict(data.get("target_policy"))
    require(errors, policy.get("explicit_target_required_for_pass") is True, "explicit target policy missing")
    require(errors, isinstance(policy.get("max_target_size_gib"), int), "max_target_size_gib missing")
    require(errors, isinstance(as_list(policy.get("accepted_bus_types")), list), "accepted_bus_types missing")

    inventory = as_dict(data.get("host_disk_inventory"))
    disks = as_list(inventory.get("disks"))
    require(errors, inventory.get("method") == "PowerShell Get-Disk read-only inventory", "inventory method mismatch")
    require(errors, isinstance(inventory.get("command"), str) and "Get-Disk" in inventory.get("command", ""), "inventory command missing Get-Disk")
    disk_count_value = inventory.get("disk_count")
    require(errors, isinstance(disk_count_value, int) and disk_count_value == len(disks), "disk_count mismatch")
    safe_count = sum(1 for row in disks if as_dict(row).get("preflight", {}).get("safe_preflight_candidate") is True)
    safe_count_value = inventory.get("safe_candidate_count")
    require(
        errors,
        isinstance(safe_count_value, int) and safe_count_value == safe_count,
        "safe_candidate_count mismatch",
    )

    selected = as_dict(data.get("selected_disk"))
    if status == PASS_STATUS:
        require(errors, bool(selected), "PASS requires selected_disk")
        require(errors, policy.get("target_disk_number") == selected.get("number"), "PASS target disk number mismatch")
        disk_is_safe(selected, image_size, policy, errors, "PASS selected_disk")
    else:
        require(errors, status != PASS_STATUS, "blocked summary must not be PASS")

    if status == "BLOCKED_NO_SAFE_SDCARD_TARGET":
        require(errors, safe_count == 0, "BLOCKED_NO_SAFE_SDCARD_TARGET requires zero safe candidates")
    if status == "BLOCKED_SDCARD_WRITE_TARGET_NOT_SELECTED":
        require(errors, policy.get("target_disk_number") is None, "target-not-selected status must not set target_disk_number")
        require(errors, safe_count > 0, "target-not-selected status requires at least one safe candidate")
    if status == "BLOCKED_SDCARD_WRITE_TARGET_UNSAFE":
        require(errors, bool(selected), "unsafe target status requires selected_disk")
        require(errors, bool(as_list(selected.get("preflight", {}).get("blocking_reasons"))), "unsafe target status requires blocking reasons")

    boundary = as_dict(data.get("claim_boundary"))
    require(errors, boundary.get("disk_inventory_read_only") is True, "disk_inventory_read_only boundary missing")
    require(errors, boundary.get("sdcard_write_target_preflight_ready") is (status == PASS_STATUS), "preflight-ready boundary mismatch")
    require(errors, boundary.get("destructive_write_performed") is False, "must not claim destructive write")
    require(errors, boundary.get("physical_sd_card_written") is False, "must not claim physical SD-card write")
    require(errors, boundary.get("genesys2_board_booted_written_image") is False, "must not claim board boot")
    require(errors, boundary.get("live_kernel_config_export_claimed") is False, "must not claim live kernel config export")
    require(errors, boundary.get("board_cycle_source_claimed") is False, "must not claim board cycle source")

    non_claims = " ".join(str(item).lower() for item in as_list(data.get("non_claims")))
    require(errors, "no physical sd-card write" in non_claims, "non_claims must reject physical SD-card write")
    require(errors, "not a board boot claim" in non_claims, "non_claims must reject board boot")

    commands = " ".join(str(item) for item in as_list(data.get("validation_commands")))
    require(errors, "rvmt ndss:sdcard-write-preflight" in commands, "validation command missing rvmt preflight")
    require(errors, "check_genesys2_sdcard_write_preflight.py --root ." in commands, "validation command missing checker")
    require(errors, "--require-pass" in commands, "validation command missing require-pass checker")
    require(errors, "rvmt ndss:sdcard-linux-manifest" in commands, "validation command missing post-write board manifest capture")
    require(errors, "rvmt ndss:live-kernel-config-export" in commands, "validation command missing post-write live kernel config export")
    return errors


def fixture_summary(root: Path, *, status: str = PASS_STATUS) -> dict[str, Any]:
    image = root / "build/linux/genesys2-cva6/sdcard.img"
    image.parent.mkdir(parents=True, exist_ok=True)
    image.write_bytes(b"RVMT-SDCARD\n" * 1024)
    safe_disk = {
        "bus_type": "USB",
        "friendly_name": "USB SD Reader",
        "is_boot": False,
        "is_offline": False,
        "is_read_only": False,
        "is_system": False,
        "number": 3,
        "operational_status": "Online",
        "partition_style": "MBR",
        "preflight": {"blocking_reasons": [], "safe_preflight_candidate": True, "warnings": []},
        "serial_number_present": True,
        "size_bytes": 8 * 1024**3,
        "size_gib": 8,
    }
    selected = safe_disk if status == PASS_STATUS else None
    safe_count = 1 if status != "BLOCKED_NO_SAFE_SDCARD_TARGET" else 0
    disks = [safe_disk] if safe_count else []
    return {
        "schema": SCHEMA,
        "status": status,
        "canonical_evaluation_root": "results/evaluation/genesys2-cva6/current",
        "scope": "read-only host preflight for selecting a physical SD-card target for the Genesys2/CVA6 image",
        "image": {
            "path": "build/linux/genesys2-cva6/sdcard.img",
            "exists": True,
            "sha256": sha256_file(image),
            "expected_sha256": sha256_file(image),
            "size_bytes": image.stat().st_size,
        },
        "target_policy": {
            "target_disk_number": selected.get("number") if selected else None,
            "explicit_target_required_for_pass": True,
            "max_target_size_gib": 128,
            "allow_large_target": False,
            "accepted_bus_types": ["MMC", "SD", "SecureDigital", "USB"],
        },
        "host_disk_inventory": {
            "method": "PowerShell Get-Disk read-only inventory",
            "command": "powershell.exe Get-Disk",
            "error": None,
            "disk_count": len(disks),
            "safe_candidate_count": safe_count,
            "disks": disks,
        },
        "selected_disk": selected,
        "blocked_reason": None if status == PASS_STATUS else "fixture blocked",
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
        ],
        "validation_commands": [
            "uv run rvmt ndss:sdcard-write-preflight --image build/linux/genesys2-cva6/sdcard.img",
            "uv run python tools/check_genesys2_sdcard_write_preflight.py --root .",
            "uv run python tools/check_genesys2_sdcard_write_preflight.py --root . --require-pass",
            "uv run rvmt ndss:sdcard-linux-manifest --port COM7 --baud 115200",
            "uv run rvmt ndss:live-kernel-config-export --port COM7 --baud 115200",
        ],
    }


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="rvmt-sdcard-write-check-") as tmp:
        root = Path(tmp)
        good = fixture_summary(root)
        errors = check_manifest(good, root, require_pass=True)
        if errors:
            print("[FAIL] good SD-card write preflight fixture rejected", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        blocked = fixture_summary(root, status="BLOCKED_NO_SAFE_SDCARD_TARGET")
        errors = check_manifest(blocked, root)
        if errors:
            print("[FAIL] blocked SD-card write preflight fixture rejected", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        bad = fixture_summary(root)
        bad["claim_boundary"]["physical_sd_card_written"] = True
        if not check_manifest(bad, root):
            print("[FAIL] bad SD-card write preflight fixture accepted", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 SD-card write preflight checker self-test")
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check the host SD-card write-target preflight summary.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--require-pass", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    summary = repo_path(root, args.summary)
    if not summary.is_file():
        print(f"[FAIL] missing SD-card write preflight summary: {summary}", file=sys.stderr)
        return 1
    try:
        data = load_json(summary)
        errors = check_manifest(data, root, require_pass=args.require_pass)
    except Exception as exc:
        print(f"[FAIL] SD-card write preflight checker error: {exc}", file=sys.stderr)
        return 1
    if errors:
        print("[FAIL] SD-card write preflight summary is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    status = data.get("status")
    print(f"[PASS] SD-card write preflight summary accepted: {summary} ({status})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
