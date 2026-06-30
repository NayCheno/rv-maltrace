from __future__ import annotations

import argparse
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
    write_json,
)


DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/linux_rebuild_manifest.json")
SUMMARY_SCHEMA = "rvmt.genesys2.cva6_linux_rebuild.v1"
PASS_PREPARED = "PASS_LINUX_REBUILD_PREPARED"
PASS_BUILT = "PASS_LINUX_PAYLOAD_BUILT"
ACCEPTED_STATUSES = {
    PASS_PREPARED,
    PASS_BUILT,
    "BLOCKED_LINUX_REBUILD_DEPS_MISSING",
    "BLOCKED_LINUX_REBUILD_SOURCE_FETCH_REQUIRED",
    "BLOCKED_LINUX_REBUILD_COMMAND_FAILED",
    "BLOCKED_LINUX_PAYLOAD_BUILD_INCOMPLETE",
}
REQUIRED_SOURCE_IDS = {
    "buildroot_defconfig",
    "linux_kernel_config",
    "opensbi_manifest",
    "opensbi_source_lock",
    "device_tree_template",
}
REQUIRED_GENERATED_IDS = {"generated_buildroot_defconfig", "generated_cv64a6_dts"}
REQUIRED_TOOL_NAMES = {
    "bash",
    "bc",
    "bison",
    "cpio",
    "file",
    "flex",
    "g++",
    "gcc",
    "git",
    "make",
    "python3",
    "rsync",
    "tar",
    "wget",
}


def row_by_id(rows: list[Any]) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("id")): row
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("id"), str)
    }


def check_hashed_row(errors: list[str], root: Path, row: dict[str, Any], label: str) -> None:
    path_value = row.get("path")
    require(errors, bool(path_value), f"{label}: path missing")
    if not path_value:
        return
    path = repo_path(root, path_value)
    require(errors, path.is_file(), f"{label}: file missing: {path_value}")
    if path.is_file():
        require(errors, row.get("sha256") == sha256_file(path), f"{label}: sha256 mismatch")
        if row.get("size_bytes") is not None:
            require(errors, int(row.get("size_bytes")) == path.stat().st_size, f"{label}: size_bytes mismatch")


def check_summary(data: dict[str, Any], root: Path, *, require_pass: bool) -> list[str]:
    errors: list[str] = []
    status = str(data.get("status") or "")
    require(errors, data.get("schema") == SUMMARY_SCHEMA, f"schema must be {SUMMARY_SCHEMA}")
    require(errors, status in ACCEPTED_STATUSES, f"unexpected status: {status}")
    if require_pass:
        require(errors, status == PASS_BUILT, f"--require-pass needs {PASS_BUILT}, got {status}")
    require(errors, data.get("canonical_evaluation_root") == "results/evaluation/genesys2-cva6/current", "canonical evidence root mismatch")

    sources = row_by_id(as_list(data.get("source_inputs")))
    missing_sources = sorted(REQUIRED_SOURCE_IDS - set(sources))
    require(errors, not missing_sources, f"missing source rows: {', '.join(missing_sources)}")
    for row_id in sorted(REQUIRED_SOURCE_IDS & set(sources)):
        require(errors, sources[row_id].get("exists") is True, f"{row_id}: source input must exist")
        check_hashed_row(errors, root, sources[row_id], row_id)

    generated = row_by_id(as_list(data.get("generated_inputs")))
    missing_generated = sorted(REQUIRED_GENERATED_IDS - set(generated))
    require(errors, not missing_generated, f"missing generated rows: {', '.join(missing_generated)}")
    for row_id in sorted(REQUIRED_GENERATED_IDS & set(generated)):
        require(errors, generated[row_id].get("exists") is True, f"{row_id}: generated input must exist")
        check_hashed_row(errors, root, generated[row_id], row_id)

    tool_rows = {
        str(row.get("tool")): row
        for row in as_list(data.get("container_tools"))
        if isinstance(row, dict) and isinstance(row.get("tool"), str)
    }
    missing_tool_rows = sorted(REQUIRED_TOOL_NAMES - set(tool_rows))
    require(errors, not missing_tool_rows, f"missing container tool rows: {', '.join(missing_tool_rows)}")
    missing_tools = sorted(name for name, row in tool_rows.items() if row.get("available") is not True)
    if status == "BLOCKED_LINUX_REBUILD_DEPS_MISSING":
        require(errors, bool(missing_tools), "dependency BLOCKED status requires unavailable tools")
    elif missing_tools:
        errors.append("non-dependency status cannot have unavailable required tools: " + ", ".join(missing_tools))

    buildroot = as_dict(data.get("buildroot"))
    require(errors, bool(buildroot.get("version")), "buildroot.version missing")
    require(errors, bool(buildroot.get("url")), "buildroot.url missing")
    require(errors, bool(buildroot.get("build_dir")), "buildroot.build_dir missing")
    if status == PASS_BUILT:
        artifacts = row_by_id(as_list(data.get("output_artifacts")))
        require(errors, "fw_payload_bin" in artifacts, "PASS build requires fw_payload_bin artifact")
        if "fw_payload_bin" in artifacts:
            check_hashed_row(errors, root, artifacts["fw_payload_bin"], "fw_payload_bin")
    elif status != PASS_PREPARED:
        require(errors, bool(data.get("blocked_reason")), "blocked status requires blocked_reason")

    boundary = as_dict(data.get("claim_boundary"))
    require(errors, boundary.get("docker_buildroot_preparation_executed") is True, "preparation boundary missing")
    require(errors, boundary.get("buildroot_or_opensbi_compiled") is (status == PASS_BUILT), "compiled claim must match PASS_BUILT")
    require(errors, boundary.get("boot_payload_built") is (status == PASS_BUILT), "payload claim must match PASS_BUILT")
    require(errors, boundary.get("sd_card_image_built") is False, "Linux rebuild manifest must not claim SD-card image creation")
    require(errors, boundary.get("genesys2_sd_card_written") is False, "Linux rebuild manifest must not claim SD-card write")
    require(errors, boundary.get("genesys2_board_booted_from_this_image") is False, "Linux rebuild manifest must not claim board boot")
    require(errors, boundary.get("board_cycle_source_claimed") is False, "Linux rebuild manifest must not claim board cycle source")
    require(errors, boundary.get("qemu_or_strace_substitution_allowed") is False, "QEMU/strace substitution must be forbidden")

    commands = " ".join(str(item) for item in as_list(data.get("validation_commands")))
    for needle in (
        "rvmt ndss:linux-rebuild-prep",
        "check_genesys2_linux_rebuild_manifest.py --root .",
        "rvmt ndss:boot-sdcard-image --payload",
        "rvmt ndss:live-kernel-config-export",
        "rvmt ndss:linux-counter-preflight",
    ):
        require(errors, needle in commands, f"validation command missing: {needle}")

    non_claims = " ".join(str(item).lower() for item in as_list(data.get("non_claims")))
    require(errors, "fw_payload.bin" in non_claims, "non_claims must require fw_payload.bin before payload claim")
    require(errors, "physical sd card" in non_claims, "non_claims must reject physical SD-card write/boot claim")
    require(errors, "qemu, strace" in non_claims, "non_claims must keep oracle boundary")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="rvmt-linux-rebuild-check-") as tmp:
        root = Path(tmp)
        current = root / "results/evaluation/genesys2-cva6/current"
        current.mkdir(parents=True, exist_ok=True)
        source_rows = []
        for row_id in REQUIRED_SOURCE_IDS:
            path = root / f"src/{row_id}.txt"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(row_id + "\n", encoding="utf-8")
            source_rows.append(
                {
                    "id": row_id,
                    "path": path.relative_to(root).as_posix(),
                    "exists": True,
                    "sha256": sha256_file(path),
                    "size_bytes": path.stat().st_size,
                }
            )
        generated_rows = []
        for row_id in REQUIRED_GENERATED_IDS:
            path = root / f"build/{row_id}.txt"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(row_id + "\n", encoding="utf-8")
            generated_rows.append(
                {
                    "id": row_id,
                    "path": path.relative_to(root).as_posix(),
                    "exists": True,
                    "sha256": sha256_file(path),
                    "size_bytes": path.stat().st_size,
                }
            )
        summary = {
            "schema": SUMMARY_SCHEMA,
            "status": PASS_PREPARED,
            "canonical_evaluation_root": "results/evaluation/genesys2-cva6/current",
            "source_inputs": source_rows,
            "generated_inputs": generated_rows,
            "container_tools": [{"tool": name, "available": True, "path": f"/usr/bin/{name}"} for name in REQUIRED_TOOL_NAMES],
            "buildroot": {
                "version": "fixture",
                "url": "https://buildroot.org/downloads/buildroot-fixture.tar.gz",
                "build_dir": "build/linux/fixture",
            },
            "output_artifacts": [],
            "validation_commands": [
                "uv run rvmt ndss:linux-rebuild-prep",
                "uv run python tools/check_genesys2_linux_rebuild_manifest.py --root .",
                "uv run rvmt ndss:boot-sdcard-image --payload build/linux/genesys2-cva6/buildroot-output/images/fw_payload.bin",
                "uv run rvmt ndss:live-kernel-config-export --port COM7 --baud 115200",
                "uv run rvmt ndss:linux-counter-preflight",
            ],
            "claim_boundary": {
                "docker_buildroot_preparation_executed": True,
                "buildroot_or_opensbi_compiled": False,
                "boot_payload_built": False,
                "sd_card_image_built": False,
                "genesys2_sd_card_written": False,
                "genesys2_board_booted_from_this_image": False,
                "board_cycle_source_claimed": False,
                "qemu_or_strace_substitution_allowed": False,
            },
            "non_claims": [
                "A boot payload claim requires fw_payload.bin.",
                "This does not write a physical SD card.",
                "QEMU, strace, and local software checks are oracles only.",
            ],
        }
        errors = check_summary(summary, root, require_pass=False)
        if errors:
            print("[FAIL] good fixture rejected", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        if not check_summary(summary, root, require_pass=True):
            print("[FAIL] --require-pass accepted preparation-only fixture", file=sys.stderr)
            return 1
        summary["claim_boundary"]["board_cycle_source_claimed"] = True
        errors = check_summary(summary, root, require_pass=False)
        if not any("must not claim board cycle source" in error for error in errors):
            print("[FAIL] checker missed board cycle-source overclaim", file=sys.stderr)
            return 1
    print("[PASS] Genesys2/CVA6 Linux rebuild manifest checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Genesys2/CVA6 Linux rebuild preparation/build manifest.")
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
            print(f"[FAIL] Linux rebuild manifest missing: {summary}", file=sys.stderr)
            return 1
        print(f"[BLOCKED_LINUX_REBUILD_SOURCE_FETCH_REQUIRED] Linux rebuild manifest missing: {summary}")
        return 0
    try:
        data = load_json(summary)
        errors = check_summary(data, root, require_pass=args.require_pass)
    except Exception as exc:
        print(f"[FAIL] Linux rebuild manifest checker error: {exc}", file=sys.stderr)
        return 2
    if errors:
        print("[FAIL] Linux rebuild manifest is not acceptable", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(f"[PASS] Linux rebuild manifest accepted: {summary} status={data.get('status')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
