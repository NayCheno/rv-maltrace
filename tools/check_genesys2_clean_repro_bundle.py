from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


DEFAULT_SUMMARY = Path("results/evaluation/genesys2-cva6/current/clean_repro_bundle_manifest.json")
EXPECTED_SCHEMA = "rvmt.genesys2.clean_repro_bundle.v1"
EXPECTED_STATUS = "PASS_LOCAL_EXPORT_REPRODUCED"


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def repo_path(root: Path, value: Any) -> Path:
    path = Path(str(value))
    return path if path.is_absolute() else root / path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def require(errors: list[str], condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def check_summary(data: dict[str, Any], root: Path, *, require_export_root: bool = True) -> list[str]:
    errors: list[str] = []
    require(errors, data.get("schema") == EXPECTED_SCHEMA, "schema mismatch")
    require(errors, data.get("status") == EXPECTED_STATUS, f"status must be {EXPECTED_STATUS}")
    require(errors, data.get("canonical_evaluation_root") == "results/evaluation/genesys2-cva6/current", "canonical root mismatch")

    boundary = as_dict(data.get("claim_boundary"))
    require(errors, boundary.get("local_export_reproduced") is True, "local export reproduction boundary missing")
    require(errors, boundary.get("true_git_fresh_clone_claimed") is False, "must not claim true Git fresh clone")
    require(errors, boundary.get("external_release_asset_published") is False, "must not claim external raw archive publication")
    require(errors, boundary.get("requires_commit_tag_for_true_fresh_clone") is True, "commit/tag boundary missing")
    require(errors, boundary.get("board_or_vivado_rerun_performed") is False, "clean export must not claim board/Vivado rerun")
    require(errors, boundary.get("real_malware_validation_claimed") is False, "real malware validation must not be claimed")

    export = as_dict(data.get("export"))
    export_root_value = str(export.get("local_root") or "")
    require(errors, bool(export_root_value), "export.local_root missing")
    export_root = repo_path(root, export_root_value) if export_root_value else root
    if require_export_root:
        require(errors, export_root.is_dir(), f"export root missing: {export_root_value}")
        for required in [
            "pyproject.toml",
            "tools/reproduce_genesys2_current.py",
            "tools/check_genesys2_raw_artifact_release.py",
            "results/evaluation/genesys2-cva6/current/reproducibility_manifest.json",
            "results/evaluation/genesys2-cva6/current/raw_artifact_release_manifest.json",
        ]:
            require(errors, (export_root / required).is_file(), f"export missing required file: {required}")
    require(errors, int(export.get("file_count_excluding_uv_env") or 0) > 0, "export file count must be positive")
    require(errors, int(export.get("raw_archive_extracted_file_count") or 0) > 0, "raw archive extracted file count must be positive")
    require(errors, int(export.get("bitstream_artifact_file_count") or 0) >= 19, "bitstream artifact copy count is too small")
    require(errors, int(export.get("cva6_submodule_source_file_count") or 0) >= 2, "CVA6 submodule source copy count is too small")

    raw_archive = as_dict(data.get("raw_archive"))
    archive_value = str(raw_archive.get("local_archive") or "")
    require(errors, bool(archive_value), "raw archive local path missing")
    archive_path = repo_path(root, archive_value) if archive_value else root
    require(errors, raw_archive.get("copied_into_export") is True, "raw archive must be copied into export")
    if archive_value and archive_path.is_file():
        require(errors, raw_archive.get("sha256") == sha256_file(archive_path), "raw archive sha256 mismatch")
        require(errors, int(raw_archive.get("size_bytes") or -1) == archive_path.stat().st_size, "raw archive size mismatch")
    else:
        errors.append(f"raw archive missing: {archive_value}")
    extraction = as_dict(raw_archive.get("extraction"))
    require(errors, extraction.get("extracted") is True, "raw archive must be extracted into export")
    require(errors, int(extraction.get("file_count") or 0) == int(export.get("raw_archive_extracted_file_count") or -1), "raw extraction count mismatch")

    required = as_dict(data.get("required_local_artifacts"))
    require(errors, not as_list(required.get("missing")), "required local artifacts missing: " + ", ".join(str(item) for item in as_list(required.get("missing"))))

    commands = as_list(data.get("commands"))
    require(errors, bool(commands), "commands list missing")
    command_text = "\n".join(str(as_dict(row).get("command") or "") for row in commands)
    require(errors, "uv run rvmt repro:quick" in command_text, "quick clean-export command missing")
    require(errors, "uv run rvmt repro:local" in command_text, "local clean-export command missing")
    for row in commands:
        command = as_dict(row)
        require(errors, command.get("status") == "PASS", f"{command.get('command', '<unknown>')}: command did not PASS")
        if require_export_root:
            log_value = str(command.get("log") or "")
            require(errors, bool(log_value), f"{command.get('command', '<unknown>')}: log missing")
            if log_value:
                require(errors, (export_root / log_value).is_file(), f"{command.get('command', '<unknown>')}: log file missing: {log_value}")

    validation = " ".join(str(item) for item in as_list(data.get("validation_commands")))
    require(errors, "rvmt repro:clean-export" in validation, "rvmt clean-export validation command missing")
    require(errors, "tools/check_genesys2_clean_repro_bundle.py --root ." in validation, "clean-export checker validation command missing")
    non_claims = " ".join(str(item).lower() for item in as_list(data.get("non_claims")))
    require(errors, "not a committed/tagged git fresh clone" in non_claims, "non-claim must reject true fresh clone")
    require(errors, "not an external immutable release asset" in non_claims, "non-claim must reject external release")
    require(errors, "no vivado" in non_claims and "real-malware" in non_claims, "non-claim must reject host/real-malware runs")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        export_root = root / "build/clean_repro/fixture"
        for rel in [
            "pyproject.toml",
            "tools/reproduce_genesys2_current.py",
            "tools/check_genesys2_raw_artifact_release.py",
            "results/evaluation/genesys2-cva6/current/reproducibility_manifest.json",
            "results/evaluation/genesys2-cva6/current/raw_artifact_release_manifest.json",
            "build/clean_repro_logs/repro_quick.log",
            "build/clean_repro_logs/repro_local.log",
        ]:
            path = export_root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture\n", encoding="utf-8")
        archive = root / "build/ndss_artifacts/raw.zip"
        archive.parent.mkdir(parents=True, exist_ok=True)
        archive.write_text("archive\n", encoding="utf-8")
        summary = {
            "schema": EXPECTED_SCHEMA,
            "status": EXPECTED_STATUS,
            "canonical_evaluation_root": "results/evaluation/genesys2-cva6/current",
            "export": {
                "local_root": "build/clean_repro/fixture",
                "file_count_excluding_uv_env": 10,
                "raw_archive_extracted_file_count": 3,
                "bitstream_artifact_file_count": 20,
                "cva6_submodule_source_file_count": 2,
            },
            "raw_archive": {
                "local_archive": "build/ndss_artifacts/raw.zip",
                "copied_into_export": True,
                "sha256": sha256_file(archive),
                "size_bytes": archive.stat().st_size,
                "extraction": {"extracted": True, "file_count": 3},
            },
            "required_local_artifacts": {"missing": []},
            "commands": [
                {"command": "uv run rvmt repro:quick", "status": "PASS", "log": "build/clean_repro_logs/repro_quick.log"},
                {"command": "uv run rvmt repro:local", "status": "PASS", "log": "build/clean_repro_logs/repro_local.log"},
            ],
            "claim_boundary": {
                "local_export_reproduced": True,
                "true_git_fresh_clone_claimed": False,
                "external_release_asset_published": False,
                "requires_commit_tag_for_true_fresh_clone": True,
                "board_or_vivado_rerun_performed": False,
                "real_malware_validation_claimed": False,
            },
            "validation_commands": [
                "uv run rvmt repro:clean-export",
                "uv run python tools/check_genesys2_clean_repro_bundle.py --root .",
            ],
            "non_claims": [
                "This is not a committed/tagged Git fresh clone.",
                "The raw artifact ZIP is not an external immutable release asset.",
                "No Vivado, Genesys2/JTAG/UART, LaTeX, or real-malware experiment was run.",
            ],
        }
        errors = check_summary(summary, root)
        if errors:
            print("[FAIL] clean-export checker good fixture failed", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        summary["claim_boundary"]["true_git_fresh_clone_claimed"] = True
        errors = check_summary(summary, root)
        if not any("fresh clone" in error for error in errors):
            print("[FAIL] clean-export checker missed true fresh clone overclaim", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 clean-export reproduction checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check local clean-export Genesys2/CVA6 reproduction evidence.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--no-export-root", action="store_true", help="Validate only the portable manifest fields.")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    path = repo_path(root, args.summary)
    if not path.is_file():
        print(f"[FAIL] clean-export reproduction manifest missing: {path}", file=sys.stderr)
        return 1
    try:
        errors = check_summary(load_json(path), root, require_export_root=not args.no_export_root)
    except Exception as exc:
        print(f"[FAIL] clean-export reproduction checker error: {exc}", file=sys.stderr)
        return 2
    if errors:
        print("[FAIL] clean-export reproduction manifest is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] clean-export reproduction accepted: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
