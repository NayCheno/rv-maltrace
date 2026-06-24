from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path
from typing import Any


DEFAULT_MANIFEST = Path("build/bootrom/genesys2-cva6/build_manifest.json")
SCHEMA = "rvmt.genesys2.bootrom_build.v1"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def rel_or_abs(root: Path, value: str) -> Path:
    candidate = Path(value)
    return candidate if candidate.is_absolute() else root / candidate


def require_artifact(root: Path, row: dict[str, Any], errors: list[str], label: str) -> Path | None:
    path_value = row.get("path")
    if not isinstance(path_value, str) or not path_value:
        errors.append(f"{label}: missing path")
        return None
    path = rel_or_abs(root, path_value)
    if not path.is_file():
        errors.append(f"{label}: missing file {path_value}")
        return path
    expected_sha = row.get("sha256")
    if not isinstance(expected_sha, str) or len(expected_sha) != 64:
        errors.append(f"{label}: missing or invalid sha256")
    else:
        actual_sha = sha256_file(path)
        if actual_sha != expected_sha:
            errors.append(f"{label}: sha256 mismatch for {path_value}: expected {expected_sha}, got {actual_sha}")
    expected_size = row.get("size_bytes")
    if not isinstance(expected_size, int) or expected_size <= 0:
        errors.append(f"{label}: missing or invalid size_bytes")
    elif path.is_file() and path.stat().st_size != expected_size:
        errors.append(f"{label}: size mismatch for {path_value}: expected {expected_size}, got {path.stat().st_size}")
    return path


def check_manifest(root: Path, manifest_path: Path) -> list[str]:
    errors: list[str] = []
    manifest = load_json(manifest_path)
    if manifest.get("schema") != SCHEMA:
        errors.append(f"schema must be {SCHEMA}")
    if manifest.get("status") != "PASS":
        errors.append("manifest status must be PASS for the build artifact, not for board cycle-source availability")
    if manifest.get("board") != "genesys2":
        errors.append("board must be genesys2")
    if manifest.get("xlen") != 64:
        errors.append("xlen must be 64")
    if manifest.get("platform") != "PLAT_XILINX":
        errors.append("platform must be PLAT_XILINX")

    source = require_artifact(root, manifest.get("source", {}), errors, "source")
    generated_sv = require_artifact(root, manifest.get("generated_sv", {}), errors, "generated_sv")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        errors.append("artifacts must be an object")
        artifacts = {}
    disasm = require_artifact(root, artifacts.get("disassembly", {}), errors, "disassembly")
    rodata = require_artifact(root, artifacts.get("rodata", {}), errors, "rodata")
    require_artifact(root, artifacts.get("elf", {}), errors, "elf")
    require_artifact(root, artifacts.get("bin", {}), errors, "bin")
    require_artifact(root, artifacts.get("img", {}), errors, "img")

    attempt = manifest.get("counter_delegation_attempt")
    if not isinstance(attempt, dict):
        errors.append("counter_delegation_attempt must be present")
        attempt = {}
    if attempt.get("counteren_value_hex") != "0x7":
        errors.append("counteren_value_hex must be 0x7")
    for key in ("writes_mcounteren", "writes_scounteren", "clears_mcountinhibit"):
        if attempt.get(key) is not True:
            errors.append(f"counter_delegation_attempt.{key} must be true")
    boundary = attempt.get("claim_boundary")
    if not isinstance(boundary, str) or "must still prove user rdcycle or kernel perf cycles" not in boundary:
        errors.append("counter_delegation_attempt.claim_boundary must preserve the board PASS boundary")

    if source and source.is_file():
        source_text = source.read_text(encoding="utf-8", errors="replace")
        required_source = [
            "RVMT_COUNTEREN_CY_TM_IR ((uintptr_t)0x7)",
            "csrw mcounteren",
            "csrw scounteren",
            "csrw mcountinhibit",
            "RVMT counter delegation: mcounteren/scounteren CY TM IR enabled",
        ]
        for needle in required_source:
            if needle not in source_text:
                errors.append(f"source is missing {needle!r}")
    if generated_sv and generated_sv.is_file() and generated_sv.stat().st_size < 1024:
        errors.append("generated bootrom SV is unexpectedly small")
    if disasm and disasm.is_file():
        disasm_text = disasm.read_text(encoding="utf-8", errors="replace")
        for needle in ("csrw\tmcounteren", "csrw\tscounteren", "csrw\tmcountinhibit"):
            if needle not in disasm_text:
                errors.append(f"disassembly is missing {needle!r}")
    if rodata and rodata.is_file():
        rodata_text = rodata.read_text(encoding="utf-8", errors="replace")
        for needle in ("RVMT counter del", "ren/scounteren C"):
            if needle not in rodata_text:
                errors.append(f"rodata dump is missing UART marker fragment {needle!r}")
    return errors


def run_self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        source = root / "rtl/cva6/corev_apu/fpga/src/bootrom/src/main.c"
        source.parent.mkdir(parents=True)
        source.write_text(
            "\n".join(
                [
                    "#define RVMT_COUNTEREN_CY_TM_IR ((uintptr_t)0x7)",
                    '__asm__ volatile ("csrw mcounteren, %0" :: "r" (counters));',
                    '__asm__ volatile ("csrw scounteren, %0" :: "r" (counters));',
                    '__asm__ volatile ("csrw mcountinhibit, zero");',
                    'print_uart("RVMT counter delegation: mcounteren/scounteren CY TM IR enabled\\r\\n");',
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        sv = root / "rtl/cva6/corev_apu/fpga/src/bootrom/bootrom_64.sv"
        sv.parent.mkdir(parents=True, exist_ok=True)
        sv.write_text("module bootrom_64;\n" + ("// data\n" * 200) + "endmodule\n", encoding="utf-8")
        out = root / "build/bootrom/genesys2-cva6"
        out.mkdir(parents=True)
        elf = out / "bootrom_64.elf"
        bin_file = out / "bootrom_64.bin"
        img = out / "bootrom_64.img"
        disasm = out / "bootrom_64.disasm.txt"
        rodata = out / "bootrom_64.rodata.txt"
        elf.write_bytes(b"elf")
        bin_file.write_bytes(b"bin")
        img.write_bytes(b"img")
        disasm.write_text("csrw\tmcounteren,a5\ncsrw\tscounteren,a5\ncsrw\tmcountinhibit,zero\n", encoding="utf-8")
        rodata.write_text("RVMT counter del\nren/scounteren C\n", encoding="utf-8")

        def row(path: Path) -> dict[str, Any]:
            return {
                "path": path.relative_to(root).as_posix(),
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
            }

        manifest = {
            "schema": SCHEMA,
            "status": "PASS",
            "board": "genesys2",
            "xlen": 64,
            "platform": "PLAT_XILINX",
            "source": row(source),
            "generated_sv": row(sv),
            "artifacts": {
                "elf": row(elf),
                "bin": row(bin_file),
                "img": row(img),
                "disassembly": row(disasm),
                "rodata": row(rodata),
            },
            "counter_delegation_attempt": {
                "csr_bits": "CY_TM_IR",
                "counteren_value_hex": "0x7",
                "writes_mcounteren": True,
                "writes_scounteren": True,
                "clears_mcountinhibit": True,
                "claim_boundary": "Firmware attempts to delegate cycle/time/instret before jumping to the SD-card payload; board Linux must still prove user rdcycle or kernel perf cycles before any cycle-source PASS.",
            },
        }
        manifest_path = out / "build_manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        errors = check_manifest(root, manifest_path)
        if errors:
            print("[FAIL] valid fixture rejected")
            for error in errors:
                print(f"- {error}")
            return 1
        manifest["counter_delegation_attempt"]["claim_boundary"] = "unsafe overclaim"
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        errors = check_manifest(root, manifest_path)
        if not errors:
            print("[FAIL] invalid fixture accepted")
            return 1
    print("[PASS] Genesys2 bootrom counter-delegation checker self-test")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Check Genesys2/CVA6 bootrom counter-delegation build artifacts.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return run_self_test()
    root = args.root.resolve()
    manifest = args.manifest if args.manifest.is_absolute() else root / args.manifest
    if not manifest.is_file():
        print(f"[FAIL] missing bootrom build manifest: {manifest}")
        return 1
    errors = check_manifest(root, manifest)
    if errors:
        print(f"[FAIL] bootrom counter-delegation artifact rejected: {manifest}")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] bootrom counter-delegation artifact accepted: {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
