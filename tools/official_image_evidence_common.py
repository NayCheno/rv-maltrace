from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CURRENT_ROOT = Path("results/evaluation/genesys2-cva6/current")
DEFAULT_BUILD_MANIFEST = Path("build/board/genesys2_official_image_probe/build_manifest.json")
DEFAULT_BITSTREAM = Path("build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker-syscall/work-fpga/ariane_xilinx.bit")
DEFAULT_LTX = Path("build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker-syscall/work-fpga/ariane_xilinx.ltx")
DEFAULT_TARGET = "/tmp/rvmt_official/official_image_probe"


def repo_rel(path: Path, root: Path = ROOT) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def repo_path(root: Path, value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else root / path


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip():
            value = json.loads(line)
            if isinstance(value, dict):
                rows.append(value)
    return rows


def sha256_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_row(path: Path) -> dict[str, Any]:
    return {
        "path": repo_rel(path),
        "exists": path.is_file(),
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size if path.is_file() else None,
    }


def int_value(value: Any) -> int | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text, 10)
    except ValueError:
        return None


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def static_binary_from_manifest(path: Path = DEFAULT_BUILD_MANIFEST) -> Path:
    row = load_json(path).get("variants", {}).get("static_exec", {})
    binary = Path(str(row.get("binary") or ""))
    if not binary.is_file():
        raise FileNotFoundError(f"static_exec binary missing in {path}: {binary}")
    return binary


def variant_row(manifest: Path, variant: str) -> dict[str, Any]:
    row = load_json(manifest).get("variants", {}).get(variant, {})
    return row if isinstance(row, dict) else {}


def extract_sections(text: str, *, begin: str = "RVMT_PROC_SECTION_BEGIN", end: str = "RVMT_PROC_SECTION_END") -> dict[str, str]:
    sections: dict[str, list[str]] = {}
    current: str | None = None
    current_lines: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith(begin):
            parts = line.split()
            if len(parts) >= 2:
                current = parts[1]
                current_lines = []
            continue
        if current is not None and line.startswith(end):
            parts = line.split()
            if len(parts) >= 2 and parts[1] == current:
                sections[current] = current_lines
                current = None
                current_lines = []
            continue
        if current is not None:
            current_lines.append(raw.rstrip("\r"))
    return {key: "\n".join(lines).strip() + ("\n" if lines else "") for key, lines in sections.items()}


def write_section_files(run_root: Path, section_dir: Path, sections: dict[str, str]) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    section_dir.mkdir(parents=True, exist_ok=True)
    for name, text in sorted(sections.items()):
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", name)
        path = section_dir / f"{safe}.txt"
        path.write_text(text, encoding="utf-8", newline="\n")
        rows[name] = file_row(path)
    return rows


def parse_maps(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        match = re.match(r"^([0-9a-fA-F]+)-([0-9a-fA-F]+)\s+(\S+)\s+(\S+)\s+\S+\s+\S+\s*(.*)$", line.strip())
        if not match:
            continue
        start = int(match.group(1), 16)
        end = int(match.group(2), 16)
        rows.append(
            {
                "start": start,
                "end": end,
                "start_hex": f"0x{start:016x}",
                "end_hex": f"0x{end:016x}",
                "perms": match.group(3),
                "offset": match.group(4),
                "path": match.group(5).strip(),
                "raw": line.strip(),
            }
        )
    return rows


def pc_attributions(records: list[dict[str, Any]], maps: list[dict[str, Any]], *, limit: int = 256) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in records:
        pc = int_value(record.get("pc"))
        if pc is None or pc == 0:
            continue
        for mapping in maps:
            if int(mapping["start"]) <= pc < int(mapping["end"]):
                rows.append(
                    {
                        "sequence_number": record.get("sequence_number"),
                        "evt": record.get("evt"),
                        "pc": f"0x{pc:016x}",
                        "mapping_start": mapping["start_hex"],
                        "mapping_end": mapping["end_hex"],
                        "mapping_perms": mapping["perms"],
                        "mapping_path": mapping["path"],
                        "provenance": "hardware_pc_joined_to_runtime_proc_maps",
                    }
                )
                break
        if len(rows) >= limit:
            break
    return rows


def bram_ring(summary: dict[str, Any]) -> dict[str, int]:
    ring = summary.get("bram_ring") if isinstance(summary.get("bram_ring"), dict) else {}
    return {
        "event_count": int(ring.get("event_count") or 0),
        "captured_count": int(ring.get("captured_count") or 0),
        "dropped_count": int(ring.get("dropped_count") or 0),
        "wrap_count": int(ring.get("wrap_count") or 0),
    }


def sequence_gap_count(records: list[dict[str, Any]]) -> int:
    values = [int(row["sequence_number"]) for row in records if row.get("sequence_number") is not None]
    return sum(1 for left, right in zip(values, values[1:]) if right != left + 1)


def parse_sha256_line(text: str) -> str | None:
    match = re.search(r"\b([0-9a-fA-F]{64})\b", text)
    return match.group(1).lower() if match else None


def parse_pid_kv(text: str, prefix: str) -> dict[str, int | None]:
    result: dict[str, int | None] = {}
    for line in text.splitlines():
        stripped = line.strip()
        offset = stripped.find(prefix)
        if offset < 0:
            continue
        for key, value in re.findall(r"([A-Za-z_]+)=(-?\d+)", stripped[offset:]):
            result[key] = int(value)
    return result
