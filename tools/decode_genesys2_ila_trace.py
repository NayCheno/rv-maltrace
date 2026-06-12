from __future__ import annotations

import argparse
import csv
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


EVENT_NAMES = {
    0: "NONE",
    1: "RETIRE",
    2: "BRANCH",
    3: "JUMP",
    4: "SYSCALL_ENTRY",
    5: "SYSCALL_RET",
    6: "TRAP",
    7: "CSR",
    8: "SATP",
    9: "PRIV",
    10: "ARG_MEM",
    11: "DROP",
    12: "MARKER",
}

PRIV_NAMES = {
    0: "U",
    1: "S",
    2: "H",
    3: "M",
}

SATP_MODE_NAMES = {
    0: "Bare",
    8: "Sv39",
    9: "Sv48",
    10: "Sv57",
}

WIDE_PROBES = {
    "fire": ("probe0", "rvmt_trace_fire"),
    "evt": ("probe1", "rvmt_trace_probe_evt"),
    "cycle": ("probe2", "rvmt_trace_probe_cycle"),
    "pc": ("probe3", "rvmt_trace_probe_pc"),
    "instr": ("probe4", "rvmt_trace_probe_instr"),
    "target": ("probe5", "rvmt_trace_probe_target"),
    "taken": ("probe6", "rvmt_trace_probe_taken"),
    "priv": ("probe7", "rvmt_trace_probe_priv"),
    "priv_transition": ("probe8", "rvmt_trace_probe_priv_transition"),
    "satp": ("probe9", "rvmt_trace_probe_satp"),
    "csr": ("probe10", "rvmt_trace_probe_csr"),
    "value": ("probe11", "rvmt_trace_probe_value"),
    "cause": ("probe12", "rvmt_trace_probe_cause"),
    "tval": ("probe13", "rvmt_trace_probe_tval"),
    "a0": ("probe14", "rvmt_trace_probe_a0"),
    "a1": ("probe15", "rvmt_trace_probe_a1"),
    "a2": ("probe16", "rvmt_trace_probe_a2"),
    "a7": ("probe17", "rvmt_trace_probe_a7"),
    "syscall_id": ("probe18", "rvmt_trace_probe_syscall_id"),
    "duration": ("probe19", "rvmt_trace_probe_duration"),
}

PACKED_PROBES = {
    "fire": ("probe0", "rvmt_trace_fire"),
    "payload": ("probe1", "rvmt_trace_probe_payload"),
}


def normalize_header(value: str) -> str:
    out = value.strip().strip('"').lower()
    for token in (" ", "\t", "[", "]", "(", ")", "{", "}"):
        out = out.replace(token, "")
    return out


def find_column(headers: list[str], aliases: tuple[str, ...], normalized: dict[str, str]) -> str | None:
    for alias in aliases:
        key = normalize_header(alias)
        if key in normalized:
            return normalized[key]
    for header in headers:
        key = normalize_header(header)
        if any(key.endswith(normalize_header(alias)) or normalize_header(alias) in key for alias in aliases):
            return header
    return None


def find_probe_columns(headers: list[str], probes: dict[str, tuple[str, ...]]) -> dict[str, str]:
    normalized = {normalize_header(header): header for header in headers}
    found: dict[str, str] = {}
    for field, aliases in probes.items():
        column = find_column(headers, aliases, normalized)
        if column is not None:
            found[field] = column
    return found


def find_columns(headers: list[str]) -> tuple[str, dict[str, str]]:
    wide = find_probe_columns(headers, WIDE_PROBES)
    if set(wide) == set(WIDE_PROBES):
        return "wide", wide

    packed = find_probe_columns(headers, PACKED_PROBES)
    if set(packed) == set(PACKED_PROBES):
        return "packed", packed

    missing_wide = sorted(set(WIDE_PROBES) - set(wide))
    missing_packed = sorted(set(PACKED_PROBES) - set(packed))
    raise ValueError(
        "missing required ILA probe columns: "
        f"wide format missing {', '.join(missing_wide)}; "
        f"packed format missing {', '.join(missing_packed)}"
    )


def parse_int(value: Any, *, unprefixed_radix: str) -> int:
    text = str(value).strip().strip('"').strip("'").replace("_", "")
    if not text:
        return 0
    lower = text.lower()
    if set(lower) <= {"x", "z", "u"}:
        return 0
    if lower.startswith("0x"):
        return int(lower, 16)
    if "'h" in lower:
        return int(lower.split("'h", 1)[1], 16)
    if "'b" in lower:
        return int(lower.split("'b", 1)[1], 2)
    if lower.startswith("h") and len(lower) > 1:
        return int(lower[1:], 16)
    if lower.startswith("b") and len(lower) > 1:
        return int(lower[1:], 2)
    return int(lower, 16 if unprefixed_radix == "hex" else 2)


def hex_width(value: int, width: int) -> str:
    digits = max(1, (width + 3) // 4)
    return f"0x{value & ((1 << width) - 1):0{digits}x}"


def priv_name(value: int) -> str:
    return PRIV_NAMES.get(value & 0x3, f"UNKNOWN_{value & 0x3}")


def annotate_satp(event: dict[str, Any], satp: int) -> None:
    event["satp"] = hex_width(satp, 64)
    event["satp_mode"] = (satp >> 60) & 0xF
    event["satp_mode_name"] = SATP_MODE_NAMES.get(event["satp_mode"], f"MODE_{event['satp_mode']}")
    event["satp_asid"] = hex_width((satp >> 44) & 0xFFFF, 16)
    event["satp_ppn"] = hex_width(satp & ((1 << 44) - 1), 44)


def row_value(row: dict[str, str], columns: dict[str, str], field: str, radix: str) -> int:
    return parse_int(row.get(columns[field], ""), unprefixed_radix=radix)


def decode_rows(rows: list[dict[str, str]], columns: dict[str, str], radix: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for row_index, row in enumerate(rows):
        if row_value(row, columns, "fire", radix) == 0:
            continue
        evt_code = row_value(row, columns, "evt", radix)
        evt = EVENT_NAMES.get(evt_code, "UNKNOWN")
        if evt == "NONE":
            continue

        priv_transition = row_value(row, columns, "priv_transition", radix)
        event: dict[str, Any] = {
            "record_index": len(events),
            "ila_row_index": row_index,
            "cycle": row_value(row, columns, "cycle", radix),
            "evt": evt,
            "evt_code": evt_code,
            "pc": hex_width(row_value(row, columns, "pc", radix), 64),
            "instr": hex_width(row_value(row, columns, "instr", radix), 32),
            "priv": priv_name(row_value(row, columns, "priv", radix)),
        }
        annotate_satp(event, row_value(row, columns, "satp", radix))

        target = row_value(row, columns, "target", radix)
        if target or evt in {"BRANCH", "JUMP", "SYSCALL_RET"}:
            event["target"] = hex_width(target, 64)

        if evt == "BRANCH":
            event["taken"] = bool(row_value(row, columns, "taken", radix))

        if evt in {"SYSCALL_ENTRY", "SYSCALL_RET"}:
            event["syscall_id"] = hex_width(row_value(row, columns, "syscall_id", radix), 64)
            event["a0"] = hex_width(row_value(row, columns, "a0", radix), 64)
            event["a1"] = hex_width(row_value(row, columns, "a1", radix), 64)
            event["a2"] = hex_width(row_value(row, columns, "a2", radix), 64)
            event["a7"] = hex_width(row_value(row, columns, "a7", radix), 64)
            if evt == "SYSCALL_RET":
                event["duration"] = row_value(row, columns, "duration", radix)

        if evt == "TRAP":
            event["cause"] = hex_width(row_value(row, columns, "cause", radix), 64)
            event["tval"] = hex_width(row_value(row, columns, "tval", radix), 64)

        if evt in {"CSR", "SATP", "DROP", "MARKER"}:
            event["value"] = hex_width(row_value(row, columns, "value", radix), 64)

        if evt in {"CSR", "SATP"}:
            event["csr"] = hex_width(row_value(row, columns, "csr", radix), 12)

        if evt == "PRIV":
            event["old_priv"] = priv_name(priv_transition >> 2)
            event["new_priv"] = priv_name(priv_transition)
            event["value"] = hex_width(row_value(row, columns, "value", radix), 64)

        events.append(event)
    return events


def decode_rows_packed(rows: list[dict[str, str]], columns: dict[str, str], radix: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for row_index, row in enumerate(rows):
        if row_value(row, columns, "fire", radix) == 0:
            continue

        payload = row_value(row, columns, "payload", radix)
        evt_code = payload & 0xF
        evt = EVENT_NAMES.get(evt_code, "UNKNOWN")
        if evt == "NONE":
            continue

        cycle = (payload >> 4) & 0xFFFFFFFF
        pc = (payload >> 36) & 0xFFFFFFFF
        primary = (payload >> 68) & 0xFFFFFFFF
        aux = (payload >> 104) & 0xFFFFFFFF

        event: dict[str, Any] = {
            "record_index": len(events),
            "ila_row_index": row_index,
            "cycle": cycle,
            "evt": evt,
            "evt_code": evt_code,
            "pc": hex_width(pc, 32),
            "packed_primary": hex_width(primary, 32),
            "packed_aux": hex_width(aux, 32),
        }

        if evt in {"BRANCH", "JUMP"}:
            event["target"] = hex_width(primary, 32)

        if evt == "SYSCALL_ENTRY":
            event["syscall_id"] = hex_width(aux, 64)
            event["a7"] = hex_width(primary, 64)

        if evt == "SYSCALL_RET":
            event["syscall_id"] = hex_width(primary, 64)

        if evt == "TRAP":
            event["cause"] = hex_width(primary, 64)

        if evt == "CSR":
            event["csr"] = hex_width(primary, 12)

        if evt == "SATP":
            event["satp"] = hex_width(primary, 64)
            event["value"] = event["satp"]
            event["satp_primary_width_bits"] = 32
            event["satp_asid_source"] = "unavailable_packed_32bit_primary"

        if evt == "PRIV":
            event["old_priv"] = priv_name(primary & 0x3)

        if evt == "ARG_MEM":
            event["mem_addr"] = hex_width(primary, 64)
            event["mem_data"] = hex_width(aux, 64)
            event["snapshot_bytes"] = 4
            event["snapshot_source"] = "hardware_compact_trace"
            event["payload_width_note"] = "packed ILA records expose 32-bit address/data prefixes for ARG_MEM"

        if evt in {"DROP", "MARKER"}:
            event["value"] = hex_width(primary, 64)

        events.append(event)
    return events


def decode_csv(path: Path, *, unprefixed_radix: str) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(line for line in handle if line.strip())
        if reader.fieldnames is None:
            raise ValueError(f"{path}: missing CSV header")
        mode, columns = find_columns(reader.fieldnames)
        rows = [
            row
            for row in reader
            if not any(str(value).strip().lower().startswith("radix") for value in row.values())
        ]
        if mode == "packed":
            return decode_rows_packed(rows, columns, unprefixed_radix)
        return decode_rows(rows, columns, unprefixed_radix)


def write_jsonl(events: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in events), encoding="utf-8", newline="\n")


def run_self_test() -> int:
    headers = [f"probe{i}" for i in range(20)]
    rows = [
        ["1", "4", "10", "0000000080001000", "00000073", "0", "0", "0", "1", "8001200000012345", "0", "0", "0", "0", "1", "2000", "12", "40", "0", "0"],
        ["1", "5", "18", "0000000080001004", "10200073", "0000000080001008", "0", "1", "5", "0", "0", "11", "0", "0", "11", "0", "0", "40", "0", "8"],
        ["1", "6", "20", "0000000080002000", "ffffffff", "0", "0", "0", "0", "0", "0", "0", "2", "ffffffff", "0", "0", "0", "0", "0", "0"],
        ["0", "0", "21", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
    ]
    with tempfile.TemporaryDirectory() as tmp:
        csv_path = Path(tmp) / "ila.csv"
        out_path = Path(tmp) / "trace.jsonl"
        with csv_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(headers)
            writer.writerows(rows)
        events = decode_csv(csv_path, unprefixed_radix="hex")
        write_jsonl(events, out_path)
        loaded = [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines()]
    if len(loaded) != 3:
        print("[FAIL] expected 3 decoded events", file=sys.stderr)
        return 1
    if loaded[0].get("evt") != "SYSCALL_ENTRY" or loaded[0].get("a7") != "0x0000000000000040":
        print("[FAIL] syscall entry decode mismatch", file=sys.stderr)
        return 1
    if loaded[0].get("satp_asid") != "0x0012" or loaded[0].get("satp_mode_name") != "Sv39":
        print("[FAIL] SATP ASID decode mismatch", file=sys.stderr)
        return 1
    if loaded[1].get("evt") != "SYSCALL_RET" or loaded[1].get("duration") != 8:
        print("[FAIL] syscall return decode mismatch", file=sys.stderr)
        return 1
    if loaded[2].get("evt") != "TRAP" or loaded[2].get("cause") != "0x0000000000000002":
        print("[FAIL] trap decode mismatch", file=sys.stderr)
        return 1
    packed_payloads = [
        (4 | (10 << 4) | (0x80001000 << 36) | (64 << 68) | (7 << 104)),
        (5 | (18 << 4) | (0x80001004 << 36) | (0 << 68)),
        (6 | (20 << 4) | (0x80002000 << 36) | (2 << 68)),
        (8 | (24 << 4) | (0x80002004 << 36) | (0x12345678 << 68)),
        (10 | (28 << 4) | (0x80002008 << 36) | (0x80003000 << 68) | (0x706d742f << 104)),
    ]
    with tempfile.TemporaryDirectory() as tmp:
        csv_path = Path(tmp) / "packed_ila.csv"
        with csv_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["probe0", "probe1"])
            writer.writerows([["1", f"{payload:x}"] for payload in packed_payloads])
        packed = decode_csv(csv_path, unprefixed_radix="hex")
    if len(packed) != 5:
        print("[FAIL] expected 5 packed decoded events", file=sys.stderr)
        return 1
    if (
        packed[0].get("evt") != "SYSCALL_ENTRY"
        or packed[0].get("a7") != "0x0000000000000040"
        or packed[0].get("syscall_id") != "0x0000000000000007"
    ):
        print("[FAIL] packed syscall entry decode mismatch", file=sys.stderr)
        return 1
    if packed[1].get("evt") != "SYSCALL_RET" or packed[1].get("syscall_id") != "0x0000000000000000":
        print("[FAIL] packed syscall return decode mismatch", file=sys.stderr)
        return 1
    if packed[2].get("evt") != "TRAP" or packed[2].get("cause") != "0x0000000000000002":
        print("[FAIL] packed trap decode mismatch", file=sys.stderr)
        return 1
    if (
        packed[3].get("evt") != "SATP"
        or packed[3].get("satp") != "0x0000000012345678"
        or packed[3].get("satp_asid_source") != "unavailable_packed_32bit_primary"
    ):
        print("[FAIL] packed SATP boundary decode mismatch", file=sys.stderr)
        return 1
    if (
        packed[4].get("evt") != "ARG_MEM"
        or packed[4].get("mem_addr") != "0x0000000080003000"
        or packed[4].get("mem_data") != "0x00000000706d742f"
        or packed[4].get("snapshot_source") != "hardware_compact_trace"
    ):
        print("[FAIL] packed ARG_MEM decode mismatch", file=sys.stderr)
        return 1
    print("[PASS] Genesys2 ILA trace decoder self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Decode Genesys2 CVA6 RV-MalTrace ILA CSV capture into trace.jsonl.")
    parser.add_argument("--csv", type=Path, help="Vivado ILA CSV exported from the rvmt trace probes.")
    parser.add_argument("--out", type=Path, help="Output JSONL trace path.")
    parser.add_argument(
        "--unprefixed-radix",
        choices=("hex", "binary"),
        default="hex",
        help="Radix for ILA values that have no 0x/h/b prefix. Vivado CSV is usually hex for these probes.",
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return run_self_test()
    if not args.csv or not args.out:
        parser.error("--csv and --out are required unless --self-test is used")

    try:
        events = decode_csv(args.csv, unprefixed_radix=args.unprefixed_radix)
        write_jsonl(events, args.out)
    except Exception as exc:
        print(f"decode_genesys2_ila_trace: error: {exc}", file=sys.stderr)
        return 2

    print(f"[PASS] wrote {len(events)} events to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
