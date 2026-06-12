from __future__ import annotations

import argparse
import csv
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from decode_genesys2_ila_trace import EVENT_NAMES, find_column, hex_width, normalize_header


BRAM_PAYLOAD_WIDTH = 484
BRAM_RING_ADDR_WIDTH = 10
BRAM_RING_DEPTH = 1 << BRAM_RING_ADDR_WIDTH
BRAM_PAYLOAD_ALIASES = (
    "rvmt_trace_bram_probe_payload",
    "rvmt_trace_bram_probe_payload[483:0]",
    "probe2[483:0]",
)
SEGMENTED_FIELD_ALIASES = {
    "evt_code": ("rvmt_trace_bram_dump_evt", "rvmt_trace_bram_dump_evt[3:0]", "probe2[3:0]"),
    "cycle": ("rvmt_trace_bram_dump_cycle", "rvmt_trace_bram_dump_cycle[31:0]", "probe2[35:4]"),
    "pc": ("rvmt_trace_bram_dump_pc", "rvmt_trace_bram_dump_pc[31:0]", "probe2[67:36]"),
    "primary": ("rvmt_trace_bram_dump_primary", "rvmt_trace_bram_dump_primary[31:0]", "probe2[99:68]"),
    "aux": ("rvmt_trace_bram_dump_aux", "rvmt_trace_bram_dump_aux[31:0]", "probe2[131:100]"),
    "sequence": ("rvmt_trace_bram_dump_sequence", "rvmt_trace_bram_dump_sequence[31:0]", "probe2[163:132]"),
    "dump_valid": ("rvmt_trace_bram_dump_valid", "probe2[164]"),
    "full": ("rvmt_trace_bram_full", "probe2[165]"),
    "dump_index": ("rvmt_trace_bram_dump_index", "rvmt_trace_bram_dump_index[9:0]", "probe2[175:166]"),
    "write_index": ("rvmt_trace_bram_write_index", "rvmt_trace_bram_write_index[9:0]", "probe2[185:176]"),
    "oldest_index": ("rvmt_trace_bram_oldest_index", "rvmt_trace_bram_oldest_index[9:0]", "probe2[195:186]"),
    "next_sequence": ("rvmt_trace_bram_next_sequence", "rvmt_trace_bram_next_sequence[31:0]", "probe2[227:196]"),
    "wrap_count": ("rvmt_trace_bram_wrap_count", "rvmt_trace_bram_wrap_count[63:0]", "probe2[291:228]"),
    "dropped_count": ("rvmt_trace_bram_dropped_count", "rvmt_trace_bram_dropped_count[63:0]", "probe2[355:292]"),
    "captured_count": ("rvmt_trace_bram_captured_count", "rvmt_trace_bram_captured_count[63:0]", "probe2[419:356]"),
    "event_count": ("rvmt_trace_bram_event_count", "rvmt_trace_bram_event_count[63:0]", "probe2[483:420]"),
}


def read_rows(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(line for line in handle if line.strip())
        if reader.fieldnames is None:
            raise ValueError(f"{path}: missing CSV header")
        rows = [
            row
            for row in reader
            if not any(str(value).strip().lower().startswith("radix") for value in row.values())
        ]
        return reader.fieldnames, rows


def parse_bram_int(value: Any, *, unprefixed_radix: str) -> int:
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
    if lower.startswith("b") and len(lower) > 1 and unprefixed_radix == "binary":
        return int(lower[1:], 2)
    return int(lower, 16 if unprefixed_radix == "hex" else 2)


def find_bram_payload_column(headers: list[str]) -> str | None:
    normalized = {normalize_header(header): header for header in headers}
    column = find_column(headers, BRAM_PAYLOAD_ALIASES, normalized)
    return column


def find_segmented_columns(headers: list[str]) -> dict[str, str]:
    normalized = {normalize_header(header): header for header in headers}
    found: dict[str, str] = {}
    for field, aliases in SEGMENTED_FIELD_ALIASES.items():
        column = find_column(headers, aliases, normalized)
        if column is not None:
            found[field] = column
    return found


def unpack_bram_payload(payload: int, *, row_index: int) -> dict[str, Any]:
    evt_code = payload & 0xF
    cycle = (payload >> 4) & 0xFFFFFFFF
    pc = (payload >> 36) & 0xFFFFFFFF
    primary = (payload >> 68) & 0xFFFFFFFF
    aux = (payload >> 100) & 0xFFFFFFFF
    sequence = (payload >> 132) & 0xFFFFFFFF
    dump_valid = (payload >> 164) & 0x1
    full = (payload >> 165) & 0x1
    dump_index = (payload >> 166) & 0x3FF
    write_index = (payload >> 176) & 0x3FF
    oldest_index = (payload >> 186) & 0x3FF
    next_sequence = (payload >> 196) & 0xFFFFFFFF
    wrap_count = (payload >> 228) & 0xFFFFFFFFFFFFFFFF
    dropped_count = (payload >> 292) & 0xFFFFFFFFFFFFFFFF
    captured_count = (payload >> 356) & 0xFFFFFFFFFFFFFFFF
    event_count = (payload >> 420) & 0xFFFFFFFFFFFFFFFF
    high_bits = payload >> BRAM_PAYLOAD_WIDTH
    return annotate_compact_arg_mem({
        "ila_row_index": row_index,
        "dump_valid": bool(dump_valid),
        "dump_index": dump_index,
        "sequence_number": sequence,
        "cycle": cycle,
        "evt": EVENT_NAMES.get(evt_code, "UNKNOWN"),
        "evt_code": evt_code,
        "pc": hex_width(pc, 32),
        "packed_primary": hex_width(primary, 32),
        "packed_aux": hex_width(aux, 32),
        "full": bool(full),
        "write_index": write_index,
        "oldest_index": oldest_index,
        "next_sequence": next_sequence,
        "event_count": event_count,
        "captured_count": captured_count,
        "dropped_count": dropped_count,
        "wrap_count": wrap_count,
        "payload_high_bits": high_bits,
    })


def unpack_segmented_row(row: dict[str, str], columns: dict[str, str], *, row_index: int, radix: str) -> dict[str, Any]:
    evt_code = parse_bram_int(row.get(columns["evt_code"], ""), unprefixed_radix=radix) & 0xF
    cycle = parse_bram_int(row.get(columns["cycle"], ""), unprefixed_radix=radix) & 0xFFFFFFFF
    pc = parse_bram_int(row.get(columns["pc"], ""), unprefixed_radix=radix) & 0xFFFFFFFF
    primary = parse_bram_int(row.get(columns["primary"], ""), unprefixed_radix=radix) & 0xFFFFFFFF
    aux = parse_bram_int(row.get(columns["aux"], ""), unprefixed_radix=radix) & 0xFFFFFFFF
    sequence = parse_bram_int(row.get(columns["sequence"], ""), unprefixed_radix=radix) & 0xFFFFFFFF
    return annotate_compact_arg_mem({
        "ila_row_index": row_index,
        "dump_valid": bool(parse_bram_int(row.get(columns["dump_valid"], ""), unprefixed_radix=radix) & 0x1),
        "dump_index": parse_bram_int(row.get(columns["dump_index"], ""), unprefixed_radix=radix) & 0x3FF,
        "sequence_number": sequence,
        "cycle": cycle,
        "evt": EVENT_NAMES.get(evt_code, "UNKNOWN"),
        "evt_code": evt_code,
        "pc": hex_width(pc, 32),
        "packed_primary": hex_width(primary, 32),
        "packed_aux": hex_width(aux, 32),
        "full": bool(parse_bram_int(row.get(columns["full"], ""), unprefixed_radix=radix) & 0x1),
        "write_index": parse_bram_int(row.get(columns["write_index"], ""), unprefixed_radix=radix) & 0x3FF,
        "oldest_index": parse_bram_int(row.get(columns["oldest_index"], ""), unprefixed_radix=radix) & 0x3FF,
        "next_sequence": parse_bram_int(row.get(columns["next_sequence"], ""), unprefixed_radix=radix) & 0xFFFFFFFF,
        "event_count": parse_bram_int(row.get(columns["event_count"], ""), unprefixed_radix=radix) & 0xFFFFFFFFFFFFFFFF,
        "captured_count": parse_bram_int(row.get(columns["captured_count"], ""), unprefixed_radix=radix) & 0xFFFFFFFFFFFFFFFF,
        "dropped_count": parse_bram_int(row.get(columns["dropped_count"], ""), unprefixed_radix=radix) & 0xFFFFFFFFFFFFFFFF,
        "wrap_count": parse_bram_int(row.get(columns["wrap_count"], ""), unprefixed_radix=radix) & 0xFFFFFFFFFFFFFFFF,
        "payload_high_bits": 0,
    })


def annotate_compact_arg_mem(record: dict[str, Any]) -> dict[str, Any]:
    if record.get("evt") == "ARG_MEM":
        record["mem_addr"] = hex_width(int(str(record.get("packed_primary", "0")), 16), 64)
        record["mem_data"] = hex_width(int(str(record.get("packed_aux", "0")), 16), 64)
        record["snapshot_bytes"] = 4
        record["snapshot_source"] = "hardware_bram_ring_compact"
        record["payload_width_note"] = "BRAM compact records expose 32-bit address/data prefixes for ARG_MEM"
    return record


def decode_csv(path: Path, *, unprefixed_radix: str) -> list[dict[str, Any]]:
    headers, rows = read_rows(path)
    column = find_bram_payload_column(headers)
    segmented_columns = find_segmented_columns(headers) if column is None else {}
    if column is None and set(segmented_columns) != set(SEGMENTED_FIELD_ALIASES):
        missing = sorted(set(SEGMENTED_FIELD_ALIASES) - set(segmented_columns))
        raise ValueError(
            "missing BRAM ring ILA columns: expected a single "
            "rvmt_trace_bram_probe_payload/probe2[483:0] column or segmented fields; "
            f"missing segmented fields: {', '.join(missing)}"
        )
    records: list[dict[str, Any]] = []
    for row_index, row in enumerate(rows):
        if column is not None:
            payload = parse_bram_int(row.get(column, ""), unprefixed_radix=unprefixed_radix)
            record = unpack_bram_payload(payload, row_index=row_index)
            if record["payload_high_bits"] != 0:
                raise ValueError(f"{path}: row {row_index} exceeds {BRAM_PAYLOAD_WIDTH}-bit BRAM payload layout")
        else:
            record = unpack_segmented_row(row, segmented_columns, row_index=row_index, radix=unprefixed_radix)
        records.append(record)
    return records


def valid_unique_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_sequence: dict[int, dict[str, Any]] = {}
    for record in records:
        if not record.get("dump_valid"):
            continue
        if record.get("evt") == "NONE":
            continue
        by_sequence[int(record["sequence_number"])] = record
    return [by_sequence[key] for key in sorted(by_sequence)]


def event_counts(records: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        evt = str(record.get("evt", "UNKNOWN"))
        counts[evt] = counts.get(evt, 0) + 1
    return counts


def latest_counters(records: list[dict[str, Any]]) -> dict[str, Any]:
    if not records:
        return {
            "event_count": 0,
            "captured_count": 0,
            "dropped_count": 0,
            "wrap_count": 0,
            "next_sequence": 0,
            "write_index": 0,
            "oldest_index": 0,
            "full": False,
        }
    latest = max(records, key=lambda record: int(record["ila_row_index"]))
    return {
        "event_count": latest["event_count"],
        "captured_count": latest["captured_count"],
        "dropped_count": latest["dropped_count"],
        "wrap_count": latest["wrap_count"],
        "next_sequence": latest["next_sequence"],
        "write_index": latest["write_index"],
        "oldest_index": latest["oldest_index"],
        "full": latest["full"],
    }


def make_summary(csv_path: Path, decoded: list[dict[str, Any]], *, sample_id: str | None, trigger_primary: str | None) -> dict[str, Any]:
    unique = valid_unique_records(decoded)
    counters = latest_counters(decoded)
    cycles = [int(record["cycle"]) for record in unique]
    sequence_numbers = [int(record["sequence_number"]) for record in unique]
    expected_trigger_seen = True
    if trigger_primary:
        trigger_value = int(trigger_primary, 16) & 0xFFFFFFFF
        expected_trigger_seen = any(
            record.get("evt") == "MARKER" and int(str(record.get("packed_primary", "0")), 16) == trigger_value
            for record in unique
        )
    return {
        "schema": "rvmt.genesys2.bram_ring_dump.v1",
        "status": "PASS" if unique and expected_trigger_seen else "FAIL",
        "sample_id": sample_id,
        "csv": csv_path.as_posix(),
        "payload_width": BRAM_PAYLOAD_WIDTH,
        "ring_depth": BRAM_RING_DEPTH,
        "decoded_rows": len(decoded),
        "valid_record_rows": sum(1 for record in decoded if record.get("dump_valid")),
        "unique_record_count": len(unique),
        "sequence_first": min(sequence_numbers) if sequence_numbers else None,
        "sequence_last": max(sequence_numbers) if sequence_numbers else None,
        "start_timestamp": min(cycles) if cycles else 0,
        "end_timestamp": max(cycles) if cycles else 0,
        "event_counts": event_counts(unique),
        "trigger_primary": trigger_primary,
        "trigger_marker_seen": expected_trigger_seen,
        "bram_ring": {
            "sequence_number": max(sequence_numbers) if sequence_numbers else 0,
            "event_count": counters["event_count"],
            "captured_count": counters["captured_count"],
            "dropped_count": counters["dropped_count"],
            "wrap_count": counters["wrap_count"],
            "next_sequence": counters["next_sequence"],
            "write_index": counters["write_index"],
            "oldest_index": counters["oldest_index"],
            "full": counters["full"],
            "start_timestamp": min(cycles) if cycles else 0,
            "end_timestamp": max(cycles) if cycles else 0,
        },
    }


def write_jsonl(records: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(record, sort_keys=True) + "\n" for record in records), encoding="utf-8", newline="\n")


def write_json(value: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def run_self_test() -> int:
    payloads = []
    for index, evt_code in enumerate((12, 4, 5, 12)):
        payload = (
            evt_code
            | ((100 + index) << 4)
            | ((0x80001000 + index * 4) << 36)
            | ((0xE0000A01 if index == 3 else index) << 68)
            | ((64 if evt_code == 4 else 0) << 100)
            | (index << 132)
            | (1 << 164)
            | (0 << 165)
            | (index << 166)
            | (4 << 176)
            | (0 << 186)
            | (4 << 196)
            | (0 << 228)
            | (0 << 292)
            | (4 << 356)
            | (4 << 420)
        )
        payloads.append(payload)
    with tempfile.TemporaryDirectory() as tmp:
        csv_path = Path(tmp) / "bram.csv"
        segmented_csv_path = Path(tmp) / "bram_segmented.csv"
        out_path = Path(tmp) / "records.jsonl"
        summary_path = Path(tmp) / "summary.json"
        with csv_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["Sample in Buffer", "rvmt_trace_bram_probe_payload[483:0]"])
            writer.writerow(["Radix - UNSIGNED", "HEX"])
            for row, payload in enumerate(payloads):
                writer.writerow([row, f"{payload:x}"])
        with segmented_csv_path.open("w", encoding="utf-8", newline="") as handle:
            field_order = list(SEGMENTED_FIELD_ALIASES)
            writer = csv.writer(handle)
            writer.writerow(["Sample in Buffer"] + [SEGMENTED_FIELD_ALIASES[field][0] for field in field_order])
            writer.writerow(["Radix - UNSIGNED"] + ["HEX"] * len(field_order))
            for row, payload in enumerate(payloads):
                record = unpack_bram_payload(payload, row_index=row)
                writer.writerow(
                    [row]
                    + [
                        f"{int(record['evt_code']):x}",
                        f"{int(record['cycle']):x}",
                        record["pc"],
                        record["packed_primary"],
                        record["packed_aux"],
                        f"{int(record['sequence_number']):x}",
                        "1" if record["dump_valid"] else "0",
                        "1" if record["full"] else "0",
                        f"{int(record['dump_index']):x}",
                        f"{int(record['write_index']):x}",
                        f"{int(record['oldest_index']):x}",
                        f"{int(record['next_sequence']):x}",
                        f"{int(record['wrap_count']):x}",
                        f"{int(record['dropped_count']):x}",
                        f"{int(record['captured_count']):x}",
                        f"{int(record['event_count']):x}",
                    ]
                )
        decoded = decode_csv(csv_path, unprefixed_radix="hex")
        decoded_segmented = decode_csv(segmented_csv_path, unprefixed_radix="hex")
        unique = valid_unique_records(decoded)
        summary = make_summary(csv_path, decoded, sample_id="hello_write", trigger_primary="e0000a01")
        write_jsonl(unique, out_path)
        write_json(summary, summary_path)
        loaded = json.loads(summary_path.read_text(encoding="utf-8"))
    if len(unique) != 4:
        print("[FAIL] expected four valid BRAM records", file=sys.stderr)
        return 1
    if valid_unique_records(decoded_segmented) != unique:
        print("[FAIL] segmented BRAM CSV decode mismatch", file=sys.stderr)
        return 1
    if loaded.get("status") != "PASS" or loaded.get("event_counts", {}).get("MARKER") != 2:
        print("[FAIL] BRAM summary self-test mismatch", file=sys.stderr)
        return 1
    if loaded.get("bram_ring", {}).get("dropped_count") != 0 or loaded.get("bram_ring", {}).get("event_count") != 4:
        print("[FAIL] BRAM counter self-test mismatch", file=sys.stderr)
        return 1
    print("[PASS] Genesys2 BRAM ring dump decoder self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Decode Genesys2 CVA6 BRAM ring ILA probe2 CSV dump.")
    parser.add_argument("--csv", type=Path, help="Vivado ILA CSV containing rvmt_trace_bram_probe_payload/probe2.")
    parser.add_argument("--out-jsonl", type=Path, help="Output decoded unique BRAM records as JSONL.")
    parser.add_argument("--summary", type=Path, help="Output BRAM dump summary JSON.")
    parser.add_argument("--sample-id")
    parser.add_argument("--trigger-primary", help="Expected marker primary value, for example e0000a01.")
    parser.add_argument(
        "--unprefixed-radix",
        choices=("hex", "binary"),
        default="hex",
        help="Radix for ILA values that have no 0x/h/b prefix.",
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return run_self_test()
    if not args.csv or not args.out_jsonl or not args.summary:
        parser.error("--csv, --out-jsonl, and --summary are required unless --self-test is used")

    try:
        decoded = decode_csv(args.csv, unprefixed_radix=args.unprefixed_radix)
        unique = valid_unique_records(decoded)
        summary = make_summary(args.csv, decoded, sample_id=args.sample_id, trigger_primary=args.trigger_primary)
        write_jsonl(unique, args.out_jsonl)
        write_json(summary, args.summary)
    except Exception as exc:
        print(f"decode_genesys2_bram_ring_dump: error: {exc}", file=sys.stderr)
        return 2

    print(f"[PASS] wrote {len(unique)} BRAM ring records to {args.out_jsonl}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
