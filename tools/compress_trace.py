from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterable

from parse_trace import load_trace


U64_MASK = (1 << 64) - 1

ARG_FIELDS = tuple(f"a{index}" for index in range(8))

EVENT_PAYLOAD_FIELDS: dict[str, tuple[str, ...]] = {
    "RETIRE": (),
    "BRANCH": ("taken",),
    "JUMP": (),
    "ECALL": ARG_FIELDS,
    "SYSCALL_ENTRY": ("syscall_id", *ARG_FIELDS),
    "SYSCALL_RET": ("syscall_id", "duration", "a0"),
    "ARG_MEM": ("syscall_id", "arg_index", "mem_addr", "mem_data", "mem_size", "mem_last"),
    "TRAP": ("cause", "tval"),
    "CSR": ("csr", "value"),
    "SATP": ("csr", "value"),
    "PRIV": ("old_priv", "new_priv"),
    "MARKER": ("value",),
    "DROP": ("value",),
}

CONTEXT_FIELDS: dict[str, tuple[str, ...]] = {
    "RETIRE": ("priv",),
    "BRANCH": ("priv",),
    "JUMP": ("priv",),
    "ECALL": ("priv",),
    "SYSCALL_ENTRY": ("priv",),
    "SYSCALL_RET": ("priv",),
    "ARG_MEM": ("priv",),
    "TRAP": ("priv",),
    "CSR": ("priv",),
    "SATP": ("priv", "satp"),
}

TARGET_DELTA_EVENTS = {"BRANCH", "JUMP", "SYSCALL_RET", "PRIV"}


def parse_int(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        raise ValueError("empty integer field")
    sign = -1 if text.startswith("-") else 1
    if text[0] in "+-":
        text = text[1:]
    return sign * int(text, 0)


def hex64(value: int) -> str:
    return f"0x{value & U64_MASK:016x}"


def delta_hex(value: int) -> str:
    prefix = "-0x" if value < 0 else "0x"
    return f"{prefix}{abs(value):x}"


def canonical_json_bytes(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def payload_len(payload: dict[str, Any]) -> int:
    return len(canonical_json_bytes(payload))


def compact_json_line(payload: Any) -> str:
    return json.dumps(payload, separators=(",", ":"))


def load_compressed(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid compressed JSONL: {exc}") from exc
            if not isinstance(record, dict):
                raise ValueError(f"{path}:{line_no}: compressed record must be a JSON object")
            records.append(record)
    return records


def write_jsonl(items: Iterable[dict[str, Any]], path: Path | None) -> None:
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            for item in items:
                handle.write(compact_json_line(item) + "\n")
        return

    for item in items:
        sys.stdout.write(compact_json_line(item) + "\n")


def compress_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    context: dict[str, Any] = {}
    previous_cycle = 0
    previous_pc = 0

    for sequence, event in enumerate(events):
        evt = str(event.get("evt", "NONE"))
        cycle = parse_int(event.get("cycle", previous_cycle))
        payload: dict[str, Any] = {}
        pc = parse_int(event["pc"]) if "pc" in event else None

        if "instr" in event:
            payload["instr"] = event["instr"]

        for field in EVENT_PAYLOAD_FIELDS.get(evt, ()):
            if field in event:
                payload[field] = event[field]

        if pc is not None and evt in TARGET_DELTA_EVENTS and "target" in event:
            payload["target_delta"] = delta_hex(parse_int(event["target"]) - pc)

        context_delta: dict[str, Any] = {}
        context_present: list[str] = []
        for field in CONTEXT_FIELDS.get(evt, ()):
            if field in event:
                context_present.append(field)
                if context.get(field) != event[field]:
                    context_delta[field] = event[field]
                context[field] = event[field]
        if context_delta:
            payload["ctx"] = context_delta
        if evt in CONTEXT_FIELDS:
            payload["ctx_fields"] = context_present

        if evt == "PRIV" and "new_priv" in event:
            context["priv"] = event["new_priv"]

        header = {
            "version": 1,
            "seq": sequence,
            "evt": evt,
            "cycle_delta": cycle - previous_cycle,
            "payload_len": payload_len(payload),
        }
        if pc is not None:
            header["pc_delta"] = delta_hex(pc - previous_pc)
        records.append({"header": header, "payload": payload})
        previous_cycle = cycle
        if pc is not None:
            previous_pc = pc

    return records


def checked_payload(record: dict[str, Any], index: int) -> tuple[dict[str, Any], dict[str, Any]]:
    header = record.get("header")
    payload = record.get("payload", {})
    if not isinstance(header, dict):
        raise ValueError(f"record {index}: missing header object")
    if not isinstance(payload, dict):
        raise ValueError(f"record {index}: payload must be an object")
    if int(header.get("payload_len", -1)) != payload_len(payload):
        raise ValueError(
            f"record {index}: payload_len mismatch, header has {header.get('payload_len')}, "
            f"actual is {payload_len(payload)}"
        )
    return header, payload


def decompress_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    context: dict[str, Any] = {}
    previous_cycle = 0
    previous_pc = 0

    for index, record in enumerate(records):
        header, payload = checked_payload(record, index)
        evt = str(header["evt"])
        cycle = previous_cycle + parse_int(header.get("cycle_delta", 0))

        event: dict[str, Any] = {
            "cycle": cycle,
            "evt": evt,
        }
        pc: int | None = None
        if "pc_delta" in header:
            pc = previous_pc + parse_int(header["pc_delta"])
            event["pc"] = hex64(pc)
        if "instr" in payload:
            event["instr"] = payload["instr"]

        context_delta = payload.get("ctx", {})
        if not isinstance(context_delta, dict):
            raise ValueError(f"record {index}: ctx must be an object")
        context.update(context_delta)
        context_fields_payload = payload.get("ctx_fields")
        if context_fields_payload is None:
            context_fields = CONTEXT_FIELDS.get(evt, ())
        else:
            if not isinstance(context_fields_payload, list) or not all(isinstance(field, str) for field in context_fields_payload):
                raise ValueError(f"record {index}: ctx_fields must be a list of strings")
            context_fields = tuple(context_fields_payload)
        valid_context_fields = set(CONTEXT_FIELDS.get(evt, ()))
        for field in context_fields:
            if field not in valid_context_fields:
                raise ValueError(f"record {index}: ctx_fields contains invalid field {field!r} for {evt}")
            if field in context:
                event[field] = context[field]

        for field in EVENT_PAYLOAD_FIELDS.get(evt, ()):
            if field in payload:
                event[field] = payload[field]

        if pc is not None and evt in TARGET_DELTA_EVENTS and "target_delta" in payload:
            event["target"] = hex64(pc + parse_int(payload["target_delta"]))

        if evt == "PRIV" and "new_priv" in payload:
            context["priv"] = payload["new_priv"]

        events.append(event)
        previous_cycle = cycle
        if pc is not None:
            previous_pc = pc

    return events


def byte_count(items: Iterable[dict[str, Any]]) -> int:
    return sum(len(compact_json_line(item).encode("utf-8")) + 1 for item in items)


def print_stats(events: list[dict[str, Any]], records: list[dict[str, Any]]) -> None:
    payload_bytes = sum(int(record["header"]["payload_len"]) for record in records)
    stats = {
        "events": len(events),
        "records": len(records),
        "original_jsonl_bytes": byte_count(events),
        "compressed_jsonl_bytes": byte_count(records),
        "payload_bytes": payload_bytes,
    }
    json.dump(stats, sys.stderr, indent=2, sort_keys=True)
    sys.stderr.write("\n")


def check_roundtrip(path: Path, *, show_stats: bool = False) -> None:
    events = load_trace(path)
    records = compress_events(events)
    decoded = decompress_records(records)
    if events != decoded:
        raise ValueError(f"round-trip mismatch for {path}")
    if show_stats:
        print_stats(events, records)
    print(f"roundtrip: PASS {path} events={len(events)} records={len(records)}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compress or decompress rv-maltrace JSONL traces.")
    parser.add_argument("input", type=Path)
    parser.add_argument("--out", type=Path, help="Output JSONL path. Defaults to stdout.")
    parser.add_argument("--decompress", action="store_true", help="Decode compressed JSONL back to trace JSONL.")
    parser.add_argument(
        "--check-roundtrip",
        action="store_true",
        help="Compress, validate payload lengths, decompress, and require exact event equality.",
    )
    parser.add_argument("--stats", action="store_true", help="Print compression byte counts to stderr.")
    args = parser.parse_args(argv)

    if args.decompress and args.check_roundtrip:
        parser.error("--decompress and --check-roundtrip are mutually exclusive")
    if args.check_roundtrip and args.out:
        parser.error("--out is not used with --check-roundtrip")

    try:
        if args.check_roundtrip:
            check_roundtrip(args.input, show_stats=args.stats)
        elif args.decompress:
            records = load_compressed(args.input)
            events = decompress_records(records)
            write_jsonl(events, args.out)
        else:
            events = load_trace(args.input)
            records = compress_events(events)
            write_jsonl(records, args.out)
            if args.stats:
                print_stats(events, records)
    except Exception as exc:
        print(f"compress_trace: error: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
