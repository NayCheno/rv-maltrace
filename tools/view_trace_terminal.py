from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any


EVENT_STYLE = {
    "MARKER": ("M", "marker"),
    "SYSCALL_ENTRY": ("S", "syscall entry"),
    "SYSCALL_RET": ("R", "syscall return"),
    "TRAP": ("T", "trap"),
    "ARG_MEM": ("A", "argument memory"),
    "PRIV": ("P", "privilege"),
    "CFLOW": ("C", "control flow"),
    "DROP": ("D", "drop"),
    "NONE": (".", "unknown"),
}

EVENT_PRIORITY = {
    "MARKER": 80,
    "DROP": 75,
    "TRAP": 70,
    "SYSCALL_ENTRY": 65,
    "SYSCALL_RET": 60,
    "ARG_MEM": 50,
    "CFLOW": 45,
    "PRIV": 30,
    "NONE": 0,
}

ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "MARKER": "\033[36m",
    "SYSCALL_ENTRY": "\033[32m",
    "SYSCALL_RET": "\033[92m",
    "TRAP": "\033[31m",
    "ARG_MEM": "\033[33m",
    "PRIV": "\033[35m",
    "CFLOW": "\033[34m",
    "DROP": "\033[91m",
}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                row = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_no}: trace record must be a JSON object")
            rows.append(row)
    return rows


def parse_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip().replace("_", "")
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        try:
            return int(text, 16)
        except ValueError:
            return None


def event_name(row: dict[str, Any]) -> str:
    return str(row.get("evt") or row.get("event") or "NONE").upper()


def short_event_char(evt: str) -> str:
    if evt in EVENT_STYLE:
        return EVENT_STYLE[evt][0]
    return (evt[:1] or "?").upper()


def colorize(text: str, evt: str | None, enabled: bool) -> str:
    if not enabled or evt is None:
        return text
    color = ANSI.get(evt)
    if not color:
        return text
    return f"{color}{text}{ANSI['reset']}"


def cell(value: Any, width: int) -> str:
    text = "" if value is None else str(value)
    if len(text) > width:
        return text[: max(0, width - 1)] + "~"
    return text.ljust(width)


def numeric_span(values: list[int]) -> tuple[int | None, int | None]:
    if not values:
        return None, None
    return values[0], values[-1]


def compact_span(start: int | None, end: int | None) -> str:
    if start is None or end is None:
        return "n/a"
    return f"{start} -> {end} (span {end - start})"


def record_metric(rows: list[dict[str, Any]], name: str) -> Any:
    for row in reversed(rows):
        value = row.get(name)
        if value is not None:
            return value
    return None


def first_present(row: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in row and row[name] is not None:
            return row[name]
    return None


def bar(count: int, max_count: int, width: int = 36) -> str:
    if max_count <= 0:
        return ""
    filled = max(1 if count else 0, round(count * width / max_count))
    return "#" * filled


def render_event_mix(rows: list[dict[str, Any]], color: bool) -> list[str]:
    counts = Counter(event_name(row) for row in rows)
    if not counts:
        return ["Event Mix", "  <empty trace>"]
    max_count = max(counts.values())
    lines = ["Event Mix"]
    for evt, count in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
        label = colorize(evt, evt, color)
        lines.append(f"  {cell(label, 18)} {str(count).rjust(6)} | {bar(count, max_count)}")
    return lines


def bucket_event(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return " "
    best = max(rows, key=lambda row: EVENT_PRIORITY.get(event_name(row), 10))
    return short_event_char(event_name(best))


def render_timeline(rows: list[dict[str, Any]], width: int, color: bool) -> list[str]:
    if not rows:
        return ["Timeline", "  <empty trace>"]
    width = max(8, width)
    if len(rows) <= width:
        chars = [(short_event_char(event_name(row)), event_name(row)) for row in rows]
    else:
        chars = []
        for index in range(width):
            start = index * len(rows) // width
            end = max(start + 1, (index + 1) * len(rows) // width)
            bucket = rows[start:end]
            evt = event_name(max(bucket, key=lambda row: EVENT_PRIORITY.get(event_name(row), 10)))
            chars.append((bucket_event(bucket), evt))
    timeline = "".join(colorize(char, evt, color) for char, evt in chars)
    legend_items = []
    for evt in sorted({event_name(row) for row in rows}, key=lambda name: (-EVENT_PRIORITY.get(name, 10), name)):
        legend_items.append(f"{short_event_char(evt)}={evt}")
    return [
        f"Timeline by record index ({len(rows)} records, {len(chars)} columns)",
        f"  |{timeline}|",
        "  " + "  ".join(legend_items),
    ]


def detail_field(row: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in ("mem_addr", "mem_addr_full", "mem_data", "mem_data_full", "syscall_id_full", "arg_index_full", "mem_last_full"):
        if key in row:
            parts.append(f"{key}={row[key]}")
    dropped = row.get("dropped_count")
    wrap = row.get("wrap_count")
    if dropped not in (None, 0, "0"):
        parts.append(f"dropped={dropped}")
    if wrap not in (None, 0, "0"):
        parts.append(f"wrap={wrap}")
    return " ".join(parts)


def render_table(rows: list[dict[str, Any]], limit: int, color: bool) -> list[str]:
    lines = [
        f"Events (showing {min(limit, len(rows))} of {len(rows)})",
        "  "
        + " ".join(
            [
                cell("#", 5),
                cell("seq", 7),
                cell("cycle", 12),
                cell("+cycle", 9),
                cell("evt", 14),
                cell("pc", 12),
                cell("primary", 12),
                cell("aux", 12),
                "detail",
            ]
        ),
    ]
    if not rows:
        lines.append("  <empty trace>")
        return lines
    first_cycle = parse_int(rows[0].get("cycle")) or 0
    for index, row in enumerate(rows[:limit]):
        evt = event_name(row)
        cycle = parse_int(row.get("cycle"))
        delta = "" if cycle is None else str(cycle - first_cycle)
        line = "  " + " ".join(
            [
                cell(index, 5),
                cell(first_present(row, "sequence_number", "seq", "sequence"), 7),
                cell(row.get("cycle"), 12),
                cell(delta, 9),
                cell(colorize(evt, evt, color), 14),
                cell(row.get("pc"), 12),
                cell(row.get("packed_primary") or row.get("primary"), 12),
                cell(row.get("packed_aux") or row.get("aux"), 12),
                detail_field(row),
            ]
        ).rstrip()
        lines.append(line)
    if len(rows) > limit:
        lines.append(f"  ... {len(rows) - limit} more records; raise --limit to show more")
    return lines


def render_trace(path: Path, rows: list[dict[str, Any]], *, limit: int, width: int, summary_only: bool, color: bool) -> str:
    cycles = [value for value in (parse_int(row.get("cycle")) for row in rows) if value is not None]
    seqs = [value for value in (parse_int(first_present(row, "sequence_number", "seq", "sequence")) for row in rows) if value is not None]
    lines = [
        "RV-MalTrace Terminal Trace View",
        f"Path: {path}",
        f"Records: {len(rows)}",
        f"Cycles: {compact_span(*numeric_span(cycles))}",
        f"Sequence: {compact_span(*numeric_span(seqs))}",
        "BRAM counters: "
        + f"dropped={record_metric(rows, 'dropped_count') or 0} "
        + f"wrap={record_metric(rows, 'wrap_count') or 0} "
        + f"captured={record_metric(rows, 'captured_count') or len(rows)} "
        + f"full={record_metric(rows, 'full')}",
        "",
        *render_event_mix(rows, color),
        "",
        *render_timeline(rows, width, color),
    ]
    if not summary_only:
        lines.extend(["", *render_table(rows, limit, color)])
    return "\n".join(lines) + "\n"


def use_color(mode: str) -> bool:
    if mode == "always":
        return True
    if mode == "never":
        return False
    return sys.stdout.isatty()


def self_test() -> int:
    rows = [
        {"evt": "MARKER", "cycle": 100, "sequence_number": 0, "pc": "0x1000", "packed_primary": "0xb0000a01"},
        {"evt": "SYSCALL_ENTRY", "cycle": 120, "sequence_number": 1, "pc": "0x1004", "packed_primary": "0x40"},
        {"evt": "ARG_MEM", "cycle": 130, "sequence_number": 2, "pc": "0x1008", "mem_addr": "0x2000", "mem_data": "0x41424344"},
        {"evt": "TRAP", "cycle": 150, "sequence_number": 3, "pc": "0x100c"},
        {"evt": "SYSCALL_RET", "cycle": 170, "sequence_number": 4, "pc": "0x1010"},
        {"evt": "MARKER", "cycle": 190, "sequence_number": 5, "pc": "0x1014", "packed_primary": "0xe0000a01"},
    ]
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "trace.jsonl"
        path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        loaded = load_jsonl(path)
        text = render_trace(path, loaded, limit=4, width=16, summary_only=False, color=False)
    required = ("RV-MalTrace Terminal Trace View", "Event Mix", "Timeline by record index", "SYSCALL_ENTRY", "ARG_MEM")
    missing = [item for item in required if item not in text]
    if missing:
        print("[FAIL] terminal trace view omitted expected text", file=sys.stderr)
        for item in missing:
            print(f"- {item}", file=sys.stderr)
        return 1
    print("[PASS] terminal trace viewer self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render an RV-MalTrace JSONL trace as a terminal dashboard.")
    parser.add_argument("trace", type=Path, nargs="?", help="Trace JSONL path, including Genesys2 bram_records.jsonl.")
    parser.add_argument("--limit", type=int, default=40, help="Maximum event rows to print.")
    parser.add_argument("--width", type=int, help="Timeline width. Defaults to terminal width minus margins.")
    parser.add_argument("--event", action="append", default=[], help="Only show matching event types. May repeat.")
    parser.add_argument("--summary-only", action="store_true", help="Print header, event mix, and timeline only.")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if args.trace is None:
        parser.error("trace path is required unless --self-test is used")
    if args.limit < 0:
        parser.error("--limit must be >= 0")
    try:
        rows = load_jsonl(args.trace)
        if args.event:
            wanted = {item.upper() for item in args.event}
            rows = [row for row in rows if event_name(row) in wanted]
        width = args.width if args.width is not None else max(48, shutil.get_terminal_size(fallback=(100, 24)).columns - 8)
        print(render_trace(args.trace, rows, limit=args.limit, width=width, summary_only=args.summary_only, color=use_color(args.color)), end="")
    except Exception as exc:
        print(f"view_trace_terminal: error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
