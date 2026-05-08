from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


def load_trace(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
            if not isinstance(event, dict):
                raise ValueError(f"{path}:{line_no}: trace event must be a JSON object")
            events.append(event)
    return events


def summarize(events: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter(str(event.get("evt", "NONE")) for event in events)
    first_cycle = events[0].get("cycle") if events else None
    last_cycle = events[-1].get("cycle") if events else None
    return {
        "events": len(events),
        "first_cycle": first_cycle,
        "last_cycle": last_cycle,
        "counts": dict(sorted(counts.items())),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Parse and summarize an rv-maltrace JSONL trace.")
    parser.add_argument("trace", type=Path)
    parser.add_argument("--summary", action="store_true", help="Print event counts instead of normalized JSON.")
    args = parser.parse_args(argv)

    try:
        events = load_trace(args.trace)
    except Exception as exc:
        print(f"parse_trace: error: {exc}", file=sys.stderr)
        return 2

    payload: Any = summarize(events) if args.summary else events
    json.dump(payload, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
