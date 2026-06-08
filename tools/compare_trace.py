from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSONL: {exc}") from exc
    return events


def normalize(value: Any) -> Any:
    if isinstance(value, str):
        if value == "ANY":
            return value
        if value.startswith("0x"):
            try:
                return hex(int(value, 16))
            except ValueError:
                return value.lower()
        return value
    return value


def field_matches(actual: Any, expected: Any) -> bool:
    if expected == "ANY":
        return actual is not None
    return normalize(actual) == normalize(expected)


def event_matches(event: dict[str, Any], required: dict[str, Any]) -> bool:
    for key, expected_value in required.items():
        if key not in event:
            return False
        if not field_matches(event[key], expected_value):
            return False
    return True


def compare(events: list[dict[str, Any]], expected: dict[str, Any]) -> tuple[bool, list[str]]:
    messages: list[str] = []
    ok = True
    counts = Counter(str(event.get("evt", "")) for event in events)
    syscall_entries = Counter(
        normalize(event.get("a7"))
        for event in events
        if str(event.get("evt", "")) == "SYSCALL_ENTRY" and event.get("a7") is not None
    )

    if "total_events" in expected:
        actual = len(events)
        exact = int(expected["total_events"])
        if actual != exact:
            ok = False
            messages.append(f"[FAIL] total events: expected exactly {exact}, got {actual}")
        else:
            messages.append(f"[PASS] total events: count {actual} == {exact}")

    for evt, minimum in expected.get("min_counts", {}).items():
        actual = counts.get(str(evt), 0)
        if actual < int(minimum):
            ok = False
            messages.append(f"[FAIL] {evt}: expected at least {minimum}, got {actual}")
        else:
            messages.append(f"[PASS] {evt}: count {actual} >= {minimum}")

    for evt, exact in expected.get("exact_counts", {}).items():
        actual = counts.get(str(evt), 0)
        if actual != int(exact):
            ok = False
            messages.append(f"[FAIL] {evt}: expected exactly {exact}, got {actual}")
        else:
            messages.append(f"[PASS] {evt}: count {actual} == {exact}")

    for evt in expected.get("forbidden_events", []):
        actual = counts.get(str(evt), 0)
        if actual:
            ok = False
            messages.append(f"[FAIL] forbidden {evt}: got {actual}")
        else:
            messages.append(f"[PASS] forbidden {evt}: absent")

    for required in expected.get("required_events", []):
        if isinstance(required, str):
            if counts.get(required, 0):
                messages.append(f"[PASS] required event present: {required}")
            else:
                ok = False
                messages.append(f"[FAIL] required event missing: {required}")
        elif any(event_matches(event, required) for event in events):
            messages.append(f"[PASS] required event matched: {required}")
        else:
            ok = False
            messages.append(f"[FAIL] required event missing: {required}")

    required_syscalls = expected.get("required_syscalls", [])
    if required_syscalls:
        wanted = Counter()
        names: dict[Any, str] = {}
        for item in required_syscalls:
            if not isinstance(item, dict) or "number" not in item:
                ok = False
                messages.append(f"[FAIL] invalid required syscall entry: {item}")
                continue
            number = normalize(hex(int(item["number"])))
            wanted[number] += 1
            names[number] = str(item.get("name", number))
        for number, minimum in wanted.items():
            actual = syscall_entries.get(number, 0)
            name = names.get(number, str(number))
            if actual < minimum:
                ok = False
                messages.append(f"[FAIL] syscall {name} ({number}): expected at least {minimum} entry event(s), got {actual}")
            else:
                messages.append(f"[PASS] syscall {name} ({number}): entry count {actual} >= {minimum}")

    if not events:
        ok = False
        messages.append("[FAIL] trace is empty")

    return ok, messages


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare rv-maltrace JSONL trace against an expected JSON file.")
    parser.add_argument("--trace", required=True, type=Path)
    parser.add_argument("--expected", required=True, type=Path)
    parser.add_argument("--log", type=Path)
    args = parser.parse_args(argv)

    try:
        events = load_jsonl(args.trace)
        expected = json.loads(args.expected.read_text(encoding="utf-8"))
        ok, messages = compare(events, expected)
    except Exception as exc:
        messages = [f"[FAIL] {exc}"]
        ok = False

    output = "\n".join(messages) + "\n"
    if args.log:
        args.log.parent.mkdir(parents=True, exist_ok=True)
        args.log.write_text(output, encoding="utf-8", newline="\n")
    sys.stdout.write(output)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
