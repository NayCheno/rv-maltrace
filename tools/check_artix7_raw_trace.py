from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rv_maltrace.cli import convert_artix7_raw_trace_to_jsonl  # noqa: E402


def load_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main() -> int:
    header_entry = 0x00000004
    header_ret = 0x00000015
    header_trap = 0x00000016
    header_priv = 0x00000359
    raw = "\n".join(
        [
            "RVMT_TRACE_DROP 00000002",
            (
                "RVMT_TRACE_RECORD 0 "
                f"{header_entry:08x} 0000000a 40000100 00000073 00000000 00000000 "
                "00000040 00000000 00000001 00000002 00000003 00000004 "
                "00000005 00000006 00000007 0000003f"
            ),
            (
                "RVMT_TRACE_RECORD 1 "
                f"{header_ret:08x} 00000018 c0000200 10200073 40000104 0000000e "
                "00000040 00000000 ffffffff 00000000 00000000 00000000 "
                "00000000 00000000 00000000 00000000"
            ),
            (
                "RVMT_TRACE_RECORD 2 "
                f"{header_trap:08x} 0000001c 40000120 00000000 00000002 deadbeef "
                "00000000 00000000 00000000 00000000 00000000 00000000 "
                "00000000 00000000 00000000 00000000"
            ),
            (
                "RVMT_TRACE_RECORD 3 "
                f"{header_priv:08x} 00000020 c0000300 30200073 40000200 00000000 "
                "00000000 00000000 00000000 00000000 00000000 00000000 "
                "00000000 00000000 00000000 00000000"
            ),
            "",
        ]
    )
    with tempfile.TemporaryDirectory() as tmp:
        raw_path = Path(tmp) / "trace_raw_uart.log"
        jsonl_path = Path(tmp) / "trace.jsonl"
        raw_path.write_text(raw, encoding="utf-8", newline="\n")
        count = convert_artix7_raw_trace_to_jsonl(raw_path, jsonl_path)
        events = load_jsonl(jsonl_path)
    errors: list[str] = []
    if count != 5 or len(events) != 5:
        errors.append(f"expected 5 converted events, got count={count} len={len(events)}")
    if events[1].get("evt") != "SYSCALL_ENTRY" or events[1].get("a7") != "0x0000003f":
        errors.append("syscall entry did not preserve a0-a7 shadow fields")
    if events[2].get("evt") != "SYSCALL_RET" or events[2].get("duration") != 14:
        errors.append("syscall return did not preserve duration")
    if events[3].get("evt") != "TRAP" or events[3].get("cause") != "0x00000002":
        errors.append("trap did not preserve cause")
    if events[4].get("evt") != "PRIV" or events[4].get("old_priv") != "S" or events[4].get("new_priv") != "M":
        errors.append("privilege event did not decode old/new privilege")
    if errors:
        for error in errors:
            print(f"FAIL: {error}")
        return 1
    print("PASS: Artix-7 raw trace converter self-test")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
