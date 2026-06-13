from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from external_closure_artifacts import ROOT, repo_path, write_summary


MAGIC = b"RVMT"
DATA_FRAME = 0x01
STATUS_FRAME = 0x7F
DATA_PAYLOAD_BYTES = 17
STATUS_PAYLOAD_BYTES = 24
DEFAULT_OUT_DIR = Path("results/board/genesys2_trace_validation/20260613-uart-streaming-dma")


def crc16_update(crc: int, byte: int) -> int:
    crc ^= byte << 8
    for _ in range(8):
        if crc & 0x8000:
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF
        else:
            crc = (crc << 1) & 0xFFFF
    return crc


def crc16_ccitt(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc = crc16_update(crc, byte)
    return crc


def decode_data_payload(payload: bytes) -> dict[str, Any]:
    raw = int.from_bytes(payload, "little")
    evt_code = raw & 0xF
    return {
        "evt_code": evt_code,
        "cycle": (raw >> 4) & 0xFFFFFFFF,
        "pc": f"0x{((raw >> 36) & 0xFFFFFFFF):08x}",
        "primary": f"0x{((raw >> 68) & 0xFFFFFFFF):08x}",
        "aux": f"0x{((raw >> 104) & 0xFFFFFFFF):08x}",
    }


def decode_status_payload(payload: bytes) -> dict[str, Any]:
    accepted = int.from_bytes(payload[0:8], "little")
    dropped = int.from_bytes(payload[8:16], "little")
    next_sequence = int.from_bytes(payload[16:20], "little")
    status_word = int.from_bytes(payload[20:24], "little")
    return {
        "accepted_count": accepted,
        "dropped_count": dropped,
        "next_sequence": next_sequence,
        "done": bool(status_word & 0x1),
        "status_word": status_word,
    }


def parse_frames(data: bytes) -> tuple[list[dict[str, Any]], list[str]]:
    frames: list[dict[str, Any]] = []
    errors: list[str] = []
    index = 0
    while index < len(data):
        magic_index = data.find(MAGIC, index)
        if magic_index < 0:
            if index < len(data):
                errors.append(f"trailing_unframed_bytes={len(data) - index}")
            break
        if magic_index > index:
            errors.append(f"skipped_unframed_bytes={magic_index - index}")
        if magic_index + 10 > len(data):
            errors.append("truncated_header")
            break
        frame_type = data[magic_index + 4]
        payload_len = data[magic_index + 5]
        frame_len = 10 + payload_len + 2
        if magic_index + frame_len > len(data):
            errors.append(f"truncated_frame_at={magic_index}")
            break
        frame = data[magic_index : magic_index + frame_len]
        sequence = int.from_bytes(frame[6:10], "little")
        payload = frame[10 : 10 + payload_len]
        expected_crc = int.from_bytes(frame[10 + payload_len : 12 + payload_len], "little")
        actual_crc = crc16_ccitt(frame[: 10 + payload_len])
        row: dict[str, Any] = {
            "frame_index": len(frames),
            "type": frame_type,
            "payload_len": payload_len,
            "sequence": sequence,
            "crc_ok": actual_crc == expected_crc,
        }
        if actual_crc != expected_crc:
            errors.append(f"crc_error_frame={len(frames)}")
        if frame_type == DATA_FRAME and payload_len == DATA_PAYLOAD_BYTES:
            row.update(decode_data_payload(payload))
        elif frame_type == STATUS_FRAME and payload_len == STATUS_PAYLOAD_BYTES:
            row.update(decode_status_payload(payload))
        else:
            errors.append(f"unexpected_frame_type=0x{frame_type:02x}/len={payload_len}")
        frames.append(row)
        index = magic_index + frame_len
    return frames, errors


def summarize_frames(frames: list[dict[str, Any]], errors: list[str], elapsed_seconds: float, raw_path: Path, frames_path: Path, stream_baud: int) -> dict[str, Any]:
    data_frames = [row for row in frames if row.get("type") == DATA_FRAME]
    status_frames = [row for row in frames if row.get("type") == STATUS_FRAME]
    sequence_errors: list[str] = []
    expected_seq = None
    for row in data_frames:
        seq = int(row.get("sequence") or 0)
        if expected_seq is not None and seq != expected_seq:
            sequence_errors.append(f"expected={expected_seq} observed={seq}")
        expected_seq = seq + 1
    status = status_frames[-1] if status_frames else {}
    accepted_count = int(status.get("accepted_count") or len(data_frames))
    dropped_count = int(status.get("dropped_count") or 0)
    payload_bytes = len(data_frames) * DATA_PAYLOAD_BYTES
    sustained = payload_bytes / elapsed_seconds if elapsed_seconds > 0 else 0.0
    status_sequence_ok = bool(status_frames) and int(status.get("next_sequence") or -1) == accepted_count + dropped_count
    return {
        "schema": "rvmt.genesys2.uart_stream_host_receiver.v1",
        "transport": "uart_streaming_dma",
        "stream_baud": stream_baud,
        "parser_success": not errors and not sequence_errors and bool(status_frames) and status_sequence_ok,
        "status_frame_seen": bool(status_frames),
        "status_sequence_ok": status_sequence_ok,
        "data_frame_count": len(data_frames),
        "accepted_count": accepted_count,
        "accepted_count_matches_data_frames": accepted_count == len(data_frames),
        "dropped_count": dropped_count,
        "sequence_error_count": len(sequence_errors),
        "crc_error_count": sum(1 for row in frames if row.get("crc_ok") is not True),
        "parse_errors": errors,
        "sequence_errors": sequence_errors,
        "payload_bytes": payload_bytes,
        "elapsed_seconds": elapsed_seconds,
        "sustained_bytes_per_second": sustained,
        "raw_capture": str(raw_path).replace("\\", "/"),
        "frames_jsonl": str(frames_path).replace("\\", "/"),
    }


def read_serial_capture(port: str, console_baud: int, stream_baud: int, command: str | None, duration: float, switch_delay: float) -> bytes:
    try:
        import serial  # type: ignore
    except Exception as exc:  # pragma: no cover - depends on host environment
        raise RuntimeError(f"pyserial is required for live UART capture: {exc}") from exc
    chunks: list[bytes] = []
    deadline = time.monotonic() + duration
    initial_baud = console_baud if command else stream_baud
    with serial.Serial(port, initial_baud, timeout=0.05, write_timeout=5) as stream:
        if command:
            stream.reset_input_buffer()
            stream.write(command.encode("utf-8") + b"\r\n")
            stream.flush()
            time.sleep(switch_delay)
            stream.baudrate = stream_baud
            deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            chunk = stream.read(65536)
            if chunk:
                chunks.append(chunk)
    return b"".join(chunks)


def write_capture_outputs(root: Path, out_dir_arg: Path, raw: bytes, elapsed_seconds: float, stream_baud: int) -> dict[str, Any]:
    out_dir = repo_path(root, out_dir_arg)
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_path = out_dir / "uart_stream.raw"
    frames_path = out_dir / "uart_frames.jsonl"
    summary_path = out_dir / "host_receiver_log.json"
    raw_path.write_bytes(raw)
    frames, errors = parse_frames(raw)
    frames_path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in frames) + ("\n" if frames else ""), encoding="utf-8")
    summary = summarize_frames(frames, errors, elapsed_seconds, raw_path, frames_path, stream_baud)
    write_summary(root, summary_path, summary)
    return summary


def self_test() -> int:
    def frame(frame_type: int, seq: int, payload: bytes) -> bytes:
        header = MAGIC + bytes([frame_type, len(payload)]) + seq.to_bytes(4, "little")
        crc = crc16_ccitt(header + payload)
        return header + payload + crc.to_bytes(2, "little")

    data_payload = (0xC | (1 << 4) | (0x1010 << 36) | (0xB0000A11 << 68)).to_bytes(DATA_PAYLOAD_BYTES, "little")
    status_payload = (1).to_bytes(8, "little") + (0).to_bytes(8, "little") + (1).to_bytes(4, "little") + (1).to_bytes(4, "little")
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        summary = write_capture_outputs(root, Path("capture"), frame(DATA_FRAME, 0, data_payload) + frame(STATUS_FRAME, 1, status_payload), 0.1, 12_000_000)
        if not summary.get("parser_success") or summary.get("sustained_bytes_per_second", 0) <= 0:
            print("[FAIL] UART receiver PASS fixture rejected", file=sys.stderr)
            print(json.dumps(summary, indent=2), file=sys.stderr)
            return 1
        bad = bytearray(frame(DATA_FRAME, 0, data_payload) + frame(STATUS_FRAME, 1, status_payload))
        bad[12] ^= 0x1
        summary = write_capture_outputs(root, Path("bad"), bytes(bad), 0.1, 12_000_000)
        if summary.get("parser_success"):
            print("[FAIL] UART receiver CRC fixture accepted", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 UART streaming receiver self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Capture and validate Genesys2 UART framed compact trace stream.")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--port", default="COM7")
    parser.add_argument("--console-baud", type=int, default=115200)
    parser.add_argument("--stream-baud", type=int, default=12_000_000)
    parser.add_argument("--command")
    parser.add_argument("--duration", type=float, default=15.0)
    parser.add_argument("--switch-delay", type=float, default=0.1)
    parser.add_argument("--input-binary", type=Path)
    parser.add_argument("--elapsed-seconds", type=float)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    start = time.monotonic()
    if args.input_binary:
        raw = repo_path(root, args.input_binary).read_bytes()
        elapsed = args.elapsed_seconds if args.elapsed_seconds is not None else max(args.duration, 1e-9)
    else:
        raw = read_serial_capture(args.port, args.console_baud, args.stream_baud, args.command, args.duration, args.switch_delay)
        elapsed = time.monotonic() - start
    summary = write_capture_outputs(root, args.out_dir, raw, elapsed, args.stream_baud)
    path = repo_path(root, args.out_dir) / "host_receiver_log.json"
    status = "PASS" if summary.get("parser_success") else "FAIL"
    print(f"[{status}] wrote UART host receiver log to {path}")
    return 0 if summary.get("parser_success") else 1


if __name__ == "__main__":
    raise SystemExit(main())
