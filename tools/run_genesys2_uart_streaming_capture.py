from __future__ import annotations

import argparse
import ctypes
import json
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from external_closure_artifacts import ROOT, repo_path, write_summary


MAGIC = b"RVMT"
DATA_FRAME = 0x01
START_FRAME = 0x7E
STATUS_FRAME = 0x7F
DATA_PAYLOAD_BYTES = 17
STATUS_PAYLOAD_BYTES = 24
MAX_DATA_PAYLOAD_BYTES = DATA_PAYLOAD_BYTES * 15
DEFAULT_OUT_DIR = Path("results/board/genesys2_trace_validation/20260613-uart-streaming-dma")
FT_STATUS_NAMES = {
    0: "FT_OK",
    1: "FT_INVALID_HANDLE",
    2: "FT_DEVICE_NOT_FOUND",
    3: "FT_DEVICE_NOT_OPENED",
    4: "FT_IO_ERROR",
    5: "FT_INSUFFICIENT_RESOURCES",
    6: "FT_INVALID_PARAMETER",
    7: "FT_INVALID_BAUD_RATE",
    8: "FT_DEVICE_NOT_OPENED_FOR_ERASE",
    9: "FT_DEVICE_NOT_OPENED_FOR_WRITE",
    10: "FT_FAILED_TO_WRITE_DEVICE",
    11: "FT_EEPROM_READ_FAILED",
    12: "FT_EEPROM_WRITE_FAILED",
    13: "FT_EEPROM_ERASE_FAILED",
    14: "FT_EEPROM_NOT_PRESENT",
    15: "FT_EEPROM_NOT_PROGRAMMED",
    16: "FT_INVALID_ARGS",
    17: "FT_NOT_SUPPORTED",
    18: "FT_OTHER_ERROR",
    19: "FT_DEVICE_LIST_NOT_READY",
}


def as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


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
        if frame_type == DATA_FRAME and payload_len > 0 and payload_len <= MAX_DATA_PAYLOAD_BYTES and payload_len % DATA_PAYLOAD_BYTES == 0:
            records: list[dict[str, Any]] = []
            for record_index in range(payload_len // DATA_PAYLOAD_BYTES):
                record_payload = payload[record_index * DATA_PAYLOAD_BYTES : (record_index + 1) * DATA_PAYLOAD_BYTES]
                record = decode_data_payload(record_payload)
                record["sequence"] = sequence + record_index
                records.append(record)
            row["record_count"] = len(records)
            row["last_sequence"] = sequence + len(records) - 1
            row["records"] = records
        elif frame_type == START_FRAME and payload_len == 0:
            row["start_frame"] = True
        elif frame_type == STATUS_FRAME and payload_len == STATUS_PAYLOAD_BYTES:
            row.update(decode_status_payload(payload))
        else:
            errors.append(f"unexpected_frame_type=0x{frame_type:02x}/len={payload_len}")
        frames.append(row)
        index = magic_index + frame_len
    return frames, errors


def summarize_frames(
    frames: list[dict[str, Any]],
    errors: list[str],
    elapsed_seconds: float,
    raw_path: Path,
    frames_path: Path,
    stream_baud: int,
    receiver_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    data_frames = [row for row in frames if row.get("type") == DATA_FRAME]
    start_frames = [row for row in frames if row.get("type") == START_FRAME]
    status_frames = [row for row in frames if row.get("type") == STATUS_FRAME]
    data_records = [record for row in data_frames for record in row.get("records", []) if isinstance(record, dict)]
    sequence_errors: list[str] = []
    expected_seq = None
    for row in data_records:
        seq = int(row.get("sequence") or 0)
        if expected_seq is not None and seq != expected_seq:
            sequence_errors.append(f"expected={expected_seq} observed={seq}")
        expected_seq = seq + 1
    status = status_frames[-1] if status_frames else {}
    accepted_count = int(status.get("accepted_count") or len(data_records))
    dropped_count = int(status.get("dropped_count") or 0)
    payload_bytes = len(data_records) * DATA_PAYLOAD_BYTES
    framed_wire_bytes = sum(10 + int(row.get("payload_len") or 0) + 2 for row in frames)
    wire_time_lower_bound = (framed_wire_bytes * 10.0 / stream_baud) if stream_baud > 0 else 0.0
    effective_elapsed_seconds = max(elapsed_seconds, wire_time_lower_bound)
    sustained = payload_bytes / effective_elapsed_seconds if effective_elapsed_seconds > 0 else 0.0
    status_sequence_ok = bool(status_frames) and int(status.get("next_sequence") or -1) == accepted_count + dropped_count
    summary = {
        "schema": "rvmt.genesys2.uart_stream_host_receiver.v1",
        "transport": "uart_streaming_dma",
        "stream_baud": stream_baud,
        "parser_success": not errors and not sequence_errors and bool(status_frames) and status_sequence_ok,
        "start_frame_seen": bool(start_frames),
        "status_frame_seen": bool(status_frames),
        "status_sequence_ok": status_sequence_ok,
        "data_frame_count": len(data_frames),
        "data_record_count": len(data_records),
        "accepted_count": accepted_count,
        "accepted_count_matches_data_frames": accepted_count == len(data_records),
        "dropped_count": dropped_count,
        "sequence_error_count": len(sequence_errors),
        "crc_error_count": sum(1 for row in frames if row.get("crc_ok") is not True),
        "parse_errors": errors,
        "sequence_errors": sequence_errors,
        "payload_bytes": payload_bytes,
        "elapsed_seconds": effective_elapsed_seconds,
        "capture_elapsed_seconds": elapsed_seconds,
        "framed_wire_bytes": framed_wire_bytes,
        "wire_time_lower_bound_seconds": wire_time_lower_bound,
        "sustained_bytes_per_second": sustained,
        "raw_capture": str(raw_path).replace("\\", "/"),
        "frames_jsonl": str(frames_path).replace("\\", "/"),
    }
    if receiver_metadata:
        summary.update(receiver_metadata)
    return summary


def wait_for_token(stream: Any, token: str, timeout_seconds: float) -> bytes:
    token_bytes = token.encode("utf-8")
    chunks: list[bytes] = []
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        chunk = stream.read(4096)
        if not chunk:
            continue
        chunks.append(chunk)
        if token_bytes in b"".join(chunks):
            return b"".join(chunks)
    raise TimeoutError(f"timed out waiting for UART token: {token}")


class D2xxPort:
    def __init__(self, serial_number: str, timeout_ms: int = 50) -> None:
        self.serial_number = serial_number
        self.dll = ctypes.WinDLL("ftd2xx.dll")
        self.handle = ctypes.c_void_p()
        self._configure_prototypes()
        status = self.dll.FT_OpenEx(ctypes.c_char_p(serial_number.encode("ascii")), 1, ctypes.byref(self.handle))
        self.open_status = int(status)
        if status != 0:
            raise RuntimeError(f"FT_OpenEx({serial_number}) failed: {status_name(status)}")
        self._check("FT_SetUSBParameters", self.dll.FT_SetUSBParameters(self.handle, 65536, 65536))
        self._check("FT_SetTimeouts", self.dll.FT_SetTimeouts(self.handle, timeout_ms, 5000))
        self._check("FT_SetLatencyTimer", self.dll.FT_SetLatencyTimer(self.handle, 2))
        self._check("FT_SetDataCharacteristics", self.dll.FT_SetDataCharacteristics(self.handle, 8, 0, 0))
        self._check("FT_SetFlowControl", self.dll.FT_SetFlowControl(self.handle, 0, 0, 0))

    def _configure_prototypes(self) -> None:
        c_void_p = ctypes.c_void_p
        c_ulong = ctypes.c_ulong
        c_ubyte = ctypes.c_ubyte
        c_ushort = ctypes.c_ushort
        self.dll.FT_OpenEx.argtypes = [c_void_p, c_ulong, ctypes.POINTER(c_void_p)]
        self.dll.FT_OpenEx.restype = c_ulong
        self.dll.FT_Close.argtypes = [c_void_p]
        self.dll.FT_Close.restype = c_ulong
        self.dll.FT_SetUSBParameters.argtypes = [c_void_p, c_ulong, c_ulong]
        self.dll.FT_SetUSBParameters.restype = c_ulong
        self.dll.FT_SetTimeouts.argtypes = [c_void_p, c_ulong, c_ulong]
        self.dll.FT_SetTimeouts.restype = c_ulong
        self.dll.FT_SetLatencyTimer.argtypes = [c_void_p, c_ubyte]
        self.dll.FT_SetLatencyTimer.restype = c_ulong
        self.dll.FT_SetDataCharacteristics.argtypes = [c_void_p, c_ubyte, c_ubyte, c_ubyte]
        self.dll.FT_SetDataCharacteristics.restype = c_ulong
        self.dll.FT_SetFlowControl.argtypes = [c_void_p, c_ushort, c_ubyte, c_ubyte]
        self.dll.FT_SetFlowControl.restype = c_ulong
        self.dll.FT_SetBaudRate.argtypes = [c_void_p, c_ulong]
        self.dll.FT_SetBaudRate.restype = c_ulong
        self.dll.FT_Purge.argtypes = [c_void_p, c_ulong]
        self.dll.FT_Purge.restype = c_ulong
        self.dll.FT_Write.argtypes = [c_void_p, c_void_p, c_ulong, ctypes.POINTER(c_ulong)]
        self.dll.FT_Write.restype = c_ulong
        self.dll.FT_Read.argtypes = [c_void_p, c_void_p, c_ulong, ctypes.POINTER(c_ulong)]
        self.dll.FT_Read.restype = c_ulong

    def _check(self, name: str, status: int) -> None:
        if status != 0:
            raise RuntimeError(f"{name} failed: {status_name(status)}")

    def close(self) -> None:
        if self.handle and self.handle.value:
            self.dll.FT_Close(self.handle)
            self.handle = ctypes.c_void_p()

    def __enter__(self) -> "D2xxPort":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def set_baudrate(self, baud: int) -> int:
        return int(self.dll.FT_SetBaudRate(self.handle, baud))

    def purge_rx(self) -> int:
        return int(self.dll.FT_Purge(self.handle, 1))

    def purge_all(self) -> int:
        return int(self.dll.FT_Purge(self.handle, 3))

    def write(self, data: bytes) -> int:
        if not data:
            return 0
        buf = ctypes.create_string_buffer(data)
        written = ctypes.c_ulong()
        self._check("FT_Write", self.dll.FT_Write(self.handle, buf, len(data), ctypes.byref(written)))
        return int(written.value)

    def flush(self) -> None:
        return None

    def read(self, size: int) -> bytes:
        buf = ctypes.create_string_buffer(max(size, 1))
        read_count = ctypes.c_ulong()
        self._check("FT_Read", self.dll.FT_Read(self.handle, buf, max(size, 1), ctypes.byref(read_count)))
        return bytes(buf.raw[: read_count.value])


def status_name(status: int) -> str:
    return f"{FT_STATUS_NAMES.get(int(status), 'FT_UNKNOWN')}({int(status)})"


def wrap_stream_command(command: str, armed_token: str, arm_delay_seconds: float) -> str:
    delay = f"{arm_delay_seconds:g}"
    split_at = max(1, len(armed_token) // 2)
    token_a = armed_token[:split_at].replace("'", "'\\''")
    token_b = armed_token[split_at:].replace("'", "'\\''")
    return f"printf '%s%s\\n' '{token_a}' '{token_b}'; sleep {delay}; {command}"


def read_serial_capture(
    port: str,
    receiver_backend: str,
    ftdi_serial: str | None,
    console_baud: int,
    stream_baud: int,
    command: str | None,
    duration: float,
    switch_delay: float,
    armed_token: str,
    arm_timeout: float,
    command_arm_delay: float,
    wrap_command: bool,
    stop_on_status: bool,
) -> tuple[bytes, dict[str, Any]]:
    serial_module: Any | None = None
    if receiver_backend == "pyserial":
        try:
            import serial as serial_module  # type: ignore
        except Exception as exc:  # pragma: no cover - depends on host environment
            raise RuntimeError(f"pyserial is required for live UART capture: {exc}") from exc
    elif receiver_backend == "d2xx" and not ftdi_serial:
        raise RuntimeError("--ftdi-serial is required when --receiver-backend=d2xx")
    elif receiver_backend != "d2xx":
        raise RuntimeError(f"unsupported receiver backend: {receiver_backend}")
    chunks: list[bytes] = []
    first_byte_time: float | None = None
    last_byte_time: float | None = None
    receiver_metadata: dict[str, Any] = {
        "receiver_backend": receiver_backend,
        "serial_port": port if receiver_backend == "pyserial" else None,
        "ftdi_serial": ftdi_serial if receiver_backend == "d2xx" else None,
        "console_baud": console_baud,
        "switch_delay_seconds": switch_delay,
        "armed_token": armed_token if command else None,
        "armed_token_seen": None,
        "command_wrapped": False,
        "command_arm_delay_seconds": None,
    }
    deadline = time.monotonic() + duration
    capture_start = time.monotonic()
    status_stop_seen = False
    initial_baud = console_baud if command else stream_baud
    if receiver_backend == "pyserial":
        stream_context = serial_module.Serial(port, initial_baud, timeout=0.05, write_timeout=5)
    else:
        stream_context = D2xxPort(ftdi_serial or "")
    with stream_context as stream:
        if receiver_backend == "d2xx":
            receiver_metadata["ftdi_open_status"] = status_name(getattr(stream, "open_status", 0))
            initial_status = stream.set_baudrate(initial_baud)
            receiver_metadata["initial_baud_set_status"] = status_name(initial_status)
            if initial_status != 0:
                receiver_metadata["capture_aborted_reason"] = f"initial baud rejected by FTDI: {status_name(initial_status)}"
                receiver_metadata["status_stop_enabled"] = stop_on_status
                receiver_metadata["status_stop_seen"] = False
                receiver_metadata["raw_byte_count"] = 0
                receiver_metadata["capture_elapsed_seconds"] = 0.0
                return b"", receiver_metadata
        if command:
            command_to_send = wrap_stream_command(command, armed_token, command_arm_delay) if wrap_command else command
            receiver_metadata["command_wrapped"] = wrap_command
            receiver_metadata["command_arm_delay_seconds"] = command_arm_delay if wrap_command else 0.0
            if receiver_backend == "pyserial":
                stream.reset_input_buffer()
            else:
                stream.purge_all()
            stream.write(command_to_send.encode("utf-8") + b"\r\n")
            stream.flush()
            prelude = wait_for_token(stream, armed_token, arm_timeout)
            receiver_metadata["armed_token_seen"] = True
            receiver_metadata["console_prelude_bytes"] = len(prelude)
            if receiver_backend == "pyserial":
                stream.reset_input_buffer()
                stream.baudrate = stream_baud
                receiver_metadata["stream_baud_set_status"] = "pyserial_no_status"
                receiver_metadata["stream_baud_accepted"] = True
            else:
                stream.purge_rx()
                stream_status = stream.set_baudrate(stream_baud)
                receiver_metadata["stream_baud_set_status"] = status_name(stream_status)
                receiver_metadata["stream_baud_accepted"] = stream_status == 0
                if stream_status != 0:
                    receiver_metadata["capture_aborted_reason"] = f"stream baud rejected by FTDI: {status_name(stream_status)}"
                    receiver_metadata["status_stop_enabled"] = stop_on_status
                    receiver_metadata["status_stop_seen"] = False
                    receiver_metadata["raw_byte_count"] = 0
                    receiver_metadata["capture_elapsed_seconds"] = 0.0
                    return b"", receiver_metadata
            time.sleep(switch_delay)
            if receiver_backend == "pyserial":
                stream.reset_input_buffer()
            else:
                stream.purge_rx()
            capture_start = time.monotonic()
            deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            chunk = stream.read(65536)
            if chunk:
                now = time.monotonic()
                if first_byte_time is None:
                    first_byte_time = now
                last_byte_time = now
                chunks.append(chunk)
                if stop_on_status:
                    frames, _ = parse_frames(b"".join(chunks))
                    if any(row.get("type") == STATUS_FRAME and row.get("done") is True for row in frames):
                        status_stop_seen = True
                        break
    receiver_metadata["status_stop_enabled"] = stop_on_status
    receiver_metadata["status_stop_seen"] = status_stop_seen
    raw = b"".join(chunks)
    receiver_metadata["raw_byte_count"] = len(raw)
    receiver_metadata["capture_elapsed_seconds"] = time.monotonic() - capture_start
    if first_byte_time is not None and last_byte_time is not None:
        observed_span = max(last_byte_time - first_byte_time, 0.0)
        raw_wire_time = (len(raw) * 10.0 / stream_baud) if stream_baud > 0 else 0.0
        receiver_metadata["first_byte_after_capture_start_seconds"] = first_byte_time - capture_start
        receiver_metadata["last_byte_after_capture_start_seconds"] = last_byte_time - capture_start
        receiver_metadata["observed_byte_span_seconds"] = observed_span
        receiver_metadata["raw_wire_time_lower_bound_seconds"] = raw_wire_time
        receiver_metadata["line_rate_elapsed_seconds"] = max(observed_span, raw_wire_time)
    return raw, receiver_metadata


def write_capture_outputs(
    root: Path,
    out_dir_arg: Path,
    raw: bytes,
    elapsed_seconds: float,
    stream_baud: int,
    receiver_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    out_dir = repo_path(root, out_dir_arg)
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_path = out_dir / "uart_stream.raw"
    frames_path = out_dir / "uart_frames.jsonl"
    summary_path = out_dir / "host_receiver_log.json"
    raw_path.write_bytes(raw)
    frames, errors = parse_frames(raw)
    frames_path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in frames) + ("\n" if frames else ""), encoding="utf-8")
    summary = summarize_frames(frames, errors, elapsed_seconds, raw_path, frames_path, stream_baud, receiver_metadata)
    write_summary(root, summary_path, summary)
    return summary


def self_test() -> int:
    def frame(frame_type: int, seq: int, payload: bytes) -> bytes:
        header = MAGIC + bytes([frame_type, len(payload)]) + seq.to_bytes(4, "little")
        crc = crc16_ccitt(header + payload)
        return header + payload + crc.to_bytes(2, "little")

    data_payload = (0xC | (1 << 4) | (0x1010 << 36) | (0xB0000A11 << 68)).to_bytes(DATA_PAYLOAD_BYTES, "little")
    batched_payload = data_payload + data_payload
    status_payload = (2).to_bytes(8, "little") + (0).to_bytes(8, "little") + (2).to_bytes(4, "little") + (1).to_bytes(4, "little")
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        summary = write_capture_outputs(
            root,
            Path("capture"),
            frame(START_FRAME, 0, b"") + frame(DATA_FRAME, 0, batched_payload) + frame(STATUS_FRAME, 2, status_payload),
            0.1,
            12_000_000,
        )
        if not summary.get("parser_success") or summary.get("sustained_bytes_per_second", 0) <= 0:
            print("[FAIL] UART receiver PASS fixture rejected", file=sys.stderr)
            print(json.dumps(summary, indent=2), file=sys.stderr)
            return 1
        bad = bytearray(frame(DATA_FRAME, 0, batched_payload) + frame(STATUS_FRAME, 2, status_payload))
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
    parser.add_argument("--receiver-backend", choices=("pyserial", "d2xx"), default="pyserial")
    parser.add_argument("--ftdi-serial")
    parser.add_argument("--console-baud", type=int, default=115200)
    parser.add_argument("--stream-baud", type=int, default=12_000_000)
    parser.add_argument("--command")
    parser.add_argument("--duration", type=float, default=15.0)
    parser.add_argument("--switch-delay", type=float, default=0.02)
    parser.add_argument("--armed-token", default="RVMT_STREAM_ARMED")
    parser.add_argument("--arm-timeout", type=float, default=10.0)
    parser.add_argument("--command-arm-delay", type=float, default=1.0)
    parser.add_argument("--no-command-wrap", action="store_true")
    parser.add_argument("--no-stop-on-status", action="store_true")
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
        receiver_metadata: dict[str, Any] | None = None
    else:
        raw, receiver_metadata = read_serial_capture(
            args.port,
            args.receiver_backend,
            args.ftdi_serial,
            args.console_baud,
            args.stream_baud,
            args.command,
            args.duration,
            args.switch_delay,
            args.armed_token,
            args.arm_timeout,
            args.command_arm_delay,
            not args.no_command_wrap,
            not args.no_stop_on_status,
        )
        elapsed = as_float(receiver_metadata.get("line_rate_elapsed_seconds"), time.monotonic() - start)
    summary = write_capture_outputs(root, args.out_dir, raw, elapsed, args.stream_baud, receiver_metadata)
    path = repo_path(root, args.out_dir) / "host_receiver_log.json"
    status = "PASS" if summary.get("parser_success") else "FAIL"
    print(f"[{status}] wrote UART host receiver log to {path}")
    return 0 if summary.get("parser_success") else 1


if __name__ == "__main__":
    raise SystemExit(main())
