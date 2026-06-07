from __future__ import annotations

import argparse
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

import serial


def append_text(path: Path, text: str) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def main() -> int:
    parser = argparse.ArgumentParser(description="Load a CVA6 payload through the FPGA boot ROM UART update path.")
    parser.add_argument("--port", default="COM6")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--payload", required=True, type=Path)
    parser.add_argument("--vivado", required=True, type=Path)
    parser.add_argument("--program-tcl", required=True, type=Path)
    parser.add_argument("--serial-log", required=True, type=Path)
    parser.add_argument("--program-log", required=True, type=Path)
    parser.add_argument("--timeout-s", type=float, default=45.0)
    args = parser.parse_args()

    payload = args.payload.read_bytes()
    if not payload:
        raise SystemExit("empty payload")

    args.serial_log.parent.mkdir(parents=True, exist_ok=True)
    args.program_log.parent.mkdir(parents=True, exist_ok=True)
    args.serial_log.write_text("", encoding="utf-8", newline="\n")
    args.program_log.write_text("", encoding="utf-8", newline="\n")

    marker = b"RVMT_BAREMETAL_PASS"
    buffer = bytearray()
    sent_trigger = False
    sent_payload = False
    done = False
    program_rc: int | None = None
    program_proc: subprocess.Popen[str] | None = None
    program_done = threading.Event()
    lock = threading.Lock()
    start = time.monotonic()

    with serial.Serial(args.port, args.baud, bytesize=8, parity="N", stopbits=1, timeout=0.02, write_timeout=5) as ser:
        append_text(args.serial_log, f"RVMT_SERIAL_OPEN port={args.port} baud={args.baud} 8N1\n")

        def reader() -> None:
            nonlocal done
            while not done:
                chunk = ser.read(256)
                if chunk:
                    with lock:
                        buffer.extend(chunk)
                    append_text(args.serial_log, chunk.decode("utf-8", errors="replace"))

        thread = threading.Thread(target=reader, daemon=True)
        thread.start()

        def programmer() -> None:
            nonlocal program_rc, program_proc
            cmd = [
                str(args.vivado),
                "-mode",
                "batch",
                "-source",
                str(args.program_tcl),
            ]
            append_text(args.program_log, "RVMT_PROGRAM_COMMAND=" + " ".join(cmd) + "\n")
            program_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
            assert program_proc.stdout is not None
            for line in program_proc.stdout:
                append_text(args.program_log, line)
            program_rc = program_proc.wait()
            append_text(args.program_log, f"RVMT_PROGRAM_EXIT={program_rc}\n")
            program_done.set()

        program_thread = threading.Thread(target=programmer, daemon=True)
        program_thread.start()

        deadline = start + args.timeout_s
        while time.monotonic() < deadline:
            with lock:
                text = bytes(buffer)

            if program_done.is_set() and program_rc != 0:
                done = True
                thread.join(timeout=1)
                program_thread.join(timeout=1)
                return 2

            if (not sent_trigger) and (
                b"Hello World!" in text
                or b"Hit any key" in text
                or b"any key" in text
                or b"update mode" in text
            ):
                ser.write(b"x")
                ser.flush()
                append_text(args.serial_log, "\nRVMT_HOST_SENT_UPDATE_TRIGGER=0x78\n")
                sent_trigger = True

            if sent_trigger and (not sent_payload) and (b"size:" in text or b"updating!" in text):
                ser.write(struct.pack("<I", len(payload)))
                ser.flush()
                time.sleep(0.05)
                for byte in payload:
                    ser.write(bytes([byte]))
                    ser.flush()
                    time.sleep(0.002)
                append_text(args.serial_log, f"\nRVMT_HOST_SENT_PAYLOAD_BYTES={len(payload)}\n")
                sent_payload = True

            if marker in text:
                append_text(args.serial_log, "\nRVMT_UART_MARKER_FOUND=RVMT_BAREMETAL_PASS\n")
                done = True
                thread.join(timeout=1)
                return 0

            time.sleep(0.02)

        done = True
        if program_proc is not None and program_proc.poll() is None:
            program_proc.terminate()
        thread.join(timeout=1)
        program_thread.join(timeout=1)
        append_text(
            args.serial_log,
            "\nRVMT_UART_MARKER_MISSING "
            f"sent_trigger={sent_trigger} sent_payload={sent_payload} payload_bytes={len(payload)}\n",
        )
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
