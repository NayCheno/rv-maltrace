from __future__ import annotations

import argparse
import base64
import sys
import time
from pathlib import Path

import serial


def emit(handle, text: str) -> None:
    sys.stdout.write(text)
    sys.stdout.flush()
    handle.write(text)
    handle.flush()


def read_for(ser: serial.Serial, seconds: float, handle) -> str:
    deadline = time.time() + seconds
    chunks: list[str] = []
    while time.time() < deadline:
        data = ser.read(4096)
        if not data:
            continue
        text = data.decode("utf-8", errors="replace")
        chunks.append(text)
        emit(handle, text)
    return "".join(chunks)


def read_until_prompt(ser: serial.Serial, timeout: float, idle_after_prompt: float, handle) -> str:
    deadline = time.time() + timeout
    chunks: list[str] = []
    prompt_seen_at: float | None = None
    while time.time() < deadline:
        data = ser.read(4096)
        now = time.time()
        if not data:
            if prompt_seen_at is not None and now - prompt_seen_at >= idle_after_prompt:
                break
            continue
        text = data.decode("utf-8", errors="replace")
        chunks.append(text)
        emit(handle, text)
        normalized = "".join(chunks).replace("\r\n", "\n").replace("\r", "\n")
        if normalized.endswith("\n# ") or normalized.endswith("\n# \n"):
            prompt_seen_at = now
    return "".join(chunks)


def main() -> int:
    parser = argparse.ArgumentParser(description="Send UART commands without prompt-probing traffic and capture output.")
    parser.add_argument("--port", default="COM7")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--pre-read", type=float, default=0.0)
    parser.add_argument("--post-read", type=float, default=6.0)
    parser.add_argument("--between-read", type=float, default=0.5)
    parser.add_argument("--send-delay", type=float, default=0.0)
    parser.add_argument("--send-char-delay", type=float, default=0.0)
    parser.add_argument("--read-until-prompt", action="store_true")
    parser.add_argument("--prompt-idle", type=float, default=0.2)
    parser.add_argument("--command-b64", action="append", default=[], help="UTF-8 command encoded as base64. May repeat.")
    parser.add_argument("commands", nargs="*")
    args = parser.parse_args()
    commands = [base64.b64decode(command).decode("utf-8") for command in args.command_b64] + args.commands
    if not commands:
        parser.error("at least one command or --command-b64 is required")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with serial.Serial(args.port, args.baud, timeout=0.1, write_timeout=5) as ser, args.out.open(
        "w", encoding="utf-8", newline="\n", errors="replace"
    ) as handle:
        handle.write(
            f"RVMT_SERIAL_DIRECT_COMMAND_CAPTURE port={args.port} baud={args.baud} "
            f"start={time.strftime('%Y-%m-%dT%H:%M:%S%z')}\n"
        )
        handle.flush()
        if args.pre_read > 0:
            read_for(ser, args.pre_read, handle)
        for index, command in enumerate(commands):
            payload = command.encode("utf-8") + b"\r\n"
            if args.send_char_delay > 0:
                for byte in payload:
                    ser.write(bytes([byte]))
                    ser.flush()
                    time.sleep(args.send_char_delay)
            else:
                ser.write(payload)
                ser.flush()
            emit(handle, f"\nRVMT_SEND {command!r}\n")
            if args.send_delay > 0:
                time.sleep(args.send_delay)
            read_seconds = args.between_read if index + 1 < len(commands) else args.post_read
            if args.read_until_prompt:
                read_until_prompt(ser, read_seconds, args.prompt_idle, handle)
            else:
                read_for(ser, read_seconds, handle)
        handle.write("\nRVMT_SERIAL_DIRECT_COMMAND_CAPTURE_DONE\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
