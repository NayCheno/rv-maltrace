from __future__ import annotations

import argparse
import base64
import sys
import time
from pathlib import Path

import serial


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


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


def send_text(ser: serial.Serial, handle, text: str, *, post_read: float = 0.1) -> None:
    ser.write(text.encode("utf-8"))
    ser.flush()
    read_for(ser, post_read, handle)


def wrap_base64(data: bytes, width: int = 76) -> list[str]:
    encoded = base64.b64encode(data).decode("ascii")
    return [encoded[index : index + width] for index in range(0, len(encoded), width)]


def main() -> int:
    parser = argparse.ArgumentParser(description="Transfer a local file to a board shell via UART/base64.")
    parser.add_argument("--port", default="COM7")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--chunk-lines", type=int, default=64)
    parser.add_argument("--initial-read", type=float, default=0.5)
    parser.add_argument("--chunk-read", type=float, default=0.05)
    parser.add_argument("--final-read", type=float, default=6.0)
    args = parser.parse_args()

    source = args.source
    if not source.exists():
        parser.error(f"source does not exist: {source}")
    if args.chunk_lines <= 0:
        parser.error("--chunk-lines must be positive")

    data = source.read_bytes()
    lines = wrap_base64(data)
    target = args.target
    target_b64 = f"{target}.b64"
    target_dir = str(Path(target).parent).replace("\\", "/")

    args.log.parent.mkdir(parents=True, exist_ok=True)
    with serial.Serial(args.port, args.baud, timeout=0.1, write_timeout=10) as ser, args.log.open(
        "w", encoding="utf-8", newline="\n", errors="replace"
    ) as handle:
        handle.write(
            f"RVMT_SERIAL_BASE64_TRANSFER port={args.port} baud={args.baud} "
            f"source={source} target={target} bytes={len(data)} base64_lines={len(lines)} "
            f"start={time.strftime('%Y-%m-%dT%H:%M:%S%z')}\n"
        )
        handle.flush()
        read_for(ser, args.initial_read, handle)
        for command in [
            f"mkdir -p {shell_quote(target_dir)}\r\n",
            f"rm -f {shell_quote(target_b64)} {shell_quote(target)}\r\n",
        ]:
            emit(handle, f"\nRVMT_SEND {command.strip()!r}\n")
            send_text(ser, handle, command, post_read=0.3)

        for index in range(0, len(lines), args.chunk_lines):
            chunk = lines[index : index + args.chunk_lines]
            marker = f"RVMT_B64_{index // args.chunk_lines:05d}"
            payload = (
                f"cat >> {shell_quote(target_b64)} <<'{marker}'\n"
                + "\n".join(chunk)
                + f"\n{marker}\n"
            )
            emit(handle, f"\nRVMT_SEND_CHUNK index={index // args.chunk_lines} lines={len(chunk)}\n")
            send_text(ser, handle, payload, post_read=args.chunk_read)

        final_command = (
            f"base64 -d {shell_quote(target_b64)} > {shell_quote(target)} && "
            f"chmod +x {shell_quote(target)} && "
            f"sha256sum {shell_quote(target)} && "
            f"ls -l {shell_quote(target)} && "
            f"rm -f {shell_quote(target_b64)}\r\n"
        )
        emit(handle, f"\nRVMT_SEND {final_command.strip()!r}\n")
        send_text(ser, handle, final_command, post_read=args.final_read)
        handle.write("\nRVMT_SERIAL_BASE64_TRANSFER_DONE\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
