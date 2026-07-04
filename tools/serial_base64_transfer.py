from __future__ import annotations

import argparse
import base64
import hashlib
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


def read_until_token(ser: serial.Serial, seconds: float, handle, token: str) -> str:
    deadline = time.time() + seconds
    chunks: list[str] = []
    combined = ""
    while time.time() < deadline:
        data = ser.read(4096)
        if not data:
            continue
        text = data.decode("utf-8", errors="replace")
        chunks.append(text)
        combined += text
        emit(handle, text)
        if token in combined:
            return combined
    raise TimeoutError(f"timed out waiting for serial prompt token {token!r}")


def write_limited(ser: serial.Serial, text: str, *, line_delay: float, char_delay: float) -> None:
    if char_delay > 0:
        for char in text:
            ser.write(char.encode("utf-8"))
            ser.flush()
            time.sleep(char_delay)
        if line_delay > 0:
            time.sleep(line_delay)
    elif line_delay > 0:
        for line in text.splitlines(keepends=True):
            ser.write(line.encode("utf-8"))
            ser.flush()
            time.sleep(line_delay)
    else:
        ser.write(text.encode("utf-8"))
        ser.flush()


def send_text(
    ser: serial.Serial,
    handle,
    text: str,
    *,
    post_read: float = 0.1,
    line_delay: float = 0.0,
    char_delay: float = 0.0,
) -> str:
    write_limited(ser, text, line_delay=line_delay, char_delay=char_delay)
    return read_for(ser, post_read, handle)


def send_text_wait(
    ser: serial.Serial,
    handle,
    text: str,
    *,
    post_read: float,
    line_delay: float,
    char_delay: float,
    prompt_token: str,
) -> str:
    write_limited(ser, text, line_delay=line_delay, char_delay=char_delay)
    if prompt_token:
        return read_until_token(ser, post_read, handle, prompt_token)
    return read_for(ser, post_read, handle)


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
    parser.add_argument("--line-delay", type=float, default=0.0)
    parser.add_argument("--send-char-delay", type=float, default=0.0)
    parser.add_argument("--prompt-token", default="")
    parser.add_argument("--disable-echo", action="store_true")
    args = parser.parse_args()

    source = args.source
    if not source.exists():
        parser.error(f"source does not exist: {source}")
    if args.chunk_lines <= 0:
        parser.error("--chunk-lines must be positive")

    data = source.read_bytes()
    expected_sha256 = hashlib.sha256(data).hexdigest()
    expected_size = len(data)
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
        if args.disable_echo:
            emit(handle, "\nRVMT_SEND 'stty -echo'\n")
            send_text_wait(
                ser,
                handle,
                "stty -echo\r\n",
                post_read=max(args.chunk_read, 1.0),
                line_delay=args.line_delay,
                char_delay=args.send_char_delay,
                prompt_token=args.prompt_token,
            )
        for command in [
            f"mkdir -p {shell_quote(target_dir)}\r\n",
            f"rm -f {shell_quote(target_b64)} {shell_quote(target)}\r\n",
        ]:
            emit(handle, f"\nRVMT_SEND {command.strip()!r}\n")
            send_text_wait(
                ser,
                handle,
                command,
                post_read=max(args.chunk_read, 1.0),
                line_delay=args.line_delay,
                char_delay=args.send_char_delay,
                prompt_token=args.prompt_token,
            )

        try:
            for index in range(0, len(lines), args.chunk_lines):
                chunk = lines[index : index + args.chunk_lines]
                marker = f"RVMT_B64_{index // args.chunk_lines:05d}"
                payload = (
                    f"cat >> {shell_quote(target_b64)} <<'{marker}'\n"
                    + "\n".join(chunk)
                    + f"\n{marker}\n"
                )
                emit(handle, f"\nRVMT_SEND_CHUNK index={index // args.chunk_lines} lines={len(chunk)}\n")
                send_text_wait(
                    ser,
                    handle,
                    payload,
                    post_read=args.chunk_read,
                    line_delay=args.line_delay,
                    char_delay=args.send_char_delay,
                    prompt_token=args.prompt_token,
                )
        except Exception:
            ser.write(b"\x03\r\nstty echo\r\n")
            ser.flush()
            read_for(ser, 1.0, handle)
            raise

        final_command = (
            f"base64 -d {shell_quote(target_b64)} > {shell_quote(target)} && "
            f"chmod +x {shell_quote(target)} && "
            f"actual_sha=$(sha256sum {shell_quote(target)} | awk '{{print $1}}') && "
            f"actual_size=$(wc -c < {shell_quote(target)} | tr -d ' ') && "
            f"echo RVMT_TRANSFER_SHA256=$actual_sha && "
            f"echo RVMT_TRANSFER_SIZE=$actual_size && "
            f"ls -l {shell_quote(target)} && "
            f"if [ \"$actual_sha\" = {shell_quote(expected_sha256)} ] && "
            f"[ \"$actual_size\" = {shell_quote(str(expected_size))} ]; then "
            "echo RVMT_TRANSFER_VERIFY=PASS; "
            f"rm -f {shell_quote(target_b64)}; "
            "else "
            f"echo RVMT_TRANSFER_VERIFY=FAIL expected_sha256={expected_sha256} expected_size={expected_size}; "
            "fi\r\n"
        )
        emit(handle, f"\nRVMT_SEND {final_command.strip()!r}\n")
        final_output = send_text_wait(
            ser,
            handle,
            final_command,
            post_read=args.final_read,
            line_delay=args.line_delay,
            char_delay=args.send_char_delay,
            prompt_token=args.prompt_token,
        )
        transfer_verified = "RVMT_TRANSFER_VERIFY=PASS" in final_output
        if args.disable_echo:
            emit(handle, "\nRVMT_SEND 'stty echo'\n")
            send_text(
                ser,
                handle,
                "stty echo\r\n",
                post_read=0.5,
                line_delay=args.line_delay,
                char_delay=args.send_char_delay,
            )
        handle.write("\nRVMT_SERIAL_BASE64_TRANSFER_DONE\n")
        if not transfer_verified:
            raise RuntimeError(
                f"board transfer verification failed for {target}: "
                f"expected sha256={expected_sha256} size={expected_size}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
