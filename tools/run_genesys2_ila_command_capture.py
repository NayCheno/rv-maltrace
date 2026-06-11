from __future__ import annotations

import argparse
import base64
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import TextIO


DEFAULT_VIVADO = Path(r"D:\Application\vivado\2025.2\Vivado\bin\vivado.bat")
DEFAULT_TCL = Path("tools/capture_genesys2_ila_event.tcl")
DEFAULT_LTX = Path("build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx.ltx")
DEFAULT_HW_SERVER = "localhost:3121"


def emit(handle: TextIO, text: str) -> None:
    sys.stdout.write(text)
    sys.stdout.flush()
    handle.write(text)
    handle.flush()


def read_for(ser, seconds: float, handle: TextIO) -> str:
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


def send_uart_commands(
    *,
    port: str,
    baud: int,
    commands: list[str],
    program_log: Path,
    pre_read: float,
    between_read: float,
    post_read: float,
    send_delay: float,
) -> None:
    try:
        import serial
    except ImportError as exc:  # pragma: no cover - exercised only on systems missing pyserial
        raise RuntimeError("pyserial is required for board UART command capture") from exc

    program_log.parent.mkdir(parents=True, exist_ok=True)
    with serial.Serial(port, baud, timeout=0.1, write_timeout=5) as ser, program_log.open(
        "w", encoding="utf-8", newline="\n", errors="replace"
    ) as handle:
        handle.write(
            f"RVMT_GENESYS2_ILA_COMMAND_CAPTURE_UART port={port} baud={baud} "
            f"start={time.strftime('%Y-%m-%dT%H:%M:%S%z')}\n"
        )
        handle.flush()
        if pre_read > 0:
            read_for(ser, pre_read, handle)
        for index, command in enumerate(commands):
            payload = command.encode("utf-8") + b"\r\n"
            ser.write(payload)
            ser.flush()
            emit(handle, f"\nRVMT_SEND {command!r}\n")
            if send_delay > 0:
                time.sleep(send_delay)
            read_for(ser, between_read if index + 1 < len(commands) else post_read, handle)
        handle.write("\nRVMT_GENESYS2_ILA_COMMAND_CAPTURE_UART_DONE\n")


def write_simulated_program_log(program_log: Path, commands: list[str]) -> None:
    program_log.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "RVMT_GENESYS2_ILA_COMMAND_CAPTURE_UART_SIM",
        f"start={time.strftime('%Y-%m-%dT%H:%M:%S%z')}",
    ]
    for command in commands:
        lines.append(f"RVMT_SEND {command!r}")
    lines.append("RVMT_GENESYS2_ILA_COMMAND_CAPTURE_UART_DONE")
    program_log.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def tee_pipe(pipe, handle: TextIO, armed: threading.Event, prefix: str = "") -> None:
    try:
        for line in iter(pipe.readline, ""):
            text = f"{prefix}{line}"
            handle.write(text)
            handle.flush()
            sys.stdout.write(text)
            sys.stdout.flush()
            if "RVMT_ILA_ARMED" in line:
                armed.set()
    finally:
        pipe.close()


def build_capture_command(args: argparse.Namespace) -> list[str]:
    if args.capture_command:
        return args.capture_command
    return [
        str(args.vivado),
        "-mode",
        "batch",
        "-source",
        str(args.tcl),
        "-tclargs",
        args.evt_hex,
        args.primary,
        str(args.csv),
        str(args.timeout_seconds),
        str(args.trigger_position),
        "1" if args.event_only_capture else "0",
        str(args.ltx),
        args.hw_server_url,
    ]


def decode_commands(args: argparse.Namespace) -> list[str]:
    commands = [base64.b64decode(value).decode("utf-8") for value in args.program_command_b64]
    commands.extend(args.program_command or [])
    return commands


def run_capture(args: argparse.Namespace) -> int:
    commands = decode_commands(args)
    if not commands:
        raise ValueError("at least one --program-command or --program-command-b64 is required")

    args.csv.parent.mkdir(parents=True, exist_ok=True)
    args.capture_log.parent.mkdir(parents=True, exist_ok=True)
    args.capture_err.parent.mkdir(parents=True, exist_ok=True)
    capture_command = build_capture_command(args)
    armed = threading.Event()
    with args.capture_log.open("w", encoding="utf-8", newline="\n", errors="replace") as stdout_log, args.capture_err.open(
        "w", encoding="utf-8", newline="\n", errors="replace"
    ) as stderr_log:
        stdout_log.write(
            "RVMT_GENESYS2_ILA_COMMAND_CAPTURE\n"
            f"command={' '.join(capture_command)}\n"
            f"csv={args.csv}\n"
            f"start={time.strftime('%Y-%m-%dT%H:%M:%S%z')}\n"
        )
        stdout_log.flush()
        process = subprocess.Popen(
            capture_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assert process.stdout is not None
        assert process.stderr is not None
        stdout_thread = threading.Thread(target=tee_pipe, args=(process.stdout, stdout_log, armed), daemon=True)
        stderr_thread = threading.Thread(target=tee_pipe, args=(process.stderr, stderr_log, armed, "STDERR: "), daemon=True)
        stdout_thread.start()
        stderr_thread.start()

        if not armed.wait(args.arm_timeout):
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            stdout_thread.join(timeout=2)
            stderr_thread.join(timeout=2)
            stdout_log.write("RVMT_ILA_ARM_TIMEOUT\n")
            return 3

        if args.serial_sim:
            write_simulated_program_log(args.program_log, commands)
        else:
            send_uart_commands(
                port=args.port,
                baud=args.baud,
                commands=commands,
                program_log=args.program_log,
                pre_read=args.pre_read,
                between_read=args.between_read,
                post_read=args.post_read,
                send_delay=args.send_delay,
            )

        try:
            returncode = process.wait(timeout=args.process_wait_timeout)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            returncode = 8
        stdout_thread.join(timeout=2)
        stderr_thread.join(timeout=2)
        stdout_log.write(f"RVMT_CAPTURE_PROCESS_RETURNCODE={returncode}\n")

    if returncode != 0:
        return returncode
    if args.decode_out:
        decode_cmd = [
            sys.executable,
            "tools/decode_genesys2_ila_trace.py",
            "--csv",
            str(args.csv),
            "--out",
            str(args.decode_out),
        ]
        result = subprocess.run(decode_cmd, cwd=args.root)
        if result.returncode != 0:
            return result.returncode
    print(f"[PASS] Genesys2 ILA command capture complete: {args.csv}")
    return 0


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        fake = root / "fake_capture.py"
        csv = root / "capture.csv"
        fake.write_text(
            "from pathlib import Path\n"
            "import sys, time\n"
            "csv = Path(sys.argv[1])\n"
            "print('RVMT_ILA_ARMED', flush=True)\n"
            "time.sleep(0.1)\n"
            "csv.write_text('Time,probe0,probe1\\n0,1,4\\n', encoding='utf-8')\n"
            "print('RVMT_ILA_CAPTURE_DONE', flush=True)\n",
            encoding="utf-8",
        )
        args = argparse.Namespace(
            root=root,
            capture_command=[sys.executable, str(fake), str(csv)],
            vivado=DEFAULT_VIVADO,
            tcl=DEFAULT_TCL,
            evt_hex="4",
            primary="40",
            csv=csv,
            timeout_seconds=5,
            trigger_position=0,
            event_only_capture=True,
            ltx=DEFAULT_LTX,
            hw_server_url=DEFAULT_HW_SERVER,
            capture_log=root / "capture.log",
            capture_err=root / "capture.err",
            program_log=root / "program.log",
            program_command=["echo RVMT_P2_RUN_START; true; echo RVMT_P2_RUN_DONE"],
            program_command_b64=[],
            port="COM7",
            baud=115200,
            pre_read=0.0,
            between_read=0.1,
            post_read=0.1,
            send_delay=0.0,
            arm_timeout=2.0,
            process_wait_timeout=5.0,
            serial_sim=True,
            decode_out=None,
        )
        rc = run_capture(args)
        if rc != 0:
            print(f"[FAIL] self-test capture returned {rc}", file=sys.stderr)
            return 1
        if "RVMT_ILA_ARMED" not in args.capture_log.read_text(encoding="utf-8"):
            print("[FAIL] self-test capture log missed armed marker", file=sys.stderr)
            return 1
        if "RVMT_SEND" not in args.program_log.read_text(encoding="utf-8"):
            print("[FAIL] self-test program log missed command marker", file=sys.stderr)
            return 1
        if not csv.exists():
            print("[FAIL] self-test missed CSV output", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 ILA command capture self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Arm a Genesys2 ILA trigger, run a UART command, and optionally decode the capture.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--vivado", type=Path, default=DEFAULT_VIVADO)
    parser.add_argument("--tcl", type=Path, default=DEFAULT_TCL)
    parser.add_argument("--evt-hex", required=False)
    parser.add_argument("--primary", default="X")
    parser.add_argument("--csv", type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    parser.add_argument("--trigger-position", type=int, default=0)
    parser.add_argument("--event-only-capture", action="store_true")
    parser.add_argument("--ltx", type=Path, default=DEFAULT_LTX)
    parser.add_argument("--hw-server-url", default=DEFAULT_HW_SERVER)
    parser.add_argument("--capture-log", type=Path)
    parser.add_argument("--capture-err", type=Path)
    parser.add_argument("--program-log", type=Path)
    parser.add_argument("--program-command", action="append", default=[])
    parser.add_argument("--program-command-b64", action="append", default=[])
    parser.add_argument("--port", default="COM7")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--pre-read", type=float, default=0.0)
    parser.add_argument("--between-read", type=float, default=0.5)
    parser.add_argument("--post-read", type=float, default=8.0)
    parser.add_argument("--send-delay", type=float, default=0.0)
    parser.add_argument("--arm-timeout", type=float, default=30.0)
    parser.add_argument("--process-wait-timeout", type=float, default=180.0)
    parser.add_argument("--decode-out", type=Path)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--serial-sim", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--capture-command", nargs="+", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    missing = [
        name
        for name, value in (
            ("--evt-hex", args.evt_hex),
            ("--csv", args.csv),
            ("--capture-log", args.capture_log),
            ("--capture-err", args.capture_err),
            ("--program-log", args.program_log),
        )
        if value is None
    ]
    if missing:
        parser.error("missing required arguments: " + ", ".join(missing))
    try:
        args.root = args.root.resolve()
        return run_capture(args)
    except Exception as exc:
        print(f"run_genesys2_ila_command_capture: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
