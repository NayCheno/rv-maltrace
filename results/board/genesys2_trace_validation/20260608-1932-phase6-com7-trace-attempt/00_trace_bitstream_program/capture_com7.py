import sys
import time

import serial

port = "COM7"
baud = 115200
duration = 90.0
out = r"D:\Code\research\rv-maltrace\results\board\genesys2_trace_validation\20260608-1932-phase6-com7-trace-attempt\00_trace_bitstream_program\serial.log"

start = time.time()
with serial.Serial(port, baud, timeout=0.2) as ser, open(
    out, "w", encoding="utf-8", newline="\n", errors="replace"
) as f:
    f.write(
        f"RVMT_SERIAL_CAPTURE port={port} baud={baud} framing=8N1 "
        f"duration={duration} start={time.strftime('%Y-%m-%dT%H:%M:%S%z')}\n"
    )
    while time.time() - start < duration:
        data = ser.read(4096)
        if data:
            text = data.decode("utf-8", errors="replace")
            sys.stdout.write(text)
            sys.stdout.flush()
            f.write(text)
            f.flush()
    f.write(f"\nRVMT_SERIAL_CAPTURE_DONE elapsed={time.time() - start:.3f}\n")
