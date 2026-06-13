from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path
from typing import Any

from check_genesys2_external_closure_intake import EXPECTED_EXTERNAL_SUMMARIES, validate_external_summary
from external_closure_artifacts import (
    ROOT,
    evidence_rows,
    external_record_root,
    load_json,
    repo_path,
    repo_relative,
    write_json_artifact,
    write_summary,
    write_text_artifact,
)


RECORD_ID = "production_streaming_dma_trace_sink"
DEFAULT_OUT = EXPECTED_EXTERNAL_SUMMARIES[RECORD_ID]["path"]
DEFAULT_HOST_LOG = Path("results/board/genesys2_trace_validation/20260613-uart-streaming-dma/host_receiver_log.json")
DEFAULT_TARGET = Path("results/evaluation/genesys2-cva6/current/streaming_dma_target_summary.json")


def as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def report_passed(path: Path, positive_tokens: tuple[str, ...]) -> bool:
    if not path.is_file():
        return False
    text = path.read_text(encoding="utf-8", errors="replace").lower()
    negative = ("timing failed", "timing_passed=false", "noninterference_passed=false", "failed=true")
    return any(token in text for token in positive_tokens) and not any(token in text for token in negative)


def p95_bytes_per_second(root: Path, target_path_arg: Path, trace_clock_hz: float, override: float | None) -> tuple[float, float]:
    if override is not None:
        return override, 0.0
    target_path = repo_path(root, target_path_arg)
    target = load_json(target_path)
    throughput_target = target.get("throughput_target") if isinstance(target.get("throughput_target"), dict) else {}
    p95_per_cycle = as_float(throughput_target.get("p95_event_bytes_per_cycle"))
    return p95_per_cycle * trace_clock_hz, p95_per_cycle


def package_summary(
    root: Path,
    host_log_arg: Path,
    timing_report_arg: Path,
    resource_report_arg: Path,
    noninterference_report_arg: Path,
    trace_clock_hz: float,
    target_arg: Path,
    p95_override: float | None,
) -> dict[str, Any]:
    record_root = external_record_root(root, RECORD_ID)
    host_log_path = repo_path(root, host_log_arg)
    timing_report = repo_path(root, timing_report_arg)
    resource_report = repo_path(root, resource_report_arg)
    noninterference_report = repo_path(root, noninterference_report_arg)
    failures: list[str] = []
    host_log = load_json(host_log_path) if host_log_path.is_file() else {}
    if not host_log_path.is_file():
        failures.append("host_receiver_log missing")
    if host_log.get("transport") != "uart_streaming_dma":
        failures.append("host_receiver_log transport is not uart_streaming_dma")
    if host_log.get("parser_success") is not True:
        failures.append("host receiver parser_success is not true")
    if host_log.get("status_frame_seen") is not True:
        failures.append("UART status/end frame was not observed")
    if int(as_float(host_log.get("dropped_count"), -1)) != 0:
        failures.append("UART status dropped_count is nonzero")
    if int(as_float(host_log.get("sequence_error_count"), -1)) != 0:
        failures.append("UART sequence_error_count is nonzero")
    if int(as_float(host_log.get("crc_error_count"), -1)) != 0:
        failures.append("UART crc_error_count is nonzero")
    if host_log.get("accepted_count_matches_data_frames") is not True:
        failures.append("UART accepted_count does not match received data frames")

    p95_bps, p95_per_cycle = p95_bytes_per_second(root, target_arg, trace_clock_hz, p95_override)
    sustained = as_float(host_log.get("sustained_bytes_per_second"))
    if sustained <= p95_bps:
        failures.append(f"sustained_bytes_per_second {sustained:.3f} <= p95 target {p95_bps:.3f}")
    timing_passed = report_passed(timing_report, ("timing_passed=true", "timing passed", "timing closure passed"))
    noninterference_passed = report_passed(noninterference_report, ("noninterference_passed=true", "noninterference passed"))
    if not timing_passed:
        failures.append("timing report does not prove timing_passed=true")
    if not resource_report.is_file():
        failures.append("resource report missing")
    if not noninterference_passed:
        failures.append("noninterference report does not prove noninterference_passed=true")

    artifacts = {
        "transport_design_manifest": write_json_artifact(
            root,
            RECORD_ID,
            "transport_design_manifest",
            {
                "transport": "uart_streaming_dma",
                "console_control_baud": 115200,
                "stream_baud": int(host_log.get("stream_baud") or 12_000_000),
                "compact_trace_record_bytes": 17,
                "status_frame_required": True,
                "rtl_source": "rtl/trace/trace_uart_stream_sink.sv",
            },
        ),
        "host_receiver_log": write_json_artifact(root, RECORD_ID, "host_receiver_log", host_log or {"missing": str(host_log_arg)}),
        "timing_report": write_text_artifact(
            root,
            RECORD_ID,
            "timing_report",
            timing_report.read_text(encoding="utf-8", errors="replace") if timing_report.is_file() else "MISSING timing report",
        ),
        "resource_report": write_text_artifact(
            root,
            RECORD_ID,
            "resource_report",
            resource_report.read_text(encoding="utf-8", errors="replace") if resource_report.is_file() else "MISSING resource report",
        ),
        "noninterference_report": write_text_artifact(
            root,
            RECORD_ID,
            "noninterference_report",
            noninterference_report.read_text(encoding="utf-8", errors="replace") if noninterference_report.is_file() else "MISSING noninterference report",
        ),
    }
    unaccounted_drop = int(as_float(host_log.get("dropped_count"), 0)) + int(as_float(host_log.get("sequence_error_count"), 0)) + int(as_float(host_log.get("crc_error_count"), 0))
    status = "PASS" if not failures else "FAIL"
    return {
        "schema": "rvmt.genesys2.streaming_dma_throughput.v1",
        "status": status,
        "evidence_artifacts": evidence_rows(root, artifacts),
        "claim_boundary": {
            "real_malware_validation_claimed": False,
            "production_streaming_dma_throughput_claimed": status == "PASS",
            "bram_jtag_substituted_for_streaming": False,
        },
        "transport": "uart_streaming_dma",
        "sustained_bytes_per_second": sustained,
        "p95_event_bytes_per_second": p95_bps,
        "p95_event_bytes_per_cycle": p95_per_cycle,
        "trace_clock_hz": trace_clock_hz,
        "unaccounted_drop": unaccounted_drop,
        "timing_passed": timing_passed,
        "noninterference_passed": noninterference_passed,
        "host_receiver_log_present": host_log_path.is_file(),
        "resource_report_present": resource_report.is_file(),
        "failed_attempts_retained": True,
        "failed_attempts": failures,
        "record_root": repo_relative(root, record_root),
        "validation_commands": [
            "uv run python tools/run_genesys2_uart_streaming_capture.py --port COM7 --stream-baud 12000000 --command <marker-window-command>",
            "uv run python tools/package_genesys2_streaming_dma_throughput.py --host-receiver-log <host_receiver_log.json> --trace-clock-hz <exact-hz> --timing-report <timing> --resource-report <resource> --noninterference-report <noninterference>",
            "uv run python tools/check_genesys2_streaming_dma_throughput.py --root .",
        ],
    }


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        host = root / "host_receiver_log.json"
        host.write_text(
            "{\n"
            '  "schema": "rvmt.genesys2.uart_stream_host_receiver.v1",\n'
            '  "transport": "uart_streaming_dma",\n'
            '  "parser_success": true,\n'
            '  "status_frame_seen": true,\n'
            '  "accepted_count_matches_data_frames": true,\n'
            '  "stream_baud": 12000000,\n'
            '  "dropped_count": 0,\n'
            '  "sequence_error_count": 0,\n'
            '  "crc_error_count": 0,\n'
            '  "sustained_bytes_per_second": 1200000\n'
            "}\n",
            encoding="utf-8",
        )
        timing = root / "timing.txt"
        timing.write_text("timing_passed=true\n", encoding="utf-8")
        resource = root / "resource.txt"
        resource.write_text("resource_report_present=true\n", encoding="utf-8")
        noninterference = root / "noninterference.txt"
        noninterference.write_text("noninterference_passed=true\n", encoding="utf-8")
        target = root / "target.json"
        target.write_text('{"throughput_target":{"p95_event_bytes_per_cycle":0.01}}\n', encoding="utf-8")
        summary = package_summary(root, host, timing, resource, noninterference, 50_000_000, target, None)
        errors = validate_external_summary(RECORD_ID, summary, root)
        if errors:
            print("[FAIL] streaming throughput PASS fixture rejected", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        bad = package_summary(root, host, timing, resource, noninterference, 200_000_000, target, None)
        if not validate_external_summary(RECORD_ID, bad, root):
            print("[FAIL] insufficient throughput fixture accepted", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 streaming DMA throughput packager self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package UART streaming/DMA throughput evidence for Genesys2 external closure intake.")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--host-receiver-log", type=Path, default=DEFAULT_HOST_LOG)
    parser.add_argument("--timing-report", type=Path)
    parser.add_argument("--resource-report", type=Path)
    parser.add_argument("--noninterference-report", type=Path)
    parser.add_argument("--trace-clock-hz", type=float)
    parser.add_argument("--target", type=Path, default=DEFAULT_TARGET)
    parser.add_argument("--p95-event-bytes-per-second", type=float)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    missing = [
        name
        for name in ("timing_report", "resource_report", "noninterference_report", "trace_clock_hz")
        if getattr(args, name) is None
    ]
    if missing:
        parser.error("missing required arguments for packaging: " + ", ".join("--" + name.replace("_", "-") for name in missing))
    root = args.root.resolve()
    summary = package_summary(
        root,
        args.host_receiver_log,
        args.timing_report,
        args.resource_report,
        args.noninterference_report,
        args.trace_clock_hz,
        args.target,
        args.p95_event_bytes_per_second,
    )
    out = write_summary(root, args.out, summary)
    errors = validate_external_summary(RECORD_ID, summary, root)
    status = "PASS" if not errors else "FAIL"
    print(f"[{status}] wrote streaming/DMA throughput summary to {out}")
    for error in errors:
        print(f"- {error}")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
