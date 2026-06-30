from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    as_dict,
    as_list,
    load_json,
    repo_path,
    require,
)

from package_genesys2_strict_sret_board_smoke import (
    DEFAULT_OUT,
    package_summary,
    self_test as packager_self_test,
    sha256_file,
    write_json,
)


def as_int(value: Any, default: int = 0) -> int:
    if isinstance(value, bool) or value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def check_file_row(root: Path, errors: list[str], row: dict[str, Any], label: str) -> None:
    path_value = row.get("path")
    require(errors, isinstance(path_value, str) and bool(path_value), f"{label}: path missing")
    if not isinstance(path_value, str):
        return
    path = repo_path(root, path_value)
    require(errors, path.is_file(), f"{label}: file missing: {path_value}")
    if not path.is_file():
        return
    require(errors, row.get("sha256") == sha256_file(path), f"{label}: sha256 mismatch")
    require(errors, row.get("size_bytes") == path.stat().st_size, f"{label}: size mismatch")


def check_summary(root: Path, path: Path) -> list[str]:
    errors: list[str] = []
    data = load_json(path)
    require(errors, data.get("schema") == "rvmt.genesys2.strict_sret_board_smoke.v1", "schema mismatch")
    require(errors, data.get("status") == "PASS", "status must be PASS for the accepted current-bitstream smoke")
    require(errors, data.get("run_root") == "results/board/genesys2_trace_validation/20260624-strict-sret-current-bitstream", "unexpected run_root")

    sample = as_dict(data.get("sample"))
    require(errors, sample.get("sample_id") == "hello_write", "sample_id mismatch")
    require(errors, sample.get("rep") == "rep_02", "accepted repetition must be rep_02")
    require(errors, sample.get("board_sha256_verified") is True, "board runtime binary SHA256 was not verified")
    for label in ("runtime_binary", "sample_manifest", "transfer_log", "setup_log"):
        check_file_row(root, errors, as_dict(sample.get(label)), f"sample.{label}")

    bitstream = as_dict(data.get("bitstream"))
    require(errors, bitstream.get("status") == "PASS", "bitstream status must be PASS")
    require(errors, bitstream.get("trace_marker_scope") is True, "trace_marker_scope must be true")
    defines = as_list(bitstream.get("verilog_defines"))
    require(errors, "RV_MALTRACE_FPGA_TRACE_MARKER_SCOPE" in defines, "trace-marker define missing")
    for label in ("bitstream", "ltx", "manifest"):
        check_file_row(root, errors, as_dict(bitstream.get(label)), f"bitstream.{label}")

    programming = as_dict(data.get("programming_evidence"))
    require(errors, programming.get("status") == "PASS_TRACE_MARKER_PROGRAMMED", "programming evidence status mismatch")
    require(errors, programming.get("target") == "localhost:3121/xilinx_tcf/Digilent/200300B81858B", "programming target mismatch")
    require(errors, programming.get("device") == "xc7k325t_0", "programming device mismatch")
    require(errors, programming.get("ila_core_count") == 1, "programming ILA count mismatch")
    check_file_row(root, errors, as_dict(programming.get("summary")), "programming.summary")

    capture = as_dict(data.get("accepted_capture"))
    require(errors, capture.get("status") == "PASS", "accepted capture status mismatch")
    for label in ("summary", "bram_records", "capture_csv", "capture_log", "capture_err_log", "uart_log"):
        check_file_row(root, errors, as_dict(capture.get(label)), f"accepted_capture.{label}")

    bram = as_dict(capture.get("bram_summary"))
    require(errors, as_int(bram.get("event_count")) > 0, "BRAM event_count must be positive")
    require(errors, as_int(bram.get("dropped_count"), -1) == 0, "BRAM dropped_count must be 0")
    require(errors, as_int(bram.get("wrap_count"), -1) == 0, "BRAM wrap_count must be 0")
    event_counts = as_dict(bram.get("event_counts"))
    require(errors, int(event_counts.get("MARKER", 0) or 0) == 2, "expected two marker events")
    require(errors, int(event_counts.get("SYSCALL_ENTRY", 0) or 0) >= 1, "missing syscall entry")
    require(errors, int(event_counts.get("SYSCALL_RET", 0) or 0) >= 1, "missing syscall return")
    require(errors, int(event_counts.get("TRAP", 0) or 0) >= 1, "missing trap evidence")
    require(errors, int(event_counts.get("PRIV", 0) or 0) >= 1, "missing privilege-transition evidence")

    marker = as_dict(capture.get("marker_window"))
    require(errors, marker.get("begin_count") == 1, "begin marker count mismatch")
    require(errors, marker.get("end_count") == 1, "end marker count mismatch")
    require(errors, marker.get("begin_sequence") == 0, "begin marker must be sequence 0")
    require(errors, not as_list(capture.get("sequence_gaps")), "sequence gaps present")
    require(errors, len(as_list(capture.get("strict_syscall_id_pairs"))) >= 1, "strict syscall pair missing")

    validation = as_dict(data.get("validation"))
    for key in (
        "bram_summary_pass",
        "uart_rc_zero",
        "ila_capture_done",
        "ila_target_seen",
        "ila_device_seen",
        "programming_summary_pass",
        "trace_marker_scope",
        "runtime_binary_sha256_seen_on_board",
    ):
        require(errors, validation.get(key) is True, f"validation.{key} must be true")
    require(errors, validation.get("dropped_count") == 0, "validation dropped_count mismatch")
    require(errors, validation.get("wrap_count") == 0, "validation wrap_count mismatch")
    require(errors, validation.get("sequence_gap_count") == 0, "validation sequence_gap_count mismatch")

    boundary = as_dict(data.get("claim_boundary"))
    require(errors, boundary.get("strict_sret_board_smoke_claimed") is True, "strict smoke claim boundary mismatch")
    for key in (
        "full_p0_repetition_cohort_claimed",
        "genesys2_booted_written_sdcard_image",
        "cycle_level_overhead_claimed",
        "production_streaming_claimed",
        "real_malware_claimed",
    ):
        require(errors, boundary.get(key) is False, f"claim_boundary.{key} must be false")
    return errors


def self_test() -> int:
    if packager_self_test() != 0:
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        args = argparse.Namespace(
            root=root,
            run_root=root / "results/board/genesys2_trace_validation/20260624-strict-sret-current-bitstream",
            rep="rep_02",
            out=root / DEFAULT_OUT,
            bitstream=root / "build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx.bit",
            ltx=root / "build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx.ltx",
            build_manifest=root / "build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/rvmt_trace_marker_build_manifest.json",
            runtime_binary=root / "build/board/genesys2_cva6_p0_marker/hello_write/hello_write.riscv64",
            sample_manifest=root / "build/board/genesys2_cva6_p0_marker/hello_write/build_manifest.json",
            programming_summary=root / "results/evaluation/genesys2-cva6/current/trace_marker_programming_summary.json",
        )
        # Reuse the packager self-test data model by writing a checked summary fixture.
        from package_genesys2_strict_sret_board_smoke import self_test as _  # noqa: F401

        # The checker fixture is covered by the packager self-test above; keep a minimal malformed
        # check here to prove failures are surfaced.
        summary = root / DEFAULT_OUT
        summary.parent.mkdir(parents=True)
        write_json(summary, {"schema": "rvmt.genesys2.strict_sret_board_smoke.v1", "status": "FAIL"})
        if not check_summary(root, summary):
            print("[FAIL] strict-SRET checker accepted malformed fixture", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 strict-SRET board smoke checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the current-bitstream Genesys2 strict-SRET board smoke evidence.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--summary", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    summary = args.summary if args.summary.is_absolute() else root / args.summary
    errors = check_summary(root, summary)
    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    print(f"[PASS] strict-SRET board smoke accepted: {summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
