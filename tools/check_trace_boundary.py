from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile
from pathlib import Path


DEFAULT_RTL_FILELIST = Path("sim/vivado/trace_rtl.f")
DEFAULT_SIM_FILELIST = Path("sim/vivado/trace_sim.f")

BANNED_RTL_PATTERNS = {
    r"\$fopen\b": "file writer",
    r"\$fclose\b": "file writer",
    r"\$fdisplay[boh]?\b": "file writer",
    r"\$fwrite[boh]?\b": "file writer",
    r"\$fflush\b": "file writer",
    r"\$fmonitor[boh]?\b": "file writer",
    r"\$fstrobe[boh]?\b": "file writer",
    r"\$finish\b": "simulation control",
    r"\$fatal\b": "simulation assertion/control",
    r"\$stop\b": "simulation control",
    r"\$value\$plusargs\b": "simulation plusargs",
    r"\binitial\b": "simulation initial block",
    r"\bfinal\b": "simulation final block",
    r"\bassert\b": "simulation assertion",
}

DELAY_RTL_PATTERNS = (
    r"^\s*#\s*(?:\(|[0-9A-Za-z_$])",
    r"\balways(?:_\w+)?\s*#\s*(?:\(|[0-9A-Za-z_$])",
    r"\bassign\s*#\s*(?:\(|[0-9A-Za-z_$])",
    r"(?:<=|=)\s*#\s*(?:\(|[0-9A-Za-z_$])",
    r";\s*#\s*(?:\(|[0-9A-Za-z_$])",
)


def strip_comment(line: str) -> str:
    return line.split("//", 1)[0]


def read_filelist(path: Path) -> list[Path]:
    entries: list[Path] = []
    for line_no, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = strip_comment(raw_line).strip()
        if not line:
            continue
        if line.startswith("-f "):
            raise ValueError(f"{path}:{line_no}: nested -f entries are not allowed in split boundary lists")
        if line.startswith("-"):
            raise ValueError(f"{path}:{line_no}: unsupported filelist option: {line}")
        entries.append(Path(line))
    return entries


def check_prefix(entries: list[Path], prefix: str, label: str) -> list[str]:
    errors: list[str] = []
    normalized_prefix = prefix.replace("\\", "/").rstrip("/") + "/"
    for entry in entries:
        normalized = entry.as_posix()
        if not normalized.startswith(normalized_prefix):
            errors.append(f"{label} file is outside {prefix}: {entry}")
        if not entry.exists():
            errors.append(f"{label} file does not exist: {entry}")
    return errors


def check_banned_rtl(entries: list[Path]) -> list[str]:
    errors: list[str] = []
    compiled = [(re.compile(pattern), reason) for pattern, reason in BANNED_RTL_PATTERNS.items()]
    delay_compiled = [re.compile(pattern) for pattern in DELAY_RTL_PATTERNS]
    for entry in entries:
        if not entry.exists():
            continue
        previous_code = ""
        for line_no, raw_line in enumerate(entry.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
            line = strip_comment(raw_line)
            stripped = line.strip()
            for pattern, reason in compiled:
                if pattern.search(line):
                    errors.append(f"{entry}:{line_no}: {reason} construct in synthesizable RTL list")
            module_param_header = stripped == "#(" and (
                previous_code.startswith("module ") or previous_code.startswith("import ")
            )
            if not module_param_header and any(pattern.search(line) for pattern in delay_compiled):
                errors.append(f"{entry}:{line_no}: simulation delay control construct in synthesizable RTL list")
            if stripped:
                previous_code = stripped
    return errors


def run_checks(rtl_filelist: Path, sim_filelist: Path) -> list[str]:
    rtl_entries = read_filelist(rtl_filelist)
    sim_entries = read_filelist(sim_filelist)

    errors: list[str] = []
    errors.extend(check_prefix(rtl_entries, "rtl/trace", "RTL"))
    errors.extend(check_prefix(sim_entries, "sim/tb", "simulation"))
    errors.extend(check_banned_rtl(rtl_entries))
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        rtl_dir = root / "rtl" / "trace"
        sim_dir = root / "sim" / "tb"
        list_dir = root / "sim" / "vivado"
        rtl_dir.mkdir(parents=True)
        sim_dir.mkdir(parents=True)
        list_dir.mkdir(parents=True)

        sim_file = sim_dir / "tb_ok.sv"
        sim_file.write_text("module tb_ok; initial $finish; endmodule\n", encoding="utf-8")

        sim_list = list_dir / "trace_sim.f"
        sim_list.write_text("sim/tb/tb_ok.sv\n", encoding="utf-8")

        cases = {
            "initial": ("module bad_initial; initial begin end endmodule", "simulation initial block"),
            "assertion": ("module bad_assert; always_comb assert (1'b1); endmodule", "simulation assertion"),
            "file_io": ("module bad_file; always_comb $fwrite(32'h0, \"bad\"); endmodule", "file writer"),
            "file_display": ("module bad_fdisplay; always_comb $fdisplay(32'h0, \"bad\"); endmodule", "file writer"),
            "file_monitor": ("module bad_fmonitor; always_comb $fmonitor(32'h0, \"bad\"); endmodule", "file writer"),
            "file_strobe": ("module bad_fstrobe; always_comb $fstrobe(32'h0, \"bad\"); endmodule", "file writer"),
            "file_write_suffix": ("module bad_fwriteh; always_comb $fwriteh(32'h0, \"bad\"); endmodule", "file writer"),
            "file_display_suffix": ("module bad_fdisplayb; always_comb $fdisplayb(32'h0, \"bad\"); endmodule", "file writer"),
            "file_monitor_suffix": ("module bad_fmonitoro; always_comb $fmonitoro(32'h0, \"bad\"); endmodule", "file writer"),
            "file_strobe_suffix": ("module bad_fstrobeo; always_comb $fstrobeo(32'h0, \"bad\"); endmodule", "file writer"),
            "line_delay": ("module bad_line_delay; initial begin\n  #1;\nend endmodule", "simulation delay control"),
            "paren_line_delay": (
                "module bad_paren_line_delay; initial begin\n  #(CLOCK_PERIOD / 2);\nend endmodule",
                "simulation delay control",
            ),
            "always_delay": (
                "module bad_always_delay; logic clk; always #(CLOCK_PERIOD / 2) clk = ~clk; endmodule",
                "simulation delay control",
            ),
            "procedural_assign_delay": (
                "module bad_proc_assign_delay; always_comb x = #1 y; endmodule",
                "simulation delay control",
            ),
            "continuous_assign_delay": (
                "module bad_cont_assign_delay; assign #1 x = y; endmodule",
                "simulation delay control",
            ),
            "semicolon_delay": (
                "module bad_semicolon_delay; initial begin x = y; #1; end endmodule",
                "simulation delay control",
            ),
        }

        cwd = Path.cwd()
        try:
            os.chdir(root)
            for name, (source, expected) in cases.items():
                bad_rtl = rtl_dir / f"{name}.sv"
                bad_rtl.write_text(source + "\n", encoding="utf-8")
                rtl_list = list_dir / f"{name}.f"
                rtl_list.write_text(f"rtl/trace/{name}.sv\n", encoding="utf-8")
                errors = run_checks(rtl_list, sim_list)
                if not any(expected in error for error in errors):
                    print(f"[FAIL] self-test missed {name}: {expected}", file=sys.stderr)
                    return 1

            parameterized_rtl = rtl_dir / "parameterized_ok.sv"
            parameterized_rtl.write_text(
                "\n".join(
                    [
                        "module parameterized_ok",
                        "  import trace_pkg::*;",
                        "#(",
                        "    parameter int WIDTH = 1",
                        ") ();",
                        "endmodule",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            rtl_list = list_dir / "parameterized_ok.f"
            rtl_list.write_text("rtl/trace/parameterized_ok.sv\n", encoding="utf-8")
            errors = run_checks(rtl_list, sim_list)
            if errors:
                for error in errors:
                    print(f"[FAIL] self-test false positive: {error}", file=sys.stderr)
                return 1
        finally:
            os.chdir(cwd)

    print("[PASS] trace boundary self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check rv-maltrace RTL/simulation source boundary.")
    parser.add_argument("--rtl-filelist", type=Path, default=DEFAULT_RTL_FILELIST)
    parser.add_argument("--sim-filelist", type=Path, default=DEFAULT_SIM_FILELIST)
    parser.add_argument("--self-test", action="store_true", help="Run negative coverage checks for banned RTL patterns.")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    try:
        errors = run_checks(args.rtl_filelist, args.sim_filelist)
    except Exception as exc:
        print(f"check_trace_boundary: error: {exc}", file=sys.stderr)
        return 2

    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1

    print(
        f"[PASS] trace boundary: {len(read_filelist(args.rtl_filelist))} synthesizable RTL files, "
        f"{len(read_filelist(args.sim_filelist))} simulation-only files"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
