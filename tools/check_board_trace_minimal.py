from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from pathlib import Path


DEFAULT_PROFILE = Path("rtl/trace/trace_board_minimal_ctrl.sv")
DEFAULT_WRAPPER = Path("rtl/trace/trace_board_minimal_top.sv")
DEFAULT_TRACE_TOP = Path("rtl/trace/trace_top.sv")
DEFAULT_FILELIST = Path("sim/vivado/trace_rtl.f")
DEFAULT_RUN_ALL = Path("sim/vivado/run_all_tests.tcl")
DEFAULT_TRACE_TB = Path("sim/tb/tb_trace_top_unit.sv")
DEFAULT_GOLDEN = Path("sim/golden/board_minimal.expected.json")
DEFAULT_DOC = Path("docs/board_trace_minimal.md")
DEFAULT_BOARD_DOC = Path("docs/board_bringup.md")

EXPECTED_ASSIGNMENTS = {
    "trace_enable_retire_o": "1'b0",
    "trace_enable_branch_o": "1'b1",
    "trace_enable_jump_o": "1'b0",
    "trace_enable_syscall_o": "1'b1",
    "trace_enable_trap_o": "1'b1",
    "trace_enable_context_o": "1'b1",
    "trace_enable_marker_o": "1'b0",
    "trace_enable_drop_o": "1'b1",
    "trace_pc_filter_enable_o": "PC_FILTER_ENABLE",
    "trace_pc_start_o": "PC_START",
    "trace_pc_end_o": "PC_END",
    "trace_priv_filter_enable_o": "PRIV_FILTER_ENABLE",
    "trace_priv_mask_o": "PRIV_MASK",
}
EXPECTED_PARAMETERS = {
    "PC_FILTER_ENABLE": "1'b0",
    "PC_START": "64'd0",
    "PC_END": "64'hffff_ffff_ffff_ffff",
    "PRIV_FILTER_ENABLE": "1'b0",
    "PRIV_MASK": "4'hf",
}
EXPECTED_DOC_CONTROLS = {
    "trace_enable_retire_o": "0",
    "trace_enable_branch_o": "1",
    "trace_enable_jump_o": "0",
    "trace_enable_syscall_o": "1",
    "trace_enable_trap_o": "1",
    "trace_enable_context_o": "1",
    "trace_enable_marker_o": "0",
    "trace_enable_drop_o": "1",
}
FILTER_SOURCES = ("retire", "branch", "syscall", "arg_mem", "trap", "context")
SOURCE_ORDER = ("trap", "syscall", "arg_mem", "context", "branch", "retire")
REQUIRED_DOC_TEXT = (
    "First board trace runs use `rtl/trace/trace_board_minimal_top.sv`",
    "instantiates `rtl/trace/trace_board_minimal_ctrl.sv`",
    "The `board_minimal` trace-unit regression instantiates that profile",
    "This is a board bring-up configuration, not evidence that hardware trace has passed on Genesys 2.",
    "Only syscall, trap, context, and branch behavior events are enabled for the first board run:",
    "`DROP` remains enabled as accounting only.",
    "`RETIRE`, `JUMP`, and `MARKER` are not first-board behavior events.",
    "`trace_filter.sv` applies event-type filtering before packets enter the",
    "`PC_FILTER_ENABLE`, `PC_START`, and `PC_END`, but is disabled by default",
    "`DROP.value` carries the",
)
FORBIDDEN_DOC_PATTERNS = (
    (re.compile(r"\bfull\s+retire\s+(?:is\s+)?enabled\b", re.IGNORECASE), "full retire must stay disabled"),
    (re.compile(r"\bRETIRE\b[^\n|]*(?:enabled|allowed)", re.IGNORECASE), "RETIRE must not be allowed"),
    (re.compile(r"\bJUMP\b[^\n|]*(?:enabled|allowed)", re.IGNORECASE), "JUMP must not be allowed"),
    (re.compile(r"\bMARKER\b[^\n|]*(?:enabled|allowed)", re.IGNORECASE), "MARKER must not be allowed"),
    (re.compile(r"\bhardware\s+trace\s+(?:passed|validated|complete)\b", re.IGNORECASE), "must not claim hardware trace pass"),
)


def resolve(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path


def compact(value: str) -> str:
    return re.sub(r"\s+", "", value)


def strip_comment(line: str) -> str:
    return line.split("//", 1)[0]


def normalized_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def read_filelist(path: Path) -> list[Path]:
    entries: list[Path] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = strip_comment(raw_line).strip()
        if line and not line.startswith("-f "):
            entries.append(Path(line))
    return entries


def parse_assignments(text: str) -> dict[str, str]:
    return {
        name: compact(value)
        for name, value in re.findall(r"\bassign\s+(\w+)\s*=\s*([^;]+);", text)
    }


def parse_table_rows(text: str) -> list[list[str]]:
    rows: list[list[str]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line.startswith("|"):
            continue
        cells = [cell.strip().strip("`") for cell in line.strip("|").split("|")]
        if cells and all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells):
            continue
        if cells and cells[0] == "Control":
            continue
        rows.append(cells)
    return rows


def check_profile(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    if not re.search(r"\bmodule\s+trace_board_minimal_ctrl\b", text):
        errors.append(f"{path}: missing trace_board_minimal_ctrl module")
    for name, expected in EXPECTED_PARAMETERS.items():
        pattern = re.compile(rf"\bparameter\b[^,\n;]*\b{re.escape(name)}\s*=\s*([^,\n)]+)")
        match = pattern.search(text)
        if match is None:
            errors.append(f"{path}: missing parameter {name}")
        elif compact(match.group(1)) != expected:
            errors.append(f"{path}: parameter {name} must default to {expected}")

    assignments = parse_assignments(text)
    for name, expected in EXPECTED_ASSIGNMENTS.items():
        if assignments.get(name) != expected:
            errors.append(f"{path}: {name} must assign {expected}")
    return errors


def instance_block(text: str, source: str) -> str | None:
    pattern = re.compile(rf"\btrace_filter\s+i_{source}_filter\s*\((.*?)\);", re.DOTALL)
    match = pattern.search(text)
    return match.group(1) if match else None


def check_trace_top(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    for source in FILTER_SOURCES:
        block = instance_block(text, source)
        if block is None:
            errors.append(f"{path}: missing trace_filter i_{source}_filter before queueing")
            continue
        if f".trace_valid_i({source}_valid)" not in compact(block):
            errors.append(f"{path}: i_{source}_filter must consume {source}_valid")
        if f".trace_valid_o(filtered_{source}_valid)" not in compact(block):
            errors.append(f"{path}: i_{source}_filter must produce filtered_{source}_valid")
        if ".enable_retire_i(trace_enable_retire_s)" not in compact(block):
            errors.append(f"{path}: i_{source}_filter must use event enable controls")
        if ".pc_filter_enable_i(trace_pc_filter_enable_s)" not in compact(block):
            errors.append(f"{path}: i_{source}_filter must use PC range filter controls")

    for index, source in enumerate(SOURCE_ORDER):
        expected = f"source_valid[{index}]=filtered_{source}_valid;"
        if expected not in compact(text):
            errors.append(f"{path}: queue source {index} must use filtered_{source}_valid")
    if "drop_packet.value=drop_count_q;" not in compact(text):
        errors.append(f"{path}: DROP.value must carry drop_count_q")
    return errors


def check_filelist(path: Path, profile: Path, wrapper: Path) -> list[str]:
    entries = [entry.as_posix() for entry in read_filelist(path)]
    errors: list[str] = []
    for expected in (profile.as_posix(), wrapper.as_posix()):
        if expected not in entries:
            errors.append(f"{path}: missing {expected} from trace RTL filelist")
    return errors


def check_wrapper(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    compact_text = compact(text)
    errors: list[str] = []
    if not re.search(r"\bmodule\s+trace_board_minimal_top\b", text):
        errors.append(f"{path}: missing trace_board_minimal_top module")
    if not re.search(r"\btrace_board_minimal_ctrl\s*(?:#\s*\(.*?\)\s*)?i_board_minimal_ctrl\s*\(", text, re.DOTALL):
        errors.append(f"{path}: must instantiate trace_board_minimal_ctrl")
    if not re.search(r"\btrace_top\s*(?:#\s*\(.*?\)\s*)?i_trace_top\s*\(", text, re.DOTALL):
        errors.append(f"{path}: must instantiate trace_top")
    for signal in (
        "trace_enable_retire",
        "trace_enable_branch",
        "trace_enable_jump",
        "trace_enable_syscall",
        "trace_enable_trap",
        "trace_enable_context",
        "trace_enable_marker",
        "trace_enable_drop",
        "trace_pc_filter_enable",
        "trace_pc_start",
        "trace_pc_end",
        "trace_priv_filter_enable",
        "trace_priv_mask",
    ):
        ctrl_port = signal.replace("trace_", "trace_", 1)
        if f".{ctrl_port}_o({signal})" not in compact_text:
            errors.append(f"{path}: minimal ctrl must drive {signal}")
        if f".{signal}_i({signal})" not in compact_text:
            errors.append(f"{path}: trace_top must consume {signal}")
    return errors


def check_regression(trace_tb: Path, run_all: Path, golden: Path) -> list[str]:
    tb_text = trace_tb.read_text(encoding="utf-8")
    run_text = run_all.read_text(encoding="utf-8")
    expected_json = json.loads(golden.read_text(encoding="utf-8"))
    errors: list[str] = []
    compact_tb = compact(tb_text)
    if "trace_board_minimal_ctrlboard_minimal_profile(" not in compact_tb:
        errors.append(f"{trace_tb}: board_minimal profile must be instantiated")
    if "board_minimal_profile_active" not in tb_text:
        errors.append(f"{trace_tb}: missing board_minimal_profile_active selector")
    if "test_name == \"board_minimal\"" not in tb_text:
        errors.append(f"{trace_tb}: missing board_minimal test dispatch")
    if "run_board_minimal" not in tb_text:
        errors.append(f"{trace_tb}: missing run_board_minimal scenario")
    for signal in (
        "trace_enable_retire",
        "trace_enable_branch",
        "trace_enable_jump",
        "trace_enable_syscall",
        "trace_enable_trap",
        "trace_enable_context",
        "trace_enable_marker",
        "trace_enable_drop",
    ):
        expected_select = f"{signal}_to_dut=board_minimal_profile_active?board_{signal}:{signal};"
        if expected_select not in compact_tb:
            errors.append(f"{trace_tb}: {signal}_to_dut must select board profile controls")
    if not re.search(r"\bboard_minimal\b", run_text):
        errors.append(f"{run_all}: missing board_minimal in trace-unit test matrix")
    exact_counts = expected_json.get("exact_counts", {})
    expected_counts = {"BRANCH": 1, "SYSCALL_ENTRY": 1, "TRAP": 1, "PRIV": 2}
    for event, expected_count in expected_counts.items():
        if exact_counts.get(event) != expected_count:
            errors.append(f"{golden}: board_minimal must expect exactly {expected_count} {event}")
    forbidden_events = set(expected_json.get("forbidden_events", []))
    for event in ("RETIRE", "JUMP", "MARKER"):
        if event not in forbidden_events:
            errors.append(f"{golden}: board_minimal must forbid {event}")
    required_events = expected_json.get("required_events", [])
    for event in ("BRANCH", "SYSCALL_ENTRY", "TRAP", "PRIV"):
        if not any(isinstance(item, dict) and item.get("evt") == event for item in required_events):
            errors.append(f"{golden}: missing required board_minimal event {event}")
    return errors


def check_policy_doc(path: Path, board_doc: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    normalized = normalized_text(text)
    errors: list[str] = []
    for required in REQUIRED_DOC_TEXT:
        if normalized_text(required) not in normalized:
            errors.append(f"{path}: missing required policy text: {required}")
    rows = parse_table_rows(text)
    by_control = {row[0]: row for row in rows if row}
    for control, expected in EXPECTED_DOC_CONTROLS.items():
        row = by_control.get(control)
        if row is None or len(row) < 2 or row[1] != expected:
            errors.append(f"{path}: {control} must be documented as {expected}")
    for pattern, message in FORBIDDEN_DOC_PATTERNS:
        if pattern.search(text):
            errors.append(f"{path}: {message}")

    board_text = board_doc.read_text(encoding="utf-8")
    if "docs/board_trace_minimal.md" not in board_text:
        errors.append(f"{board_doc}: missing Phase 5.2 minimal trace policy link")
    if "trace_board_minimal_top.sv" not in board_text:
        errors.append(f"{board_doc}: missing trace_board_minimal_top.sv reference")
    return errors


def run_checks(
    root: Path,
    profile: Path,
    wrapper: Path,
    trace_top: Path,
    filelist: Path,
    run_all: Path,
    trace_tb: Path,
    golden: Path,
    doc: Path,
    board_doc: Path,
) -> list[str]:
    profile_path = resolve(root, profile)
    wrapper_path = resolve(root, wrapper)
    trace_top_path = resolve(root, trace_top)
    filelist_path = resolve(root, filelist)
    run_all_path = resolve(root, run_all)
    trace_tb_path = resolve(root, trace_tb)
    golden_path = resolve(root, golden)
    doc_path = resolve(root, doc)
    board_doc_path = resolve(root, board_doc)
    errors: list[str] = []
    for path, label in (
        (profile_path, "profile"),
        (wrapper_path, "wrapper"),
        (trace_top_path, "trace top"),
        (filelist_path, "filelist"),
        (run_all_path, "trace-unit matrix"),
        (trace_tb_path, "trace-unit testbench"),
        (golden_path, "board_minimal golden"),
        (doc_path, "policy doc"),
        (board_doc_path, "board doc"),
    ):
        if not path.exists():
            errors.append(f"missing {label}: {path}")
    if errors:
        return errors
    errors.extend(check_profile(profile_path))
    errors.extend(check_wrapper(wrapper_path))
    errors.extend(check_trace_top(trace_top_path))
    errors.extend(check_filelist(filelist_path, profile, wrapper))
    errors.extend(check_regression(trace_tb_path, run_all_path, golden_path))
    errors.extend(check_policy_doc(doc_path, board_doc_path))
    return errors


def write_fixture(root: Path) -> None:
    (root / "rtl" / "trace").mkdir(parents=True)
    (root / "sim" / "vivado").mkdir(parents=True)
    (root / "docs").mkdir(parents=True)
    (root / DEFAULT_PROFILE).write_text(
        """module trace_board_minimal_ctrl #(
    parameter logic        PC_FILTER_ENABLE = 1'b0,
    parameter logic [63:0] PC_START = 64'd0,
    parameter logic [63:0] PC_END = 64'hffff_ffff_ffff_ffff,
    parameter logic        PRIV_FILTER_ENABLE = 1'b0,
    parameter logic [ 3:0] PRIV_MASK = 4'hf
) ();
  assign trace_enable_retire_o = 1'b0;
  assign trace_enable_branch_o = 1'b1;
  assign trace_enable_jump_o = 1'b0;
  assign trace_enable_syscall_o = 1'b1;
  assign trace_enable_trap_o = 1'b1;
  assign trace_enable_context_o = 1'b1;
  assign trace_enable_marker_o = 1'b0;
  assign trace_enable_drop_o = 1'b1;
  assign trace_pc_filter_enable_o = PC_FILTER_ENABLE;
  assign trace_pc_start_o = PC_START;
  assign trace_pc_end_o = PC_END;
  assign trace_priv_filter_enable_o = PRIV_FILTER_ENABLE;
  assign trace_priv_mask_o = PRIV_MASK;
endmodule
""",
        encoding="utf-8",
    )
    (root / DEFAULT_WRAPPER).write_text(
        """module trace_board_minimal_top;
  logic trace_enable_retire;
  logic trace_enable_branch;
  logic trace_enable_jump;
  logic trace_enable_syscall;
  logic trace_enable_trap;
  logic trace_enable_context;
  logic trace_enable_marker;
  logic trace_enable_drop;
  logic trace_pc_filter_enable;
  logic trace_pc_start;
  logic trace_pc_end;
  logic trace_priv_filter_enable;
  logic trace_priv_mask;
  trace_board_minimal_ctrl i_board_minimal_ctrl (
      .trace_enable_retire_o(trace_enable_retire),
      .trace_enable_branch_o(trace_enable_branch),
      .trace_enable_jump_o(trace_enable_jump),
      .trace_enable_syscall_o(trace_enable_syscall),
      .trace_enable_trap_o(trace_enable_trap),
      .trace_enable_context_o(trace_enable_context),
      .trace_enable_marker_o(trace_enable_marker),
      .trace_enable_drop_o(trace_enable_drop),
      .trace_pc_filter_enable_o(trace_pc_filter_enable),
      .trace_pc_start_o(trace_pc_start),
      .trace_pc_end_o(trace_pc_end),
      .trace_priv_filter_enable_o(trace_priv_filter_enable),
      .trace_priv_mask_o(trace_priv_mask)
  );
  trace_top #() i_trace_top (
      .trace_enable_retire_i(trace_enable_retire),
      .trace_enable_branch_i(trace_enable_branch),
      .trace_enable_jump_i(trace_enable_jump),
      .trace_enable_syscall_i(trace_enable_syscall),
      .trace_enable_trap_i(trace_enable_trap),
      .trace_enable_context_i(trace_enable_context),
      .trace_enable_marker_i(trace_enable_marker),
      .trace_enable_drop_i(trace_enable_drop),
      .trace_pc_filter_enable_i(trace_pc_filter_enable),
      .trace_pc_start_i(trace_pc_start),
      .trace_pc_end_i(trace_pc_end),
      .trace_priv_filter_enable_i(trace_priv_filter_enable),
      .trace_priv_mask_i(trace_priv_mask)
  );
endmodule
""",
        encoding="utf-8",
    )
    filter_blocks = []
    for source in FILTER_SOURCES:
        filter_blocks.append(
            f"""  trace_filter i_{source}_filter (
      .trace_valid_i({source}_valid),
      .enable_retire_i(trace_enable_retire_s),
      .pc_filter_enable_i(trace_pc_filter_enable_s),
      .trace_valid_o(filtered_{source}_valid)
  );"""
        )
    sources = "\n".join(
        f"    source_valid[{index}] = filtered_{source}_valid;"
        for index, source in enumerate(SOURCE_ORDER)
    )
    (root / DEFAULT_TRACE_TOP).write_text(
        "module trace_top;\n"
        + "\n".join(filter_blocks)
        + "\n  always_comb begin\n"
        + sources
        + "\n    drop_packet.value = drop_count_q;\n  end\nendmodule\n",
        encoding="utf-8",
    )
    (root / DEFAULT_FILELIST).write_text(
        "rtl/trace/trace_board_minimal_ctrl.sv\nrtl/trace/trace_top.sv\nrtl/trace/trace_board_minimal_top.sv\n",
        encoding="utf-8",
    )
    (root / DEFAULT_RUN_ALL).write_text("set tests {smoke board_minimal}\n", encoding="utf-8")
    (root / DEFAULT_TRACE_TB).parent.mkdir(parents=True, exist_ok=True)
    (root / DEFAULT_TRACE_TB).write_text(
        """module tb_trace_top_unit;
  trace_board_minimal_ctrl board_minimal_profile ();
  logic board_minimal_profile_active;
  assign trace_enable_retire_to_dut = board_minimal_profile_active ? board_trace_enable_retire : trace_enable_retire;
  assign trace_enable_branch_to_dut = board_minimal_profile_active ? board_trace_enable_branch : trace_enable_branch;
  assign trace_enable_jump_to_dut = board_minimal_profile_active ? board_trace_enable_jump : trace_enable_jump;
  assign trace_enable_syscall_to_dut = board_minimal_profile_active ? board_trace_enable_syscall : trace_enable_syscall;
  assign trace_enable_trap_to_dut = board_minimal_profile_active ? board_trace_enable_trap : trace_enable_trap;
  assign trace_enable_context_to_dut = board_minimal_profile_active ? board_trace_enable_context : trace_enable_context;
  assign trace_enable_marker_to_dut = board_minimal_profile_active ? board_trace_enable_marker : trace_enable_marker;
  assign trace_enable_drop_to_dut = board_minimal_profile_active ? board_trace_enable_drop : trace_enable_drop;
  task run_board_minimal(); endtask
  initial if (test_name == "board_minimal") run_board_minimal();
endmodule
""",
        encoding="utf-8",
    )
    (root / DEFAULT_GOLDEN).parent.mkdir(parents=True, exist_ok=True)
    (root / DEFAULT_GOLDEN).write_text(
        '{"exact_counts":{"BRANCH":1,"SYSCALL_ENTRY":1,"TRAP":1,"PRIV":2},'
        '"required_events":[{"evt":"BRANCH"},{"evt":"SYSCALL_ENTRY"},{"evt":"TRAP"},{"evt":"PRIV"}],'
        '"forbidden_events":["RETIRE","JUMP","MARKER"]}\n',
        encoding="utf-8",
    )
    (root / DEFAULT_DOC).write_text(
        """# Board Trace Minimal Policy

First board trace runs use `rtl/trace/trace_board_minimal_top.sv` to drive the controls.
It instantiates `rtl/trace/trace_board_minimal_ctrl.sv`.
The `board_minimal` trace-unit regression instantiates that profile before board integration.
This is a board bring-up configuration, not evidence that hardware trace has passed on Genesys 2.

| Control | First-board Value | Purpose |
| --- | ---: | --- |
| `trace_enable_retire_o` | 0 | Keep full retire disabled by default |
| `trace_enable_branch_o` | 1 | Enable committed conditional branch events |
| `trace_enable_jump_o` | 0 | Defer jump events until the branch-only path is proven |
| `trace_enable_syscall_o` | 1 | Enable syscall events |
| `trace_enable_trap_o` | 1 | Enable trap and exception events |
| `trace_enable_context_o` | 1 | Enable CSR, SATP, and privilege context events |
| `trace_enable_marker_o` | 0 | Keep synthetic marker events off for board bring-up |
| `trace_enable_drop_o` | 1 | Keep dropped-event accounting observable |

Only syscall, trap, context, and branch behavior events are enabled for the first board run:
`DROP` remains enabled as accounting only.
`RETIRE`, `JUMP`, and `MARKER` are not first-board behavior events.
`trace_filter.sv` applies event-type filtering before packets enter the
`PC_FILTER_ENABLE`, `PC_START`, and `PC_END`, but is disabled by default
`DROP.value` carries the
""",
        encoding="utf-8",
    )
    (root / DEFAULT_BOARD_DOC).write_text(
        "Phase 5.2 is tracked in docs/board_trace_minimal.md and trace_board_minimal_top.sv.\n",
        encoding="utf-8",
    )


def expect_error(root: Path, expected: str) -> bool:
    errors = run_checks(
        root,
        DEFAULT_PROFILE,
        DEFAULT_WRAPPER,
        DEFAULT_TRACE_TOP,
        DEFAULT_FILELIST,
        DEFAULT_RUN_ALL,
        DEFAULT_TRACE_TB,
        DEFAULT_GOLDEN,
        DEFAULT_DOC,
        DEFAULT_BOARD_DOC,
    )
    return any(expected in error for error in errors)


def self_test() -> int:
    cases: list[tuple[str, str, str, str]] = [
        ("retire_enabled", "trace_enable_retire_o = 1'b0", "trace_enable_retire_o = 1'b1", "trace_enable_retire_o"),
        ("jump_enabled", "trace_enable_jump_o = 1'b0", "trace_enable_jump_o = 1'b1", "trace_enable_jump_o"),
        ("drop_disabled", "trace_enable_drop_o = 1'b1", "trace_enable_drop_o = 1'b0", "trace_enable_drop_o"),
        ("pc_filter_default_on", "PC_FILTER_ENABLE = 1'b0", "PC_FILTER_ENABLE = 1'b1", "PC_FILTER_ENABLE"),
    ]
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        errors = run_checks(
            root,
            DEFAULT_PROFILE,
            DEFAULT_WRAPPER,
            DEFAULT_TRACE_TOP,
            DEFAULT_FILELIST,
            DEFAULT_RUN_ALL,
            DEFAULT_TRACE_TB,
            DEFAULT_GOLDEN,
            DEFAULT_DOC,
            DEFAULT_BOARD_DOC,
        )
        if errors:
            for error in errors:
                print(f"[FAIL] self-test false positive: {error}", file=sys.stderr)
            return 1

    for name, old, new, expected in cases:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root)
            profile = root / DEFAULT_PROFILE
            profile.write_text(profile.read_text(encoding="utf-8").replace(old, new), encoding="utf-8")
            if not expect_error(root, expected):
                print(f"[FAIL] self-test missed {name}", file=sys.stderr)
                return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        (root / DEFAULT_FILELIST).write_text("rtl/trace/trace_top.sv\n", encoding="utf-8")
        if not expect_error(root, "trace_board_minimal_ctrl.sv"):
            print("[FAIL] self-test missed missing profile in filelist", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        wrapper = root / DEFAULT_WRAPPER
        wrapper.write_text(wrapper.read_text(encoding="utf-8").replace("trace_board_minimal_ctrl i_board_minimal_ctrl", "trace_board_minimal_ctrl i_unused_ctrl"), encoding="utf-8")
        if not expect_error(root, "must instantiate trace_board_minimal_ctrl"):
            print("[FAIL] self-test missed missing minimal wrapper ctrl instance", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        trace_top = root / DEFAULT_TRACE_TOP
        trace_top.write_text(
            trace_top.read_text(encoding="utf-8").replace("source_valid[5] = filtered_retire_valid;", "source_valid[5] = retire_valid;"),
            encoding="utf-8",
        )
        if not expect_error(root, "queue source 5 must use filtered_retire_valid"):
            print("[FAIL] self-test missed unfiltered retire source", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        trace_top = root / DEFAULT_TRACE_TOP
        trace_top.write_text(trace_top.read_text(encoding="utf-8").replace("drop_packet.value = drop_count_q;", ""), encoding="utf-8")
        if not expect_error(root, "DROP.value must carry drop_count_q"):
            print("[FAIL] self-test missed missing drop_count evidence", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        doc = root / DEFAULT_DOC
        doc.write_text(doc.read_text(encoding="utf-8").replace("| `trace_enable_retire_o` | 0 |", "| `trace_enable_retire_o` | 1 |"), encoding="utf-8")
        if not expect_error(root, "trace_enable_retire_o must be documented as 0"):
            print("[FAIL] self-test missed doc retire over-enable", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        trace_tb = root / DEFAULT_TRACE_TB
        trace_tb.write_text(trace_tb.read_text(encoding="utf-8").replace("trace_board_minimal_ctrl board_minimal_profile ();", ""), encoding="utf-8")
        if not expect_error(root, "board_minimal profile must be instantiated"):
            print("[FAIL] self-test missed missing board_minimal profile instantiation", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        run_all = root / DEFAULT_RUN_ALL
        run_all.write_text("set tests {smoke}\n", encoding="utf-8")
        if not expect_error(root, "missing board_minimal in trace-unit test matrix"):
            print("[FAIL] self-test missed missing board_minimal matrix entry", file=sys.stderr)
            return 1

    print("[PASS] board trace minimal policy self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Phase 5.2 first-board minimal trace policy.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--wrapper", type=Path, default=DEFAULT_WRAPPER)
    parser.add_argument("--trace-top", type=Path, default=DEFAULT_TRACE_TOP)
    parser.add_argument("--filelist", type=Path, default=DEFAULT_FILELIST)
    parser.add_argument("--run-all", type=Path, default=DEFAULT_RUN_ALL)
    parser.add_argument("--trace-tb", type=Path, default=DEFAULT_TRACE_TB)
    parser.add_argument("--golden", type=Path, default=DEFAULT_GOLDEN)
    parser.add_argument("--doc", type=Path, default=DEFAULT_DOC)
    parser.add_argument("--board-doc", type=Path, default=DEFAULT_BOARD_DOC)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    root = args.root.resolve()
    try:
        errors = run_checks(
            root,
            args.profile,
            args.wrapper,
            args.trace_top,
            args.filelist,
            args.run_all,
            args.trace_tb,
            args.golden,
            args.doc,
            args.board_doc,
        )
    except Exception as exc:
        print(f"check_board_trace_minimal: error: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    print("[PASS] Phase 5.2 board trace policy keeps first hardware trace minimal")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
