from __future__ import annotations

import re
import shutil
from pathlib import Path


CPU_MODULE = "VexRiscvLitexSmpCluster_Cc1_Iw32Is4096Iy1_Dw32Ds4096Dy1_ITs4DTs4_Ood_Wm"


TRACE_PORTS = [
    "  output              rvmt_trace_valid,",
    "  output     [3:0]    rvmt_trace_event,",
    "  output     [1:0]    rvmt_trace_priv,",
    "  output     [1:0]    rvmt_trace_old_priv,",
    "  output     [1:0]    rvmt_trace_new_priv,",
    "  output     [31:0]   rvmt_trace_pc,",
    "  output     [31:0]   rvmt_trace_instr,",
    "  output     [31:0]   rvmt_trace_target,",
    "  output     [31:0]   rvmt_trace_cause,",
    "  output     [31:0]   rvmt_trace_tval,",
    "  output     [31:0]   rvmt_trace_syscall_id,",
    "  output     [31:0]   rvmt_trace_duration,",
    "  output     [31:0]   rvmt_trace_a0,",
    "  output     [31:0]   rvmt_trace_a1,",
    "  output     [31:0]   rvmt_trace_a2,",
    "  output     [31:0]   rvmt_trace_a3,",
    "  output     [31:0]   rvmt_trace_a4,",
    "  output     [31:0]   rvmt_trace_a5,",
    "  output     [31:0]   rvmt_trace_a6,",
    "  output     [31:0]   rvmt_trace_a7",
]


TRACE_ASSIGNMENTS = """
  reg [31:0] rvmt_trace_cycle;
  reg [31:0] rvmt_trace_entry_cycle;
  reg [31:0] rvmt_trace_syscall_seq;
  reg [31:0] rvmt_trace_active_syscall_id;
  reg        rvmt_trace_pending_syscall;
  reg [1:0] rvmt_trace_prev_priv;
  reg       rvmt_trace_priv_changed;
  reg [31:0] rvmt_trace_a0_shadow;
  reg [31:0] rvmt_trace_a1_shadow;
  reg [31:0] rvmt_trace_a2_shadow;
  reg [31:0] rvmt_trace_a3_shadow;
  reg [31:0] rvmt_trace_a4_shadow;
  reg [31:0] rvmt_trace_a5_shadow;
  reg [31:0] rvmt_trace_a6_shadow;
  reg [31:0] rvmt_trace_a7_shadow;
  always @(posedge debugCd_external_clk) begin
    if(systemCd_logic_outputReset) begin
      rvmt_trace_cycle <= 32'd0;
      rvmt_trace_entry_cycle <= 32'd0;
      rvmt_trace_syscall_seq <= 32'd0;
      rvmt_trace_active_syscall_id <= 32'd0;
      rvmt_trace_pending_syscall <= 1'b0;
      rvmt_trace_prev_priv <= 2'b11;
      rvmt_trace_priv_changed <= 1'b0;
      rvmt_trace_a0_shadow <= 32'd0;
      rvmt_trace_a1_shadow <= 32'd0;
      rvmt_trace_a2_shadow <= 32'd0;
      rvmt_trace_a3_shadow <= 32'd0;
      rvmt_trace_a4_shadow <= 32'd0;
      rvmt_trace_a5_shadow <= 32'd0;
      rvmt_trace_a6_shadow <= 32'd0;
      rvmt_trace_a7_shadow <= 32'd0;
    end else begin
      rvmt_trace_cycle <= (rvmt_trace_cycle + 32'd1);
      rvmt_trace_priv_changed <= (CsrPlugin_privilege != rvmt_trace_prev_priv);
      rvmt_trace_prev_priv <= CsrPlugin_privilege;
      if(lastStageRegFileWrite_valid) begin
        case(lastStageRegFileWrite_payload_address)
          5'd10 : rvmt_trace_a0_shadow <= lastStageRegFileWrite_payload_data;
          5'd11 : rvmt_trace_a1_shadow <= lastStageRegFileWrite_payload_data;
          5'd12 : rvmt_trace_a2_shadow <= lastStageRegFileWrite_payload_data;
          5'd13 : rvmt_trace_a3_shadow <= lastStageRegFileWrite_payload_data;
          5'd14 : rvmt_trace_a4_shadow <= lastStageRegFileWrite_payload_data;
          5'd15 : rvmt_trace_a5_shadow <= lastStageRegFileWrite_payload_data;
          5'd16 : rvmt_trace_a6_shadow <= lastStageRegFileWrite_payload_data;
          5'd17 : rvmt_trace_a7_shadow <= lastStageRegFileWrite_payload_data;
          default : begin
          end
        endcase
      end
      if(rvmt_trace_syscall) begin
        rvmt_trace_active_syscall_id <= rvmt_trace_syscall_seq;
        rvmt_trace_entry_cycle <= rvmt_trace_cycle;
        rvmt_trace_pending_syscall <= 1'b1;
        rvmt_trace_syscall_seq <= (rvmt_trace_syscall_seq + 32'd1);
      end
      if(rvmt_trace_syscall_ret) begin
        rvmt_trace_pending_syscall <= 1'b0;
      end
    end
  end
  wire rvmt_trace_execute_system = (execute_arbitration_isValid && (execute_INSTRUCTION[6 : 0] == 7'b1110011));
  wire rvmt_trace_writeback_system = (writeBack_arbitration_isValid && (writeBack_INSTRUCTION[6 : 0] == 7'b1110011));
  wire rvmt_trace_syscall = (((execute_arbitration_isValid && (execute_ENV_CTRL == EnvCtrlEnum_ECALL)) || (rvmt_trace_execute_system && (execute_INSTRUCTION[31 : 20] == 12'h000))) && (CsrPlugin_privilege == 2'b00));
  wire rvmt_trace_xret = ((writeBack_arbitration_isValid && (writeBack_ENV_CTRL == EnvCtrlEnum_XRET)) || (rvmt_trace_writeback_system && ((writeBack_INSTRUCTION[31 : 20] == 12'h102) || (writeBack_INSTRUCTION[31 : 20] == 12'h302))));
  wire rvmt_trace_syscall_ret = (rvmt_trace_xret && rvmt_trace_pending_syscall);
  wire rvmt_trace_decode_trap = decodeExceptionPort_valid;
  wire rvmt_trace_fetch_trap = IBusCachedPlugin_decodeExceptionPort_valid;
  wire rvmt_trace_had_exception = (CsrPlugin_exception && (CsrPlugin_exceptionPortCtrl_exceptionContext_code != 4'd8) && (CsrPlugin_exceptionPortCtrl_exceptionContext_code != 4'd9) && (CsrPlugin_exceptionPortCtrl_exceptionContext_code != 4'd11));
  wire rvmt_trace_self_trap = (rvmt_trace_decode_trap || rvmt_trace_fetch_trap || (CsrPlugin_selfException_valid && (! rvmt_trace_syscall)) || rvmt_trace_had_exception);
  wire rvmt_trace_priv_event = ((rvmt_trace_priv_changed || CsrPlugin_jumpInterface_valid || rvmt_trace_xret) && (! rvmt_trace_syscall_ret));
  wire [1:0] rvmt_trace_xret_new_priv = ((switch_CsrPlugin_l1385 == 2'b01) ? {1'b0,CsrPlugin_sstatus_SPP} : ((switch_CsrPlugin_l1385 == 2'b11) ? CsrPlugin_mstatus_MPP : CsrPlugin_privilege));
  assign rvmt_trace_valid = (rvmt_trace_syscall || rvmt_trace_syscall_ret || rvmt_trace_self_trap || rvmt_trace_priv_event);
  assign rvmt_trace_event = (rvmt_trace_syscall ? 4'd4 : (rvmt_trace_syscall_ret ? 4'd5 : (rvmt_trace_self_trap ? 4'd6 : 4'd9)));
  assign rvmt_trace_priv = CsrPlugin_privilege;
  assign rvmt_trace_old_priv = rvmt_trace_prev_priv;
  assign rvmt_trace_new_priv = (rvmt_trace_xret ? rvmt_trace_xret_new_priv : CsrPlugin_privilege);
  assign rvmt_trace_pc = (rvmt_trace_syscall ? execute_PC : (rvmt_trace_decode_trap ? decode_PC : (rvmt_trace_self_trap ? (rvmt_trace_had_exception ? writeBack_PC : execute_PC) : writeBack_PC)));
  assign rvmt_trace_instr = (rvmt_trace_syscall ? execute_INSTRUCTION : (rvmt_trace_decode_trap ? decode_INSTRUCTION : writeBack_INSTRUCTION));
  assign rvmt_trace_target = ((rvmt_trace_syscall_ret || rvmt_trace_priv_event) ? (CsrPlugin_jumpInterface_valid ? CsrPlugin_jumpInterface_payload : writeBack_PC) : 32'd0);
  assign rvmt_trace_cause = (rvmt_trace_self_trap ? (rvmt_trace_decode_trap ? {28'd0, decodeExceptionPort_payload_code} : (rvmt_trace_fetch_trap ? {28'd0, IBusCachedPlugin_decodeExceptionPort_payload_code} : (rvmt_trace_had_exception ? {28'd0, CsrPlugin_exceptionPortCtrl_exceptionContext_code} : {28'd0, CsrPlugin_selfException_payload_code}))) : 32'd0);
  assign rvmt_trace_tval = (rvmt_trace_self_trap ? (rvmt_trace_decode_trap ? decodeExceptionPort_payload_badAddr : (rvmt_trace_fetch_trap ? IBusCachedPlugin_decodeExceptionPort_payload_badAddr : (rvmt_trace_had_exception ? CsrPlugin_exceptionPortCtrl_exceptionContext_badAddr : CsrPlugin_selfException_payload_badAddr))) : 32'd0);
  assign rvmt_trace_syscall_id = (rvmt_trace_syscall ? rvmt_trace_syscall_seq : rvmt_trace_active_syscall_id);
  assign rvmt_trace_duration = (rvmt_trace_syscall_ret ? (rvmt_trace_cycle - rvmt_trace_entry_cycle) : 32'd0);
  assign rvmt_trace_a0 = rvmt_trace_a0_shadow;
  assign rvmt_trace_a1 = rvmt_trace_a1_shadow;
  assign rvmt_trace_a2 = rvmt_trace_a2_shadow;
  assign rvmt_trace_a3 = rvmt_trace_a3_shadow;
  assign rvmt_trace_a4 = rvmt_trace_a4_shadow;
  assign rvmt_trace_a5 = rvmt_trace_a5_shadow;
  assign rvmt_trace_a6 = rvmt_trace_a6_shadow;
  assign rvmt_trace_a7 = rvmt_trace_a7_shadow;
"""


def _replace_once(text: str, old: str, new: str, *, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"expected one {label}, found {count}")
    return text.replace(old, new, 1)


def _replace_first(text: str, old: str, new: str, *, label: str) -> str:
    count = text.count(old)
    if count < 1:
        raise RuntimeError(f"expected at least one {label}, found {count}")
    return text.replace(old, new, 1)


def patch_cpu(cpu_src: Path, out_dir: Path) -> Path:
    patched = out_dir / f"{CPU_MODULE}_rvmt_trace.v"
    text = cpu_src.read_text(encoding="utf-8")
    if "rvmt_trace_valid" not in text:
        text = _replace_first(
            text,
            "  input               jtag_clk\n);",
            "  input               jtag_clk,\n" + "\n".join(TRACE_PORTS) + "\n);",
            label="CPU module port list",
        )
        text = re.sub(
            r"(module VexRiscv \([\s\S]*?  input\s+debugCd_logic_outputReset\n)\);",
            lambda m: m.group(1) + ",\n" + "\n".join(TRACE_PORTS) + "\n);",
            text,
            count=1,
        )
        text = _replace_once(
            text,
            "    .debugCd_logic_outputReset     (debugCd_logic_outputReset                                                     )  //i\n  );",
            "    .debugCd_logic_outputReset     (debugCd_logic_outputReset                                                     ), //i\n"
            "    .rvmt_trace_valid              (rvmt_trace_valid                                                            ), //o\n"
            "    .rvmt_trace_event              (rvmt_trace_event[3:0]                                                       ), //o\n"
            "    .rvmt_trace_priv               (rvmt_trace_priv[1:0]                                                        ), //o\n"
            "    .rvmt_trace_old_priv           (rvmt_trace_old_priv[1:0]                                                    ), //o\n"
            "    .rvmt_trace_new_priv           (rvmt_trace_new_priv[1:0]                                                    ), //o\n"
            "    .rvmt_trace_pc                 (rvmt_trace_pc[31:0]                                                        ), //o\n"
            "    .rvmt_trace_instr              (rvmt_trace_instr[31:0]                                                     ), //o\n"
            "    .rvmt_trace_target             (rvmt_trace_target[31:0]                                                    ), //o\n"
            "    .rvmt_trace_cause              (rvmt_trace_cause[31:0]                                                     ), //o\n"
            "    .rvmt_trace_tval               (rvmt_trace_tval[31:0]                                                      ), //o\n"
            "    .rvmt_trace_syscall_id         (rvmt_trace_syscall_id[31:0]                                                ), //o\n"
            "    .rvmt_trace_duration           (rvmt_trace_duration[31:0]                                                  ), //o\n"
            "    .rvmt_trace_a0                 (rvmt_trace_a0[31:0]                                                        ), //o\n"
            "    .rvmt_trace_a1                 (rvmt_trace_a1[31:0]                                                        ), //o\n"
            "    .rvmt_trace_a2                 (rvmt_trace_a2[31:0]                                                        ), //o\n"
            "    .rvmt_trace_a3                 (rvmt_trace_a3[31:0]                                                        ), //o\n"
            "    .rvmt_trace_a4                 (rvmt_trace_a4[31:0]                                                        ), //o\n"
            "    .rvmt_trace_a5                 (rvmt_trace_a5[31:0]                                                        ), //o\n"
            "    .rvmt_trace_a6                 (rvmt_trace_a6[31:0]                                                        ), //o\n"
            "    .rvmt_trace_a7                 (rvmt_trace_a7[31:0]                                                       )  //o\n"
            "  );",
            label="inner VexRiscv trace port connection",
        )
        text = _replace_once(
            text,
            "  assign when_CsrPlugin_l1315 = (CsrPlugin_hadException || CsrPlugin_interruptJump);\n",
            "  assign when_CsrPlugin_l1315 = (CsrPlugin_hadException || CsrPlugin_interruptJump);\n" + TRACE_ASSIGNMENTS,
            label="CPU trace assignment insertion point",
        )
    patched.write_text(text, encoding="utf-8", newline="\n")
    return patched


def patch_top(top_path: Path) -> None:
    text = top_path.read_text(encoding="utf-8")
    valid_match = re.search(r"\breg\s+(?P<name>\w+_rvmt_trace_valid)\s*=\s*1'd0;", text)
    if not valid_match:
        valid_match = re.search(r"\bwire\s+(?P<name>\w+_rvmt_trace_valid)\s*;", text)
    if not valid_match:
        raise RuntimeError("could not find generated rvmt_trace_valid signal")
    trace_prefix = valid_match.group("name")[: -len("valid")]
    trace_names = {
        "valid": f"{trace_prefix}valid",
        "event": f"{trace_prefix}event",
        "priv": f"{trace_prefix}priv",
        "old_priv": f"{trace_prefix}old_priv",
        "new_priv": f"{trace_prefix}new_priv",
        "pc": f"{trace_prefix}pc",
        "instr": f"{trace_prefix}instr",
        "target": f"{trace_prefix}target",
        "cause": f"{trace_prefix}cause",
        "tval": f"{trace_prefix}tval",
        "syscall_id": f"{trace_prefix}syscall_id",
        "duration": f"{trace_prefix}duration",
        "a0": f"{trace_prefix}a0",
        "a1": f"{trace_prefix}a1",
        "a2": f"{trace_prefix}a2",
        "a3": f"{trace_prefix}a3",
        "a4": f"{trace_prefix}a4",
        "a5": f"{trace_prefix}a5",
        "a6": f"{trace_prefix}a6",
        "a7": f"{trace_prefix}a7",
    }
    widths = {
        "valid": "",
        "event": "[3:0] ",
        "priv": "[1:0] ",
        "old_priv": "[1:0] ",
        "new_priv": "[1:0] ",
        "pc": "[31:0] ",
        "instr": "[31:0] ",
        "target": "[31:0] ",
        "cause": "[31:0] ",
        "tval": "[31:0] ",
        "syscall_id": "[31:0] ",
        "duration": "[31:0] ",
        "a0": "[31:0] ",
        "a1": "[31:0] ",
        "a2": "[31:0] ",
        "a3": "[31:0] ",
        "a4": "[31:0] ",
        "a5": "[31:0] ",
        "a6": "[31:0] ",
        "a7": "[31:0] ",
    }
    for key, name in trace_names.items():
        text = re.sub(
            rf"\breg\s+(\[[^\]]+\]\s+)?{re.escape(name)}\s*=\s*[^;]+;",
            f"wire   {widths[key]}{name};",
            text,
            count=1,
        )
    trace_port_block = (
        f"\t.rvmt_trace_valid       ({trace_names['valid']}),\n"
        f"\t.rvmt_trace_event       ({trace_names['event']}),\n"
        f"\t.rvmt_trace_priv        ({trace_names['priv']}),\n"
        f"\t.rvmt_trace_old_priv    ({trace_names['old_priv']}),\n"
        f"\t.rvmt_trace_new_priv    ({trace_names['new_priv']}),\n"
        f"\t.rvmt_trace_pc          ({trace_names['pc']}),\n"
        f"\t.rvmt_trace_instr       ({trace_names['instr']}),\n"
        f"\t.rvmt_trace_target      ({trace_names['target']}),\n"
        f"\t.rvmt_trace_cause       ({trace_names['cause']}),\n"
        f"\t.rvmt_trace_tval        ({trace_names['tval']}),\n"
        f"\t.rvmt_trace_syscall_id  ({trace_names['syscall_id']}),\n"
        f"\t.rvmt_trace_duration    ({trace_names['duration']}),\n"
        f"\t.rvmt_trace_a0          ({trace_names['a0']}),\n"
        f"\t.rvmt_trace_a1          ({trace_names['a1']}),\n"
        f"\t.rvmt_trace_a2          ({trace_names['a2']}),\n"
        f"\t.rvmt_trace_a3          ({trace_names['a3']}),\n"
        f"\t.rvmt_trace_a4          ({trace_names['a4']}),\n"
        f"\t.rvmt_trace_a5          ({trace_names['a5']}),\n"
        f"\t.rvmt_trace_a6          ({trace_names['a6']}),\n"
        f"\t.rvmt_trace_a7          ({trace_names['a7']}),"
    )
    if ".rvmt_trace_valid" in text and ".rvmt_trace_a7" not in text:
        text, count = re.subn(
            r"\s*\.rvmt_trace_valid\s*\([^\n]+\),\n"
            r"\s*\.rvmt_trace_event\s*\([^\n]+\),\n"
            r"\s*\.rvmt_trace_priv\s*\([^\n]+\),\n"
            r"\s*\.rvmt_trace_pc\s*\([^\n]+\),\n"
            r"\s*\.rvmt_trace_cause\s*\([^\n]+\),\n"
            r"\s*\.rvmt_trace_tval\s*\([^\n]+\),",
            "\n" + trace_port_block,
            text,
            count=1,
        )
        if count != 1:
            raise RuntimeError(f"expected one old CPU trace port block, found {count}")
    elif ".rvmt_trace_valid" not in text:
        text, count = re.subn(
            r"(\s*\.plicWishbone_WE\s*\(\w*soclinux_plicbus_we\),)\s*\n\s*// Outputs\.",
            r"\1\n"
            + trace_port_block
            + "\n\n\t// Outputs.",
            text,
            count=1,
        )
        if count != 1:
            raise RuntimeError(f"expected one CPU instance port list, found {count}")
    top_path.write_text(text, encoding="utf-8", newline="\n")


def patch_tcl(tcl_path: Path, cpu_src: Path, patched_cpu: Path) -> None:
    text = tcl_path.read_text(encoding="utf-8")
    cpu_pattern = re.escape(str(cpu_src))
    text, count = re.subn(cpu_pattern, lambda _m: str(patched_cpu), text, count=1)
    if count != 1:
        if str(patched_cpu) in text:
            return
        raise RuntimeError(f"expected one read_verilog entry for {cpu_src}, found {count}")
    tcl_path.write_text(text, encoding="utf-8", newline="\n")


def patch_trace_gateware(gateware_dir: Path, cpu_src: Path) -> Path:
    gateware_dir = gateware_dir.resolve()
    cpu_src = cpu_src.resolve()
    patched_cpu = patch_cpu(cpu_src, gateware_dir)
    patch_top(gateware_dir / "embedfire_rise_pro.v")
    patch_tcl(gateware_dir / "embedfire_rise_pro.tcl", cpu_src, patched_cpu)
    shutil.copyfile(gateware_dir / "embedfire_rise_pro.tcl", gateware_dir / "embedfire_rise_pro.rvmt_trace.tcl")
    return patched_cpu
