from __future__ import annotations

import argparse
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


TRACE_TOP = "tb_cva6_direct_xsim_smoke"
TRACE_SNAPSHOT = f"{TRACE_TOP}_snap"
NOTRACE_TOP = "tb_cva6_direct_xsim_notrace_smoke"
NOTRACE_SNAPSHOT = f"{NOTRACE_TOP}_snap"
FULL_SOC_TOP = "tb_cva6_xsim_smoke"
FULL_SOC_SNAPSHOT = f"{FULL_SOC_TOP}_snap"
# addi t0, zero, 1; ebreak; j .
FULL_SOC_SMOKE_MEM = (
    "0010007300100293",
    "000000000000006f",
)
XSIM_FATAL_PATTERNS = [
    "FATAL_ERROR:",
    "Vivado Simulator kernel has discovered an exceptional condition",
]
CVA6_XSIM_TESTS = [
    ("cva6_smoke", "cva6_smoke/cva6_smoke.mem", "cva6_smoke.expected.json"),
    ("cva6_branch", "cva6_branch/cva6_branch.mem", "cva6_branch.expected.json"),
    ("cva6_jump", "cva6_jump/cva6_jump.mem", "cva6_jump.expected.json"),
    ("cva6_ecall", "cva6_ecall/cva6_ecall.mem", "cva6_ecall.expected.json"),
    ("cva6_trap_illegal", "cva6_trap_illegal/cva6_trap_illegal.mem", "cva6_trap_illegal.expected.json"),
    ("cva6_ebreak", "cva6_ebreak/cva6_ebreak.mem", "cva6_ebreak.expected.json"),
]
FULL_SOC_RV64GC_TESTS = [
    ("rv64gc_i_addi", "full_soc_rv64gc_i_addi/full_soc_rv64gc_i_addi.mem", 1, False),
    ("rv64gc_m_mul", "full_soc_rv64gc_m_mul/full_soc_rv64gc_m_mul.mem", 1, False),
    ("rv64gc_c_nop", "full_soc_rv64gc_c_nop/full_soc_rv64gc_c_nop.mem", 1, False),
    ("rv64gc_f_fsgnj_s", "full_soc_rv64gc_f_fsgnj_s/full_soc_rv64gc_f_fsgnj_s.mem", 1, True),
    ("rv64gc_d_fsgnj_d", "full_soc_rv64gc_d_fsgnj_d/full_soc_rv64gc_d_fsgnj_d.mem", 1, True),
    ("rv64gc_a_sc_w", "full_soc_rv64gc_a_sc_w/full_soc_rv64gc_a_sc_w.mem", 1, False),
]
DEFAULT_TOOL_PREFIX = "riscv-none-elf-"
READMEMH_WORD_BYTES = 8
CONTAINER_REPO_ROOT = Path("/workspace/rv-maltrace")


@dataclass(frozen=True)
class ProgramRun:
    name: str
    mem_src: Path
    expected: Path | None
    disasm_src: Path | None = None
    full_soc_pass_retire_count: int | None = None
    full_soc_force_fs_dirty: bool = False


ARIANE_PKG = [
    "corev_apu/tb/ariane_axi_pkg.sv",
    "corev_apu/tb/axi_intf.sv",
    "corev_apu/register_interface/src/reg_intf.sv",
    "corev_apu/tb/ariane_soc_pkg.sv",
    "corev_apu/riscv-dbg/src/dm_pkg.sv",
    "corev_apu/tb/ariane_axi_soc_pkg.sv",
]


SRC_STATIC = [
    "core/cva6_rvfi.sv",
    "corev_apu/src/ariane.sv",
    "corev_apu/axi_mem_if/src/axi2mem.sv",
    "corev_apu/rv_plic/rtl/rv_plic_target.sv",
    "corev_apu/rv_plic/rtl/rv_plic_gateway.sv",
    "corev_apu/rv_plic/rtl/plic_regmap.sv",
    "corev_apu/rv_plic/rtl/plic_top.sv",
    "corev_apu/riscv-dbg/debug_rom/debug_rom.sv",
    "corev_apu/register_interface/src/apb_to_reg.sv",
    "vendor/pulp-platform/axi/src/axi_multicut.sv",
    "vendor/pulp-platform/common_cells/src/rstgen_bypass.sv",
    "vendor/pulp-platform/common_cells/src/rstgen.sv",
    "vendor/pulp-platform/common_cells/src/addr_decode.sv",
    "vendor/pulp-platform/common_cells/src/stream_register.sv",
    "vendor/pulp-platform/axi/src/axi_cut.sv",
    "vendor/pulp-platform/axi/src/axi_join.sv",
    "vendor/pulp-platform/axi/src/axi_delayer.sv",
    "vendor/pulp-platform/axi/src/axi_to_axi_lite.sv",
    "vendor/pulp-platform/axi/src/axi_id_prepend.sv",
    "vendor/pulp-platform/axi/src/axi_atop_filter.sv",
    "vendor/pulp-platform/axi/src/axi_err_slv.sv",
    "vendor/pulp-platform/axi/src/axi_mux.sv",
    "vendor/pulp-platform/axi/src/axi_demux.sv",
    "vendor/pulp-platform/axi/src/axi_xbar.sv",
    "vendor/pulp-platform/common_cells/src/cdc_2phase.sv",
    "vendor/pulp-platform/common_cells/src/spill_register_flushable.sv",
    "vendor/pulp-platform/common_cells/src/spill_register.sv",
    "vendor/pulp-platform/common_cells/src/deprecated/fifo_v1.sv",
    "vendor/pulp-platform/common_cells/src/deprecated/fifo_v2.sv",
    "vendor/pulp-platform/common_cells/src/stream_delay.sv",
    "vendor/pulp-platform/common_cells/src/lfsr_16bit.sv",
    "vendor/pulp-platform/tech_cells_generic/src/deprecated/cluster_clk_cells.sv",
    "vendor/pulp-platform/tech_cells_generic/src/deprecated/pulp_clk_cells.sv",
    "vendor/pulp-platform/tech_cells_generic/src/rtl/tc_clk.sv",
    "corev_apu/instr_tracing/ITI/include/iti_pkg.sv",
    "corev_apu/instr_tracing/rv_tracer-main/include/te_pkg.sv",
    "corev_apu/instr_tracing/rv_encapsulator-main/src/include/encap_pkg.sv",
    "corev_apu/tb/ariane_testharness.sv",
    "corev_apu/tb/ariane_peripherals.sv",
    "corev_apu/tb/rvfi_tracer.sv",
    "corev_apu/tb/common/uart.sv",
    "corev_apu/tb/common/SimDTM.sv",
    "corev_apu/tb/common/SimJTAG.sv",
    "corev_apu/instr_tracing/ITI/cva6_iti/iti.sv",
    "corev_apu/instr_tracing/ITI/cva6_iti/block_retirement.sv",
    "corev_apu/instr_tracing/ITI/cva6_iti/single_retirement.sv",
    "corev_apu/instr_tracing/ITI/cva6_iti/itype_detector.sv",
    "vendor/pulp-platform/common_cells/src/counter.sv",
    "vendor/pulp-platform/common_cells/src/sync.sv",
    "vendor/pulp-platform/common_cells/src/sync_wedge.sv",
    "vendor/pulp-platform/common_cells/src/edge_detect.sv",
    "corev_apu/instr_tracing/rv_tracer-main/rtl/lzc.sv",
    "corev_apu/instr_tracing/rv_tracer-main/rtl/te_branch_map.sv",
    "corev_apu/instr_tracing/rv_tracer-main/rtl/te_filter.sv",
    "corev_apu/instr_tracing/rv_tracer-main/rtl/te_packet_emitter.sv",
    "corev_apu/instr_tracing/rv_tracer-main/rtl/te_priority.sv",
    "corev_apu/instr_tracing/rv_tracer-main/rtl/te_reg.sv",
    "corev_apu/instr_tracing/rv_tracer-main/rtl/te_resync_counter.sv",
    "corev_apu/instr_tracing/rv_tracer-main/rtl/rv_tracer.sv",
    "vendor/pulp-platform/common_cells/src/fifo_v3.sv",
    "corev_apu/instr_tracing/DPTI/slicer_DPTI.sv",
    "corev_apu/instr_tracing/rv_encapsulator-main/src/rtl/encapsulator.sv",
]


INCDIRS = [
    "vendor/pulp-platform/common_cells/include",
    "vendor/pulp-platform/axi/include",
    "corev_apu/register_interface/include",
    "corev_apu/tb/common",
    "verif/core-v-verif/lib/uvm_agents/uvma_rvfi",
    "verif/core-v-verif/lib/uvm_components/uvmc_rvfi_reference_model",
    "verif/core-v-verif/lib/uvm_components/uvmc_rvfi_scoreboard",
    "verif/core-v-verif/lib/uvm_agents/uvma_core_cntrl",
    "verif/tb/core",
    "core/include",
    "corev_apu/instr_tracing/ITI/include",
]


def repo_root() -> Path:
    cwd = Path.cwd().resolve()
    for parent in [cwd, *cwd.parents]:
        if (parent / "pyproject.toml").exists() and (parent / "rtl" / "cva6").exists():
            return parent
    raise RuntimeError("Could not find rv-maltrace repository root.")


def as_posix(path: Path) -> str:
    return path.resolve().as_posix()


def resolve_tool(name: str, vivado_bin: Path | None) -> str:
    names = [name]
    if os.name == "nt":
        names = [f"{name}.bat", f"{name}.exe", name]
    if vivado_bin:
        for candidate in names:
            path = vivado_bin / candidate
            if path.exists():
                return str(path)
    for candidate in names:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    raise RuntimeError(f"Vivado tool not found: {name}")


def resolve_prefixed_tool(name: str, prefix: str) -> str:
    configured = f"{prefix}{name}"
    resolved = shutil.which(configured)
    return resolved or configured


def select_tool_mode(prefix: str, requested: str) -> str:
    if requested != "auto":
        return requested
    return "local" if shutil.which(f"{prefix}gcc") and shutil.which(f"{prefix}objcopy") else "docker"


def container_path(root: Path, path: Path) -> str:
    resolved = path.resolve()
    try:
        rel = resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise RuntimeError(f"Docker tool mode requires inputs under the repository root: {resolved}") from exc
    return (CONTAINER_REPO_ROOT / rel.as_posix()).as_posix()


def shell_join(cmd: list[str]) -> str:
    return " ".join(shlex.quote(item) for item in cmd)


def docker_compose_cmd(root: Path, inner_cmd: list[str]) -> list[str]:
    return [
        "docker",
        "compose",
        "-f",
        str(root / "docker-compose.toolchain.yml"),
        "run",
        "--rm",
        "cva6-toolchain",
        "bash",
        "-lc",
        shell_join(inner_cmd),
    ]


def sanitize_result_name(raw: str) -> str:
    name = re.sub(r"[^A-Za-z0-9_.-]+", "_", raw).strip("._-")
    return name or "custom"


def custom_input_count(args: argparse.Namespace) -> int:
    return sum(value is not None for value in (args.asm, args.elf, args.bin, args.mem))


def has_custom_program(args: argparse.Namespace) -> bool:
    return custom_input_count(args) > 0


def write_readmemh_from_binary(binary_path: Path, mem_path: Path) -> None:
    data = binary_path.read_bytes()
    if not data:
        raise RuntimeError(f"empty program binary: {binary_path}")
    mem_path.parent.mkdir(parents=True, exist_ok=True)
    with mem_path.open("w", encoding="utf-8", newline="\n") as handle:
        for offset in range(0, len(data), READMEMH_WORD_BYTES):
            chunk = data[offset : offset + READMEMH_WORD_BYTES].ljust(READMEMH_WORD_BYTES, b"\0")
            handle.write(f"{int.from_bytes(chunk, byteorder='little'):016x}\n")


def run_tool(
    *,
    root: Path,
    args: argparse.Namespace,
    tool: str,
    tool_args: list[Path | str],
    cwd: Path,
    env: dict[str, str],
    log: Path,
) -> str:
    mode = select_tool_mode(args.tool_prefix, args.tool_mode)
    if mode == "local":
        return run(
            [resolve_prefixed_tool(tool, args.tool_prefix), *(str(item) for item in tool_args)],
            cwd=cwd,
            env=env,
            log=log,
            dry_run=False,
        )

    docker_tool = f"/opt/riscv/bin/{args.tool_prefix}{tool}"
    converted_args = [
        container_path(root, item) if isinstance(item, Path) else item
        for item in tool_args
    ]
    return run(
        docker_compose_cmd(root, [docker_tool, *converted_args]),
        cwd=root,
        env=env,
        log=log,
        dry_run=False,
    )


def ensure_clean_workdir(root: Path, work_dir: Path) -> None:
    resolved = work_dir.resolve()
    build_dir = (root / "build").resolve()
    if build_dir != resolved and build_dir not in resolved.parents:
        raise RuntimeError(f"Refusing to clean work directory outside build/: {resolved}")
    if work_dir.exists():
        shutil.rmtree(work_dir)
    work_dir.mkdir(parents=True)


def write_lines(path: Path, lines: list[Path | str]) -> None:
    path.write_text(
        "".join(f"{item if isinstance(item, str) else as_posix(item)}\n" for item in lines),
        encoding="utf-8",
        newline="\n",
    )


def kill_process_tree(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    else:
        process.kill()


def run(
    cmd: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    log: Path,
    dry_run: bool,
    timeout: int | None = None,
    fatal_patterns: list[str] | None = None,
    fatal_message: str | None = None,
) -> str:
    rendered = " ".join(cmd)
    print(f"+ {rendered}")
    if dry_run:
        return ""
    with log.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(f"+ {rendered}\n")
        process = subprocess.Popen(
            cmd,
            cwd=cwd,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        try:
            stdout, _ = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            kill_process_tree(process)
            stdout, _ = process.communicate()
            handle.write(stdout)
            raise RuntimeError(f"Command timed out after {timeout}s: {rendered}\nSee {log}")
        handle.write(stdout)
        if fatal_patterns and any(pattern in stdout for pattern in fatal_patterns):
            message = fatal_message or "Command output matched a fatal pattern."
            raise RuntimeError(f"{message}\nSee {log}")
        if process.returncode:
            raise RuntimeError(f"Command failed with exit code {process.returncode}: {rendered}\nSee {log}")
        return stdout


def copy_if_exists(src: Path, dst: Path) -> None:
    if src.exists():
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)


def publish_artifacts(
    *,
    work_dir: Path,
    work_result_dir: Path,
    result_dir: Path,
    log: Path,
    compare_message: str | None = None,
) -> None:
    result_dir.mkdir(parents=True, exist_ok=True)

    trace_src = work_result_dir / "trace.jsonl"
    trace_dst = result_dir / "trace.jsonl"
    if trace_src.exists():
        shutil.copy2(trace_src, trace_dst)
    elif compare_message is not None:
        trace_dst.write_text("", encoding="utf-8", newline="\n")
    copy_if_exists(work_result_dir / "trace.disasm.jsonl", result_dir / "trace.disasm.jsonl")
    copy_if_exists(work_result_dir / "program.dump", result_dir / "program.dump")

    compare_src = work_result_dir / "compare.log"
    compare_dst = result_dir / "compare.log"
    if compare_message is not None:
        if compare_src.exists():
            shutil.copy2(compare_src, compare_dst)
            with compare_dst.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(compare_message)
        else:
            compare_dst.write_text(compare_message, encoding="utf-8", newline="\n")
    else:
        copy_if_exists(compare_src, compare_dst)

    copy_if_exists(log, result_dir / "run.log")
    if (work_result_dir / "xsim.log").exists():
        shutil.copy2(work_result_dir / "xsim.log", result_dir / "xsim.log")
    else:
        copy_if_exists(work_dir / "xsim.log", result_dir / "xsim.log")
    copy_if_exists(work_result_dir / "xsim_notrace.log", result_dir / "xsim_notrace.log")


def reset_result_dir(path: Path) -> None:
    if path.exists():
        for attempt in range(10):
            try:
                shutil.rmtree(path)
                break
            except PermissionError:
                if attempt == 9:
                    raise
                time.sleep(0.5)
    path.mkdir(parents=True)


def prepare_custom_program(
    root: Path,
    args: argparse.Namespace,
    work_dir: Path,
    env: dict[str, str],
    log: Path,
) -> ProgramRun | None:
    count = custom_input_count(args)
    if count == 0:
        return None
    if count != 1:
        raise RuntimeError("choose exactly one custom program input: --asm, --elf, --bin, or --mem")

    raw_name = args.name
    input_path = (args.asm or args.elf or args.bin or args.mem).resolve()
    if not input_path.exists():
        raise RuntimeError(f"custom program input does not exist: {input_path}")
    name = sanitize_result_name(raw_name or f"custom_{input_path.stem}")
    custom_dir = work_dir / "custom_program" / name
    custom_dir.mkdir(parents=True, exist_ok=True)

    expected = args.expected.resolve() if args.expected else None
    if expected and not expected.exists():
        raise RuntimeError(f"expected trace file does not exist: {expected}")

    if args.mem:
        return ProgramRun(name=name, mem_src=input_path, expected=expected)

    binary = custom_dir / f"{name}.bin"
    mem = custom_dir / f"{name}.mem"
    disasm_src: Path | None = None
    if args.asm:
        asm_source = custom_dir / input_path.name
        shutil.copy2(input_path, asm_source)
        common_dir = root / "sim" / "programs" / "common"
        linker = (args.linker.resolve() if args.linker else common_dir / "linker.ld")
        if not linker.exists():
            raise RuntimeError(f"linker script does not exist: {linker}")
        sources = [] if args.no_runtime else [
            common_dir / "crt0.S",
            common_dir / "finish.S",
            common_dir / "trap_vector.S",
        ]
        sources.append(asm_source)
        elf = custom_dir / f"{name}.elf"
        run_tool(
            root=root,
            args=args,
            tool="gcc",
            tool_args=[
                "-march=rv64gc",
                "-mabi=lp64d",
                "-nostdlib",
                "-ffreestanding",
                "-Wl,--no-relax",
                "-T",
                linker,
                "-I",
                common_dir,
                *(item for include_dir in args.include for item in ("-I", include_dir)),
                *args.cflag,
                *sources,
                "-o",
                elf,
            ],
            cwd=root,
            env=env,
            log=log,
        )
        run_tool(
            root=root,
            args=args,
            tool="objcopy",
            tool_args=["-O", "binary", elf, binary],
            cwd=root,
            env=env,
            log=log,
        )
    elif args.elf:
        elf = custom_dir / input_path.name
        shutil.copy2(input_path, elf)
        run_tool(
            root=root,
            args=args,
            tool="objcopy",
            tool_args=["-O", "binary", elf, binary],
            cwd=root,
            env=env,
            log=log,
        )
    else:
        shutil.copy2(input_path, binary)

    if args.asm or args.elf:
        dump = custom_dir / f"{name}.dump"
        dump.write_text(
            run_tool(
                root=root,
                args=args,
                tool="objdump",
                tool_args=["-d", elf],
                cwd=root,
                env=env,
                log=log,
            ),
            encoding="utf-8",
            newline="\n",
        )
        disasm_src = dump

    write_readmemh_from_binary(binary, mem)
    return ProgramRun(name=name, mem_src=mem, expected=expected, disasm_src=disasm_src)


def remove_public_cva6_results(result_root: Path) -> None:
    if not result_root.exists():
        return
    for test_name, _, _ in CVA6_XSIM_TESTS:
        stale_result = result_root / test_name
        if stale_result.exists():
            shutil.rmtree(stale_result)


def remove_public_full_soc_rv64gc_results(result_root: Path) -> None:
    if not result_root.exists():
        return
    for stale_result in result_root.glob("cva6_full_soc_rv64gc_*"):
        if stale_result.is_dir():
            shutil.rmtree(stale_result)


def flatten_core_flist(root: Path, cva6_root: Path, work_dir: Path, env: dict[str, str], dry_run: bool) -> tuple[list[Path], list[Path]]:
    flat = work_dir / "Flist.cva6.flat"
    source_file = work_dir / "Flist.cva6.sources"
    incdir_file = work_dir / "Flist.cva6.incdirs"

    cmd = [
        sys.executable,
        str(cva6_root / "util" / "flist_flattener.py"),
        "--print_incdir",
        "--print_newline",
        str(cva6_root / "core" / "Flist.cva6"),
        str(flat),
    ]
    run(cmd, cwd=root, env=env, log=work_dir / "flist.log", dry_run=dry_run)
    if dry_run:
        return [], []

    sources: list[Path] = []
    incdirs: list[Path] = []
    for raw_line in flat.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("+incdir+"):
            incdirs.append(Path(line[len("+incdir+") :]).resolve())
        elif line.startswith("+"):
            continue
        else:
            sources.append(Path(line).resolve())

    write_lines(source_file, sources)
    write_lines(incdir_file, incdirs)
    return sources, incdirs


def glob_rel(cva6_root: Path, pattern: str) -> list[Path]:
    return sorted(cva6_root.glob(pattern))


def cva6_sources(root: Path, cva6_root: Path) -> list[Path]:
    sources: list[Path] = [
        root / "rtl" / "trace" / "trace_pkg.sv",
        root / "rtl" / "trace" / "cva6_rvfi_trace_adapter.sv",
        root / "sim" / "tb" / "tb_trace_sink.sv",
    ]
    sources.extend(cva6_root / item for item in SRC_STATIC)
    sources[5:5] = glob_rel(cva6_root, "corev_apu/bootrom/*.sv")
    sources[6:6] = glob_rel(cva6_root, "corev_apu/clint/*.sv")
    insert = 8
    for pattern in [
        "corev_apu/fpga/src/axi2apb/src/*.sv",
        "corev_apu/fpga/src/apb_timer/*.sv",
        "corev_apu/fpga/src/axi_slice/src/*.sv",
        "vendor/pulp-platform/axi_riscv_atomics/src/*.sv",
        "corev_apu/riscv-dbg/src/*.sv",
    ]:
        matched = glob_rel(cva6_root, pattern)
        sources[insert:insert] = matched
        insert += len(matched)
    sources.append(root / "sim" / "tb" / "tb_cva6_direct_xsim_smoke.sv")
    sources.append(root / "sim" / "tb" / "tb_cva6_xsim_smoke.sv")
    return sources


def compile_args(incdirs: list[Path]) -> list[str]:
    args: list[str] = []
    for incdir in incdirs:
        args.extend(["-i", as_posix(incdir)])
    return args


def run_program(
    *,
    root: Path,
    work_dir: Path,
    work_result_root: Path,
    result_root: Path,
    env: dict[str, str],
    log: Path,
    xsim: str,
    args: argparse.Namespace,
    program: ProgramRun,
) -> None:
    local_mem = work_dir / "cva6_program.mem"
    work_result_dir = work_result_root / "smoke"
    result_dir = result_root / program.name
    reset_result_dir(work_result_dir)
    reset_result_dir(result_dir)
    shutil.copyfile(program.mem_src, local_mem)

    xsim_cmd = [xsim, TRACE_SNAPSHOT]
    if args.disable_circular_dependency_check:
        xsim_cmd.append("--disable_circular_dependency_check")
    xsim_cmd.append("--runall")
    try:
        run(
            xsim_cmd,
            cwd=work_dir,
            env=env,
            log=log,
            dry_run=False,
            timeout=args.run_timeout_seconds,
            fatal_patterns=XSIM_FATAL_PATTERNS,
            fatal_message=f"Vivado xsim kernel fatal during {program.name} run.",
        )
    except RuntimeError as exc:
        message = str(exc).splitlines()[0]
        status = "BLOCKED" if "kernel fatal" in message.lower() else "FAIL"
        publish_artifacts(
            work_dir=work_dir,
            work_result_dir=work_result_dir,
            result_dir=result_dir,
            log=log,
            compare_message=f"[{status}] {message}\n",
        )
        raise
    copy_if_exists(work_dir / "xsim.log", work_result_dir / "xsim.log")

    if program.expected is not None:
        try:
            run(
                [
                    sys.executable,
                    as_posix(root / "tools" / "compare_trace.py"),
                    "--trace",
                    as_posix(work_result_dir / "trace.jsonl"),
                    "--expected",
                    as_posix(program.expected),
                    "--log",
                    as_posix(work_result_dir / "compare.log"),
                ],
                cwd=root,
                env=env,
                log=log,
                dry_run=False,
            )
        except RuntimeError:
            publish_artifacts(work_dir=work_dir, work_result_dir=work_result_dir, result_dir=result_dir, log=log)
            raise
    else:
        (work_result_dir / "compare.log").write_text(
            "[INFO] no expected golden supplied; trace captured without JSONL comparison\n",
            encoding="utf-8",
            newline="\n",
        )

    if program.disasm_src is not None and (work_result_dir / "trace.jsonl").exists():
        dump_dst = work_result_dir / "program.dump"
        shutil.copy2(program.disasm_src, dump_dst)
        run(
            [
                sys.executable,
                as_posix(root / "tools" / "annotate_trace_disasm.py"),
                "--trace",
                as_posix(work_result_dir / "trace.jsonl"),
                "--objdump",
                as_posix(dump_dst),
                "--out",
                as_posix(work_result_dir / "trace.disasm.jsonl"),
            ],
            cwd=root,
            env=env,
            log=log,
            dry_run=False,
        )

    notrace_cmd = [xsim, NOTRACE_SNAPSHOT]
    if args.disable_circular_dependency_check:
        notrace_cmd.append("--disable_circular_dependency_check")
    notrace_cmd.append("--runall")
    try:
        run(
            notrace_cmd,
            cwd=work_dir,
            env=env,
            log=log,
            dry_run=False,
            timeout=args.run_timeout_seconds,
            fatal_patterns=XSIM_FATAL_PATTERNS,
            fatal_message=f"Vivado xsim kernel fatal during {program.name} no-trace run.",
        )
    except RuntimeError as exc:
        message = str(exc).splitlines()[0]
        copy_if_exists(work_dir / "xsim.log", work_result_dir / "xsim_notrace.log")
        publish_artifacts(
            work_dir=work_dir,
            work_result_dir=work_result_dir,
            result_dir=result_dir,
            log=log,
            compare_message=f"[FAIL] no-trace final result mismatch for {program.name}: {message}\n",
        )
        raise
    copy_if_exists(work_dir / "xsim.log", work_result_dir / "xsim_notrace.log")
    with (work_result_dir / "compare.log").open("a", encoding="utf-8", newline="\n") as handle:
        handle.write("[PASS] no-trace final result reached tohost PASS\n")
    publish_artifacts(work_dir=work_dir, work_result_dir=work_result_dir, result_dir=result_dir, log=log)


def run_full_soc_smoke(
    *,
    root: Path,
    work_dir: Path,
    work_result_root: Path,
    result_root: Path,
    env: dict[str, str],
    log: Path,
    xsim: str,
    args: argparse.Namespace,
    program: ProgramRun,
) -> None:
    local_mem = work_dir / "cva6_smoke.mem"
    work_result_dir = work_result_root / "smoke"
    result_dir = result_root / ("cva6_full_soc_smoke" if program.name == "cva6_smoke" else f"cva6_full_soc_{program.name}")
    reset_result_dir(work_result_dir)
    reset_result_dir(result_dir)
    if program.name == "cva6_smoke":
        local_mem.write_text("\n".join(FULL_SOC_SMOKE_MEM) + "\n", encoding="utf-8", newline="\n")
    else:
        shutil.copyfile(program.mem_src, local_mem)

    xsim_cmd = [xsim, FULL_SOC_SNAPSHOT]
    if args.disable_circular_dependency_check:
        xsim_cmd.append("--disable_circular_dependency_check")
    xsim_cmd.extend(["--testplusarg", "debug_disable"])
    if args.full_soc_debug_progress:
        xsim_cmd.extend(["--testplusarg", "RVMT_DEBUG_PROGRESS"])
    if args.full_soc_store_path_only:
        xsim_cmd.extend(["--testplusarg", "RVMT_STORE_PATH_ONLY"])
    if program.full_soc_force_fs_dirty or args.full_soc_force_fs_dirty:
        xsim_cmd.extend(["--testplusarg", "RVMT_FORCE_FS_DIRTY"])
    pass_retire_count = program.full_soc_pass_retire_count or args.full_soc_pass_retire_count
    if pass_retire_count:
        xsim_cmd.extend(["--testplusarg", f"RVMT_PASS_RETIRE_COUNT_{pass_retire_count}"])
    xsim_cmd.append("--runall")
    try:
        run(
            xsim_cmd,
            cwd=work_dir,
            env=env,
            log=log,
            dry_run=False,
            timeout=args.run_timeout_seconds,
            fatal_patterns=XSIM_FATAL_PATTERNS,
            fatal_message=f"Vivado xsim kernel fatal during {program.name} full SoC smoke run.",
        )
    except RuntimeError as exc:
        message = str(exc).splitlines()[0]
        lowered = message.lower()
        copy_if_exists(work_dir / "xsim.log", work_result_dir / "xsim.log")
        transcript = (work_dir / "xsim.log").read_text(encoding="utf-8", errors="replace") if (work_dir / "xsim.log").exists() else ""
        if "timed out" in lowered and "[rvmt] CVA6 xsim smoke PASS" in transcript:
            if args.full_soc_store_path_only:
                pass_message = "[PASS] full SoC UART/MMIO store-path observation PASS\n"
            elif program.name == "cva6_smoke":
                pass_message = "[PASS] full SoC smoke reached breakpoint PASS\n"
            else:
                pass_message = f"[PASS] full SoC {program.name} reached retire-count PASS before xsim timeout\n"
            (work_result_dir / "compare.log").write_text(pass_message, encoding="utf-8", newline="\n")
            publish_artifacts(work_dir=work_dir, work_result_dir=work_result_dir, result_dir=result_dir, log=log)
            return
        status = "BLOCKED" if "kernel fatal" in lowered or "timed out" in lowered else "FAIL"
        publish_artifacts(
            work_dir=work_dir,
            work_result_dir=work_result_dir,
            result_dir=result_dir,
            log=log,
            compare_message=f"[{status}] {message}\n",
        )
        raise

    copy_if_exists(work_dir / "xsim.log", work_result_dir / "xsim.log")
    transcript = (work_dir / "xsim.log").read_text(encoding="utf-8", errors="replace") if (work_dir / "xsim.log").exists() else ""
    if "Fatal:" in transcript or "[rvmt] CVA6 xsim smoke PASS" not in transcript:
        message = "full SoC smoke did not report PASS"
        publish_artifacts(
            work_dir=work_dir,
            work_result_dir=work_result_dir,
            result_dir=result_dir,
            log=log,
            compare_message=f"[FAIL] {message}\n",
        )
        raise RuntimeError(f"{message}. See {work_dir / 'xsim.log'}")

    if args.full_soc_store_path_only:
        pass_message = "[PASS] full SoC UART/MMIO store-path observation PASS\n"
    elif program.name == "cva6_smoke":
        pass_message = "[PASS] full SoC smoke reached breakpoint PASS\n"
    else:
        pass_message = f"[PASS] full SoC {program.name} reached tohost PASS\n"
    (work_result_dir / "compare.log").write_text(pass_message, encoding="utf-8", newline="\n")
    publish_artifacts(work_dir=work_dir, work_result_dir=work_result_dir, result_dir=result_dir, log=log)


def build(root: Path, args: argparse.Namespace) -> None:
    cva6_root = (root / args.cva6).resolve()
    work_dir = (root / args.work_dir).resolve()
    vivado_bin = Path(args.vivado_bin).resolve() if args.vivado_bin else None
    result_root = (root / "results" / "vivado_sim").resolve()

    env = os.environ.copy()
    env["CVA6_REPO_DIR"] = as_posix(cva6_root)
    env["HPDCACHE_DIR"] = as_posix(cva6_root / "core" / "cache_subsystem" / "hpdcache")
    env["TARGET_CFG"] = args.target
    if vivado_bin:
        env["PATH"] = f"{vivado_bin}{os.pathsep}{env.get('PATH', '')}"

    log = work_dir / "run.log"
    custom = has_custom_program(args)
    if not args.dry_run:
        if not custom and not args.full_soc_smoke:
            remove_public_cva6_results(result_root)
        if args.full_soc_rv64gc_suite:
            remove_public_full_soc_rv64gc_results(result_root)
        ensure_clean_workdir(root, work_dir)

    xvlog = resolve_tool("xvlog", vivado_bin)
    xvhdl = resolve_tool("xvhdl", vivado_bin)
    xelab = resolve_tool("xelab", vivado_bin)
    xsim = resolve_tool("xsim", vivado_bin)
    xsc = resolve_tool("xsc", vivado_bin)

    _, core_incdirs = flatten_core_flist(root, cva6_root, work_dir, env, args.dry_run)
    all_incdirs = list(dict.fromkeys(core_incdirs + [(cva6_root / item).resolve() for item in INCDIRS if (cva6_root / item).exists()]))
    inc_args = compile_args(all_incdirs)

    if args.dry_run:
        return

    custom_program = prepare_custom_program(root, args, work_dir, env, log)
    if args.full_soc_rv64gc_suite:
        programs = [
            ProgramRun(
                name=test_name,
                mem_src=root / "sim" / "programs" / mem_rel,
                expected=None,
                full_soc_pass_retire_count=retire_count,
                full_soc_force_fs_dirty=force_fs_dirty,
            )
            for test_name, mem_rel, retire_count, force_fs_dirty in FULL_SOC_RV64GC_TESTS
        ]
    elif custom_program is not None:
        programs = [custom_program]
    else:
        programs = [
            ProgramRun(
                name=test_name,
                mem_src=root / "sim" / "programs" / mem_rel,
                expected=root / "sim" / "golden" / expected_name,
            )
            for test_name, mem_rel, expected_name in CVA6_XSIM_TESTS
        ]

    work_result_root = work_dir / "results" / "vivado_sim"
    work_result_root.mkdir(parents=True, exist_ok=True)
    pkg_file = work_dir / "ariane_pkg.files"
    src_file = work_dir / "src.files"
    vhdl_file = work_dir / "uart_vhdl.files"
    write_lines(pkg_file, [cva6_root / item for item in ARIANE_PKG])
    write_lines(src_file, cva6_sources(root, cva6_root))
    write_lines(vhdl_file, glob_rel(cva6_root, "corev_apu/fpga/src/apb_uart/src/vhdl_orig/*.vhd"))

    common_xvlog = [
        xvlog,
        "-sv",
        "-L",
        "uvm",
        "-d",
        "XSIM",
        "-d",
        "RV_MALTRACE_TRACE",
    ]
    run(
        common_xvlog + inc_args + ["-f", as_posix(work_dir / "Flist.cva6.sources")],
        cwd=work_dir,
        env=env,
        log=log,
        dry_run=False,
    )
    run(common_xvlog + inc_args + ["-f", as_posix(pkg_file)], cwd=work_dir, env=env, log=log, dry_run=False)
    run([xvhdl, "-2008", "-f", as_posix(vhdl_file)], cwd=work_dir, env=env, log=log, dry_run=False)
    run(common_xvlog + inc_args + ["-f", as_posix(src_file)], cwd=work_dir, env=env, log=log, dry_run=False)
    run([xsc, as_posix(root / "sim" / "dpi" / "xsim_dpi_stubs.c")], cwd=work_dir, env=env, log=log, dry_run=False)
    common_xelab = [
        xelab,
        "-L",
        "uvm",
        "--sv_lib",
        "dpi",
        "--sv_root",
        as_posix(work_dir / "xsim.dir" / "work" / "xsc"),
        "--timescale",
        "1ns/1ps",
        "--override_timeunit",
        "--override_timeprecision",
    ]
    if args.full_soc_smoke:
        run(
            common_xelab
            + [
                f"work.{FULL_SOC_TOP}",
                "-s",
                FULL_SOC_SNAPSHOT,
            ],
            cwd=work_dir,
            env=env,
            log=log,
            dry_run=False,
            fatal_patterns=XSIM_FATAL_PATTERNS,
            fatal_message=f"Vivado xsim kernel fatal during {FULL_SOC_TOP} elaboration.",
        )
        blocked_errors: list[str] = []
        for program in programs:
            try:
                run_full_soc_smoke(
                    root=root,
                    work_dir=work_dir,
                    work_result_root=work_result_root,
                    result_root=result_root,
                    env=env,
                    log=log,
                    xsim=xsim,
                    args=args,
                    program=program,
                )
            except RuntimeError as exc:
                if not args.full_soc_allow_suite_blocked:
                    raise
                compare_log = result_root / f"cva6_full_soc_{program.name}" / "compare.log"
                if compare_log.exists() and "[BLOCKED]" in compare_log.read_text(encoding="utf-8", errors="replace"):
                    blocked_errors.append(f"{program.name}: {str(exc).splitlines()[0]}")
                    continue
                raise
        if blocked_errors:
            for item in blocked_errors:
                print(f"[rvmt] allowed full-SoC suite BLOCKED: {item}")
        return

    run(
        common_xelab
        + [
            f"work.{TRACE_TOP}",
            "-s",
            TRACE_SNAPSHOT,
            "-debug",
            "typical",
        ],
        cwd=work_dir,
        env=env,
        log=log,
        dry_run=False,
    )
    run(
        common_xelab
        + [
            f"work.{NOTRACE_TOP}",
            "-s",
            NOTRACE_SNAPSHOT,
            "-debug",
            "typical",
        ],
        cwd=work_dir,
        env=env,
        log=log,
        dry_run=False,
    )
    for program in programs:
        run_program(
            root=root,
            work_dir=work_dir,
            work_result_root=work_result_root,
            result_root=result_root,
            env=env,
            log=log,
            xsim=xsim,
            args=args,
            program=program,
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the CVA6 xsim smoke regression.")
    parser.add_argument("--cva6", default="rtl/cva6", help="Path to the CVA6 checkout.")
    parser.add_argument("--target", default="cv64a6_imafdc_sv39")
    parser.add_argument("--vivado-bin", help="Vivado bin directory containing xvlog/xelab/xsim/xsc.")
    parser.add_argument("--work-dir", default="build/cva6_xsim_smoke")
    parser.add_argument("--run-timeout-seconds", type=int, default=900)
    parser.add_argument("--disable-circular-dependency-check", action="store_true")
    parser.add_argument("--full-soc-debug-progress", action="store_true")
    parser.add_argument("--full-soc-store-path-only", action="store_true")
    parser.add_argument("--full-soc-pass-retire-count", type=int, default=0)
    parser.add_argument("--full-soc-force-fs-dirty", action="store_true")
    parser.add_argument("--full-soc-rv64gc-suite", action="store_true")
    parser.add_argument("--full-soc-allow-suite-blocked", action="store_true")
    parser.add_argument(
        "--full-soc-smoke",
        action="store_true",
        help="Elaborate and run the ariane_testharness full SoC smoke instead of the direct-core matrix.",
    )
    parser.add_argument("--asm", type=Path, help="Custom RISC-V assembly source to compile and run.")
    parser.add_argument("--elf", type=Path, help="Custom RISC-V ELF image to objcopy to a direct-core memory image.")
    parser.add_argument("--bin", type=Path, help="Custom raw binary image loaded at the direct-core DRAM base.")
    parser.add_argument("--mem", type=Path, help="Custom $readmemh image with one little-endian 64-bit word per line.")
    parser.add_argument("--name", help="Result name under results/vivado_sim/ for a custom program.")
    parser.add_argument("--expected", type=Path, help="Optional JSON golden to compare a custom trace against.")
    parser.add_argument("--tool-prefix", default=DEFAULT_TOOL_PREFIX, help="RISC-V tool prefix for --asm/--elf.")
    parser.add_argument(
        "--tool-mode",
        choices=("auto", "local", "docker"),
        default="auto",
        help="How to run RISC-V compiler tools for --asm/--elf. auto uses local tools when present, otherwise Docker.",
    )
    parser.add_argument("--linker", type=Path, help="Linker script for --asm. Defaults to sim/programs/common/linker.ld.")
    parser.add_argument("--include", type=Path, action="append", default=[], help="Extra include directory for --asm.")
    parser.add_argument("--cflag", action="append", default=[], help="Extra compiler flag for --asm. May be repeated.")
    parser.add_argument("--no-runtime", action="store_true", help="For --asm, do not link the rv-maltrace crt0/trap/finish runtime.")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    try:
        build(repo_root(), args)
    except Exception as exc:
        print(f"run_cva6_xsim: error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
