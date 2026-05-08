from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


TOP = "tb_cva6_direct_xsim_smoke"
SNAPSHOT = f"{TOP}_snap"
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

    compare_src = work_result_dir / "compare.log"
    compare_dst = result_dir / "compare.log"
    if compare_message is not None:
        compare_dst.write_text(compare_message, encoding="utf-8", newline="\n")
    else:
        copy_if_exists(compare_src, compare_dst)

    copy_if_exists(log, result_dir / "run.log")
    copy_if_exists(work_dir / "xsim.log", result_dir / "xsim.log")


def reset_result_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)


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
    if not args.dry_run:
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

    work_result_root = work_dir / "results" / "vivado_sim"
    work_result_root.mkdir(parents=True, exist_ok=True)
    if result_root.exists():
        for test_name, _, _ in CVA6_XSIM_TESTS:
            stale_result = result_root / test_name
            if stale_result.exists():
                shutil.rmtree(stale_result)
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
    run(
        [
            xelab,
            "-L",
            "uvm",
            "--sv_lib",
            "dpi",
            "--sv_root",
            as_posix(work_dir / "xsim.dir" / "work" / "xsc"),
            f"work.{TOP}",
            "-s",
            SNAPSHOT,
            "-debug",
            "typical",
        ],
        cwd=work_dir,
        env=env,
        log=log,
        dry_run=False,
    )
    for test_name, mem_rel, expected_name in CVA6_XSIM_TESTS:
        mem_src = root / "sim" / "programs" / mem_rel
        local_mem = work_dir / "cva6_program.mem"
        work_result_dir = work_result_root / "smoke"
        result_dir = result_root / test_name
        reset_result_dir(work_result_dir)
        reset_result_dir(result_dir)
        shutil.copyfile(mem_src, local_mem)

        xsim_cmd = [xsim, SNAPSHOT]
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
                fatal_message=f"Vivado xsim kernel fatal during {test_name} run.",
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

        try:
            run(
                [
                    sys.executable,
                    as_posix(root / "tools" / "compare_trace.py"),
                    "--trace",
                    as_posix(work_result_dir / "trace.jsonl"),
                    "--expected",
                    as_posix(root / "sim" / "golden" / expected_name),
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
        publish_artifacts(work_dir=work_dir, work_result_dir=work_result_dir, result_dir=result_dir, log=log)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the CVA6 xsim smoke regression.")
    parser.add_argument("--cva6", default="rtl/cva6", help="Path to the CVA6 checkout.")
    parser.add_argument("--target", default="cv64a6_imafdc_sv39")
    parser.add_argument("--vivado-bin", help="Vivado bin directory containing xvlog/xelab/xsim/xsc.")
    parser.add_argument("--work-dir", default="build/cva6_xsim_smoke")
    parser.add_argument("--run-timeout-seconds", type=int, default=900)
    parser.add_argument("--disable-circular-dependency-check", action="store_true")
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
