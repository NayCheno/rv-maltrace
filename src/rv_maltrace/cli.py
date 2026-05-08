from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Iterable


BOARD_DEFAULTS = {
    "genesys2": ("xc7k325tffg900-2", "digilentinc.com:genesys2:part0:1.1"),
    "kc705": ("xc7k325tffg900-2", "xilinx.com:kc705:part0:1.5"),
    "vc707": ("xc7vx485tffg1761-2", "xilinx.com:vc707:part0:1.3"),
    "nexys_video": ("xc7a200tsbg484-1", "digilentinc.com:nexys_video:part0:1.1"),
}

TASK_ALIASES = {
    "help": "help",
    "docker": "docker:build",
    "docker:build": "docker:build",
    "image": "docker:build",
    "image:build": "docker:build",
    "tool": "toolchain:build",
    "tool:build": "toolchain:build",
    "toolchain": "toolchain:build",
    "toolchain:build": "toolchain:build",
    "bootrom": "bootrom:build",
    "bootrom:build": "bootrom:build",
    "bitstream": "bitstream:build",
    "bitstream:build": "bitstream:build",
    "fpga": "bitstream:build",
    "fpga:build": "bitstream:build",
    "vivado": "vivado:check",
    "vivado:check": "vivado:check",
    "config": "config:show",
    "config:show": "config:show",
    "tasks": "tasks:list",
    "tasks:list": "tasks:list",
    "completion": "completion:powershell",
    "completion:bash": "completion:bash",
    "completion:ps1": "completion:powershell",
    "completion:powershell": "completion:powershell",
    "completion:zsh": "completion:zsh",
}

DISPLAY_TASKS = [
    "docker:build",
    "toolchain:build",
    "bootrom:build",
    "vivado:check",
    "bitstream:build",
    "config:show",
    "tasks:list",
    "completion:powershell",
    "completion:bash",
    "completion:zsh",
]

COMPLETION_CANDIDATES = sorted(
    {
        "--dry-run",
        "--help",
        "-h",
        "docker/tool/bootrom/bitstream",
        "docker/toolchain/bootrom/bitstream",
        "tool/bootrom/bitstream",
        *TASK_ALIASES.keys(),
        *DISPLAY_TASKS,
    }
)


class TaskError(RuntimeError):
    pass


def repo_root() -> Path:
    cwd = Path.cwd().resolve()
    for parent in [cwd, *cwd.parents]:
        candidate = parent / "pyproject.toml"
        if candidate.exists() and "rv-maltrace" in candidate.read_text(encoding="utf-8"):
            return parent

    here = Path(__file__).resolve()
    for parent in [here, *here.parents]:
        candidate = parent / "pyproject.toml"
        if candidate.exists() and "rv-maltrace" in candidate.read_text(encoding="utf-8"):
            return parent
    raise TaskError("Could not find pyproject.toml from rvmt package path.")


def load_config(root: Path) -> dict:
    data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    return data.get("tool", {}).get("rv-maltrace", {})


def as_posix_path(value: str | os.PathLike[str]) -> str:
    return str(value).replace("\\", "/")


def configured_path(root: Path, value: str, *, must_exist: bool = False) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = root / path
    if must_exist and not path.exists():
        raise TaskError(f"Configured path does not exist: {path}")
    return path


def configured_search_paths(root: Path, values: Iterable[str]) -> list[Path]:
    paths: list[Path] = []
    for value in values:
        path = Path(str(value))
        if not path.is_absolute():
            path = root / path
        paths.append(path)
    return paths


def resolve_executable(
    name_or_path: str,
    *,
    candidates: tuple[str, ...] = (),
    search_path: str | None = None,
) -> str:
    if any(sep in name_or_path for sep in ("/", "\\")):
        path = Path(name_or_path)
        if path.is_dir():
            for candidate in candidates:
                candidate_path = path / candidate
                if candidate_path.exists():
                    return str(candidate_path)
            suffix = ", ".join(candidates) if candidates else "an executable"
            raise TaskError(f"Configured directory does not contain {suffix}: {name_or_path}")
        if not path.exists() and path.suffix == "" and os.name == "nt":
            for suffix in (".exe", ".bat", ".cmd"):
                candidate_path = path.with_suffix(suffix)
                if candidate_path.exists():
                    return str(candidate_path)
        if not path.exists():
            raise TaskError(f"Configured executable does not exist: {name_or_path}")
        return str(path)

    resolved = shutil.which(name_or_path, path=search_path)
    if not resolved:
        raise TaskError(
            f"Executable '{name_or_path}' was not found in PATH. "
            "Set it in [tool.rv-maltrace] in pyproject.toml."
        )
    return resolved


def resolve_make(root: Path, config: dict) -> str:
    make_config = str(config.get("make", "make.exe"))
    make_paths = configured_search_paths(root, config.get("make_path_prepend", []))

    if any(sep in make_config for sep in ("/", "\\")):
        resolved = Path(resolve_executable(make_config)).resolve()
        if make_paths and resolved.parent not in {path.resolve() for path in make_paths}:
            allowed = os.pathsep.join(str(path) for path in make_paths)
            raise TaskError(
                f"Configured make is outside make_path_prepend: {resolved}. "
                f"Allowed make directories: {allowed}"
            )
        return str(resolved)

    if not make_paths:
        raise TaskError(
            "make_path_prepend must contain the MSYS bin directory. "
            "rvmt does not search the global PATH for make."
        )

    names = [make_config]
    if os.name == "nt" and Path(make_config).suffix == "":
        names.extend(f"{make_config}{suffix}" for suffix in (".exe", ".bat", ".cmd"))

    for directory in make_paths:
        for name in names:
            candidate = directory / name
            if candidate.exists():
                return str(candidate.resolve())

    searched = os.pathsep.join(str(path) for path in make_paths)
    raise TaskError(f"make '{make_config}' was not found in make_path_prepend: {searched}")


def resolve_vivado(config: dict) -> str:
    vivado_config = str(config.get("vivado", "vivado"))
    return resolve_executable(vivado_config, candidates=("vivado.bat", "vivado.exe", "vivado"))


def xilinx_settings(config: dict) -> tuple[str, str]:
    board = str(config.get("board", "genesys2"))
    part, board_part = BOARD_DEFAULTS.get(board, ("", ""))
    part = str(config.get("xilinx_part", part))
    board_part = str(config.get("xilinx_board", board_part))
    if not part or not board_part:
        raise TaskError(
            f"No Xilinx part mapping for board '{board}'. "
            "Set xilinx_part and xilinx_board in [tool.rv-maltrace]."
        )
    return part, board_part


def vivado_board_repo_paths(root: Path, config: dict) -> list[Path]:
    return configured_search_paths(root, config.get("vivado_board_repo_paths", []))


def normalize_windows_path(value: str | os.PathLike[str]) -> str:
    return os.path.normcase(os.path.normpath(str(value)))


def current_subst_mappings() -> dict[str, str]:
    if os.name != "nt":
        return {}
    completed = subprocess.run(
        ["subst"],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
    )
    mappings: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        if "=>" not in line:
            continue
        drive, target = line.split("=>", 1)
        drive = drive.strip().upper()
        if len(drive) >= 2 and drive[1] == ":":
            mappings[drive[:2]] = target.strip()
    return mappings


def vivado_subst_drive(config: dict) -> str | None:
    drive = str(config.get("vivado_subst_drive", "")).strip()
    if not drive:
        return None
    if os.name != "nt":
        raise TaskError("vivado_subst_drive is only supported on Windows.")

    drive = drive.rstrip("\\/")
    if not drive.endswith(":"):
        drive = f"{drive}:"
    return drive.upper()


def release_subst_mapping(drive: str, root: Path) -> None:
    existing = current_subst_mappings().get(drive)
    if not existing:
        return
    if normalize_windows_path(existing) != normalize_windows_path(root):
        print(f"rvmt: warning: not releasing {drive}; it now maps to {existing}", file=sys.stderr)
        return

    completed = subprocess.run(["subst", drive, "/D"], capture_output=True, encoding="utf-8", errors="replace")
    if completed.returncode:
        message = (completed.stderr or completed.stdout).strip()
        print(f"rvmt: warning: failed to release {drive}: {message}", file=sys.stderr)


def vivado_work_root(root: Path, config: dict, *, dry_run: bool) -> Path:
    drive = vivado_subst_drive(config)
    if not drive:
        return root

    drive_root = Path(f"{drive}\\")

    if dry_run:
        return drive_root

    root_text = str(root)
    mappings = current_subst_mappings()
    existing = mappings.get(drive)
    if existing:
        if normalize_windows_path(existing) != normalize_windows_path(root_text):
            raise TaskError(f"{drive} is already mapped to {existing}, not {root_text}.")
    else:
        completed = subprocess.run(["subst", drive, root_text])
        if completed.returncode:
            raise TaskError(f"Failed to create subst mapping {drive} => {root_text}.")

    if not drive_root.exists():
        raise TaskError(f"subst mapping did not create an accessible drive: {drive_root}")
    return drive_root


def vivado_shell_entry(vivado: str) -> str:
    path = Path(vivado)
    if path.name.lower() == "vivado.bat":
        shell_script = path.with_suffix("")
        if shell_script.exists():
            return str(shell_script)
    return vivado


def prepare_msys_python_wrapper(root: Path) -> Path:
    wrapper_dir = root / ".rvmt" / "bin"
    wrapper_dir.mkdir(parents=True, exist_ok=True)
    real_python = shell_single_quoted(as_posix_path(sys.executable))
    for name in ("python3", "python"):
        wrapper = wrapper_dir / name
        wrapper.write_text(
            f"""#!/usr/bin/env bash
exec {real_python} "$@"
""",
            encoding="utf-8",
            newline="\n",
        )
        os.chmod(wrapper, 0o755)
    return wrapper_dir


def prepare_vivado_wrapper(root: Path, config: dict, vivado: str) -> str:
    repo_paths = vivado_board_repo_paths(root, config)
    if not repo_paths:
        return vivado

    wrapper_dir = root / ".rvmt" / "bin"
    wrapper_dir.mkdir(parents=True, exist_ok=True)
    wrapper = wrapper_dir / "vivado"
    real_vivado = as_posix_path(vivado_shell_entry(vivado))
    repo_args = " ".join(f"'{as_posix_path(path)}'" for path in repo_paths)
    wrapper.write_text(
        f"""#!/usr/bin/env bash
set -euo pipefail

real_vivado='{real_vivado}'
target_cfg='{str(config.get("target", "cv64a6_imafdc_sv39"))}'
board_repo_paths=({repo_args})
args=()
tmp_files=()

normalize_msys_paths() {{
  local file="scripts/add_sources.tcl"
  [[ -f "$file" ]] || return 0

  local tmp_file="${{file}}.rvmt"
  local sed_args=("-e" "/read_verilog[[:space:]]*-sv[[:space:]]*{{[[:space:]]*}}/d")
  local pair lower upper
  for pair in a:A b:B c:C d:D e:E f:F g:G h:H i:I j:J k:K l:L m:M n:N o:O p:P q:Q r:R s:S t:T u:U v:V w:W x:X y:Y z:Z; do
    lower="${{pair%:*}}"
    upper="${{pair#*:}}"
    sed_args+=("-e" "s#/${{lower}}/#${{upper}}:/#g")
  done
  local dedup_pattern
  local dedup_patterns=(
    'core/cvfpu/src/fpnew_pkg\\.sv'
    'core/include/config_pkg\\.sv'
    'core/include/[^[:space:]{{}}]*_config_pkg\\.sv'
    'core/include/riscv_pkg\\.sv'
    'core/include/ariane_pkg\\.sv'
    'vendor/pulp-platform/axi/src/axi_pkg\\.sv'
    'core/include/wt_cache_pkg\\.sv'
    'core/include/std_cache_pkg\\.sv'
    'core/include/instr_tracer_pkg\\.sv'
    'core/include/build_config_pkg\\.sv'
    'core/include/aes_pkg\\.sv'
    'core/include/triggers_pkg\\.sv'
    'core/cache_subsystem/axi_adapter\\.sv'
    'common/local/util/instr_tracer\\.sv'
    'common/local/util/tc_sram_wrapper\\.sv'
    'vendor/pulp-platform/tech_cells_generic/src/rtl/tc_sram\\.sv'
    'core/cache_subsystem/hpdcache/rtl/src/common/macros/behav/hpdcache_sram_1rw\\.sv'
    'core/cache_subsystem/hpdcache/rtl/src/common/macros/behav/hpdcache_sram_wbyteenable_1rw\\.sv'
    'core/cache_subsystem/hpdcache/rtl/src/common/macros/behav/hpdcache_sram_wmask_1rw\\.sv'
    'vendor/pulp-platform/common_cells/src/cf_math_pkg\\.sv'
    'vendor/pulp-platform/common_cells/src/delta_counter\\.sv'
    'vendor/pulp-platform/common_cells/src/rr_arb_tree\\.sv'
  )
  for dedup_pattern in "${{dedup_patterns[@]}}"; do
    sed_args+=("-e" "s#[^[:space:]{{}}]*${{dedup_pattern}}[[:space:]]*##g")
  done
  sed_args+=("-e" "/read_verilog[[:space:]]*-sv[[:space:]]*{{[[:space:]]*}}/d")
  sed "${{sed_args[@]}}" "$file" > "$tmp_file"
  mv "$tmp_file" "$file"

  if grep -q "ariane_axi_pkg.sv\\|common_cells/src/addr_decode.sv" "$file"; then
    tmp_file="${{file}}.rvmt"
    {{
      echo "read_verilog -sv {{../../core/cvfpu/src/fpnew_pkg.sv}}"
      echo "read_verilog -sv {{../../core/include/config_pkg.sv}}"
      echo "read_verilog -sv {{../../core/include/${{target_cfg}}_config_pkg.sv}}"
      echo "read_verilog -sv {{../../core/include/riscv_pkg.sv}}"
      echo "read_verilog -sv {{../../core/include/ariane_pkg.sv}}"
      echo "read_verilog -sv {{../../vendor/pulp-platform/axi/src/axi_pkg.sv}}"
      echo "read_verilog -sv {{../../core/include/wt_cache_pkg.sv}}"
      echo "read_verilog -sv {{../../core/include/std_cache_pkg.sv}}"
      echo "read_verilog -sv {{../../core/include/instr_tracer_pkg.sv}}"
      echo "read_verilog -sv {{../../core/include/build_config_pkg.sv}}"
      echo "read_verilog -sv {{../../core/include/aes_pkg.sv}}"
      echo "read_verilog -sv {{../../core/include/triggers_pkg.sv}}"
      echo "read_verilog -sv {{../../core/cache_subsystem/axi_adapter.sv}}"
      echo "read_verilog -sv {{../../vendor/pulp-platform/common_cells/src/cf_math_pkg.sv}}"
      echo "read_verilog -sv {{../../vendor/pulp-platform/common_cells/src/delta_counter.sv}}"
      echo "read_verilog -sv {{../../vendor/pulp-platform/common_cells/src/rr_arb_tree.sv}}"
      cat "$file"
    }} > "$tmp_file"
    mv "$tmp_file" "$file"
  fi

  chmod u+w "$file" 2>/dev/null || true
}}

cleanup() {{
  for file in "${{tmp_files[@]}}"; do
    rm -f "$file"
  done
}}
trap cleanup EXIT

while (($#)); do
  if [[ "$1" == "-source" && $# -ge 2 ]]; then
    src="$2"
    source_to_run="$src"
    if [[ "$src" == "scripts/run.tcl" && -f "$src" ]]; then
      mkdir -p work-fpga
      patched_src="work-fpga/rvmt-vivado-run-$$-${{#tmp_files[@]}}.tcl"
      sed -E 's#exec[[:space:]]+rm[[:space:]]+-rf[[:space:]]+reports/\\*#file delete -force {{*}}[glob -nocomplain reports/*]#' "$src" > "$patched_src"
      tmp_files+=("$patched_src")
      source_to_run="$patched_src"
    fi
    tmp="${{TMPDIR:-/tmp}}/rvmt-vivado-$$-${{#tmp_files[@]}}.tcl"
    {{
      printf 'set_param board.repoPaths [list'
      for repo in "${{board_repo_paths[@]}}"; do
        printf ' {{%s}}' "$repo"
      done
      printf ']\\n'
      printf 'source {{%s}}\\n' "$source_to_run"
    }} > "$tmp"
    tmp_files+=("$tmp")
    args+=("-source" "$tmp")
    shift 2
  else
    args+=("$1")
    shift
  fi
done

normalize_msys_paths
"$real_vivado" "${{args[@]}}"
""",
        encoding="utf-8",
        newline="\n",
    )
    os.chmod(wrapper, 0o755)
    return str(wrapper)


def task_list(raw_tasks: Iterable[str]) -> list[str]:
    tasks: list[str] = []
    for raw in raw_tasks:
        for part in raw.split("/"):
            part = part.strip()
            if not part:
                continue
            canonical = TASK_ALIASES.get(part)
            if not canonical:
                known = ", ".join(sorted(TASK_ALIASES))
                raise TaskError(f"Unknown task '{part}'. Known tasks: {known}")
            tasks.append(canonical)
    return tasks


def print_task_list() -> None:
    for task in DISPLAY_TASKS:
        print(task)


def merged_env(config: dict) -> dict[str, str]:
    env = os.environ.copy()
    for key, value in config.get("env", {}).items():
        env[str(key)] = str(value)
    prepend = [str(item) for item in config.get("make_path_prepend", [])]
    if prepend:
        env["PATH"] = os.pathsep.join([*prepend, env.get("PATH", "")])
    return env


def prepend_env_path(env: dict[str, str], *paths: str | os.PathLike[str]) -> dict[str, str]:
    env = env.copy()
    existing = env.get("PATH", "")
    prepend = [str(path) for path in paths if str(path)]
    if prepend:
        env["PATH"] = os.pathsep.join([*prepend, existing])
    return env


def run(cmd: list[str], *, cwd: Path, env: dict[str, str], dry_run: bool) -> None:
    printable = " ".join(quote_for_display(part) for part in cmd)
    print(f"+ {printable}")
    if dry_run:
        return

    completed = subprocess.run(cmd, cwd=str(cwd), env=env)
    if completed.returncode:
        raise TaskError(f"Command failed with exit code {completed.returncode}: {printable}")


def quote_for_display(value: str) -> str:
    if not value or any(ch.isspace() for ch in value):
        return f'"{value}"'
    return value


def docker_compose_base(config: dict) -> list[str]:
    docker = resolve_executable(str(config.get("docker", "docker")))
    compose_file = str(config.get("docker_compose_file", "docker-compose.toolchain.yml"))
    return [docker, "compose", "-f", compose_file]


def task_docker_build(root: Path, config: dict, env: dict[str, str], dry_run: bool) -> None:
    run([*docker_compose_base(config), "build"], cwd=root, env=env, dry_run=dry_run)


def task_toolchain_build(root: Path, config: dict, env: dict[str, str], dry_run: bool) -> None:
    env = env.copy()
    env.setdefault("TOOLCHAIN_CONFIG", str(config.get("toolchain_config", "gcc-13.1.0-baremetal")))
    env.setdefault("NUM_JOBS", str(config.get("num_jobs", 8)))
    service = str(config.get("docker_service", "cva6-toolchain"))
    run([*docker_compose_base(config), "run", "--rm", service], cwd=root, env=env, dry_run=dry_run)


def task_bootrom_build(root: Path, config: dict, env: dict[str, str], dry_run: bool) -> None:
    env = env.copy()
    env.setdefault("BOARD", str(config.get("board", "genesys2")))
    env.setdefault("XLEN", str(config.get("xlen", 64)))
    env.setdefault("PLATFORM", str(config.get("platform", "PLAT_XILINX")))
    service = str(config.get("docker_service", "cva6-toolchain"))
    run(
        [
            *docker_compose_base(config),
            "run",
            "--rm",
            service,
            "bash",
            "docker/toolchain/build-cva6-bootrom.sh",
        ],
        cwd=root,
        env=env,
        dry_run=dry_run,
    )


def tcl_braced(value: str) -> str:
    return "{" + value.replace("\\", "/").replace("}", "\\}") + "}"


def task_vivado_check(root: Path, config: dict, env: dict[str, str], dry_run: bool) -> None:
    vivado = resolve_vivado(config)
    xpart, xboard = xilinx_settings(config)
    board_repos = vivado_board_repo_paths(root, config)
    if dry_run:
        print(
            f"+ {quote_for_display(vivado)} -mode batch -source <vivado-check.tcl> "
            f"# XILINX_PART={xpart} XILINX_BOARD={xboard}"
        )
        return

    env = prepend_env_path(env, Path(vivado).parent)
    script = "\n".join(
        [
            f"set rvmt_part {tcl_braced(xpart)}",
            f"set rvmt_board {tcl_braced(xboard)}",
            "set rvmt_failed 0",
            (
                "set_param board.repoPaths [list "
                + " ".join(tcl_braced(as_posix_path(path)) for path in board_repos)
                + "]"
                if board_repos
                else ""
            ),
            "if {[llength [get_parts -quiet $rvmt_part]] == 0} {",
            "  puts \"RVMT_MISSING_PART=$rvmt_part\"",
            "  set rvmt_failed 1",
            "} else {",
            "  puts \"RVMT_PART_OK=$rvmt_part\"",
            "}",
            "if {[llength [get_board_parts -quiet $rvmt_board]] == 0} {",
            "  puts \"RVMT_MISSING_BOARD=$rvmt_board\"",
            "  set rvmt_failed 1",
            "} else {",
            "  puts \"RVMT_BOARD_OK=$rvmt_board\"",
            "}",
            "if {$rvmt_failed} { exit 12 }",
        ]
    )

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".tcl", delete=False) as tcl_file:
        tcl_file.write(script)
        tcl_path = Path(tcl_file.name)

    cmd = [vivado, "-mode", "batch", "-nojournal", "-nolog", "-notrace", "-source", str(tcl_path)]
    print("+ " + " ".join(quote_for_display(part) for part in cmd))
    try:
        completed = subprocess.run(
            cmd,
            cwd=str(root),
            env=env,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
        )
    finally:
        try:
            tcl_path.unlink()
        except OSError:
            pass

    output = "\n".join(part for part in (completed.stdout, completed.stderr) if part)
    markers = [line.strip() for line in output.splitlines() if line.startswith("RVMT_")]
    for marker in markers:
        if marker.startswith("RVMT_PART_OK="):
            print(f"Vivado part OK: {marker.split('=', 1)[1]}")
        elif marker.startswith("RVMT_BOARD_OK="):
            print(f"Vivado board part OK: {marker.split('=', 1)[1]}")

    if completed.returncode:
        missing = []
        for marker in markers:
            if marker.startswith("RVMT_MISSING_PART="):
                missing.append(f"missing Vivado part: {marker.split('=', 1)[1]}")
            elif marker.startswith("RVMT_MISSING_BOARD="):
                missing.append(f"missing Vivado board part: {marker.split('=', 1)[1]}")
        details = "\n- ".join(missing) if missing else output.strip()
        if details:
            raise TaskError(f"Vivado preflight failed:\n- {details}")
        raise TaskError(f"Vivado preflight failed with exit code {completed.returncode}")


def task_bitstream_build(root: Path, config: dict, env: dict[str, str], dry_run: bool) -> None:
    subst_drive = vivado_subst_drive(config)
    subst_before = current_subst_mappings() if subst_drive and not dry_run else {}
    work_root = vivado_work_root(root, config, dry_run=dry_run)
    release_drive = subst_drive if subst_drive and not dry_run and subst_drive not in subst_before else None
    try:
        cva6_dir = configured_path(work_root, str(config.get("cva6_dir", "rtl/cva6")), must_exist=not dry_run)
        xlen = int(config.get("xlen", 64))
        bootrom = cva6_dir / "corev_apu" / "fpga" / "src" / "bootrom" / f"bootrom_{xlen}.sv"
        if not bootrom.exists() and not dry_run:
            raise TaskError(
                f"Missing {bootrom}. Run 'uv run rvmt bootrom:build' before bitstream:build."
            )

        vivado_config = str(config.get("vivado", "vivado"))
        make = resolve_make(root, config)
        if not dry_run:
            task_vivado_check(work_root, config, env, dry_run=False)
            add_sources = cva6_dir / "corev_apu" / "fpga" / "scripts" / "add_sources.tcl"
            if add_sources.exists():
                os.chmod(add_sources, 0o666)
                add_sources.unlink()
        vivado = vivado_config
        if not dry_run:
            real_vivado = resolve_vivado(config)
            vivado = prepare_vivado_wrapper(work_root, config, real_vivado)
            wrapper_dir = prepare_msys_python_wrapper(work_root)
            env = prepend_env_path(env, wrapper_dir, Path(vivado).parent, Path(real_vivado).parent)
        board = str(config.get("board", "genesys2"))
        target = str(config.get("target", "cv64a6_imafdc_sv39"))
        riscv = str(config.get("riscv_placeholder", "/tmp/riscv-placeholder"))
        xpart, xboard = xilinx_settings(config)

        run(
            [
                make,
                f"MAKE={Path(make).name}",
                f"BOARD={board}",
                f"XILINX_PART={xpart}",
                f"XILINX_BOARD={xboard}",
                f"target={target}",
                f"RISCV={riscv}",
                f"VIVADO={as_posix_path(vivado)}",
                "fpga",
            ],
            cwd=cva6_dir,
            env=env,
            dry_run=dry_run,
        )
    finally:
        if release_drive:
            release_subst_mapping(release_drive, root)


def show_config(root: Path, config: dict) -> None:
    cva6_dir = configured_path(root, str(config.get("cva6_dir", "rtl/cva6")))
    print(f"repo_root            = {root}")
    print(f"vivado_work_root     = {vivado_work_root(root, config, dry_run=True)}")
    print(f"docker              = {config.get('docker', 'docker')}")
    print(f"docker_compose_file = {config.get('docker_compose_file', 'docker-compose.toolchain.yml')}")
    print(f"docker_service      = {config.get('docker_service', 'cva6-toolchain')}")
    print(f"vivado              = {config.get('vivado', 'vivado')}")
    print(f"vivado_board_repos  = {[str(path) for path in vivado_board_repo_paths(root, config)]}")
    print(f"make                = {config.get('make', 'make')}")
    print(f"make_path_prepend   = {config.get('make_path_prepend', [])}")
    print(f"make_resolved       = {resolve_make(root, config)}")
    print(f"cva6_dir            = {cva6_dir}")
    print(f"board               = {config.get('board', 'genesys2')}")
    xpart, xboard = xilinx_settings(config)
    print(f"xilinx_part         = {xpart}")
    print(f"xilinx_board        = {xboard}")
    print(f"target              = {config.get('target', 'cv64a6_imafdc_sv39')}")
    print(f"xlen                = {config.get('xlen', 64)}")
    print(f"toolchain_config    = {config.get('toolchain_config', 'gcc-13.1.0-baremetal')}")
    print(f"num_jobs            = {config.get('num_jobs', 8)}")


def ps_single_quoted(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def shell_single_quoted(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def print_completion(shell: str) -> None:
    if shell == "powershell":
        candidates = ", ".join(ps_single_quoted(item) for item in COMPLETION_CANDIDATES)
        print(
            f"""# rvmt completion for PowerShell.
# Supports both:
#   rvmt <TAB>
#   uv run rvmt <TAB>
$script:RvmtCompletions = @({candidates})

function script:Complete-RvmtTask {{
    param($wordToComplete)
    $script:RvmtCompletions |
        Where-Object {{ $_ -like "$wordToComplete*" }} |
        ForEach-Object {{
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }}
}}

Register-ArgumentCompleter -Native -CommandName 'rvmt' -ScriptBlock {{
    param($wordToComplete, $commandAst, $cursorPosition)
    Complete-RvmtTask $wordToComplete
}}

Register-ArgumentCompleter -Native -CommandName 'uv' -ScriptBlock {{
    param($wordToComplete, $commandAst, $cursorPosition)
    $words = @($commandAst.CommandElements | ForEach-Object {{ $_.Extent.Text }})
    if ($words.Count -ge 3 -and $words[0] -eq 'uv' -and $words[1] -eq 'run' -and $words[2] -eq 'rvmt') {{
        Complete-RvmtTask $wordToComplete
    }}
}}
"""
        )
    elif shell == "bash":
        words = " ".join(COMPLETION_CANDIDATES)
        print(
            f"""# rvmt completion for Bash.
_rvmt_complete() {{
    local cur="${{COMP_WORDS[COMP_CWORD]}}"
    local first="${{COMP_WORDS[0]}}"
    local enabled=0

    if [[ "$first" == "rvmt" ]]; then
        enabled=1
    elif [[ "$first" == "uv" && "${{COMP_WORDS[1]}}" == "run" && "${{COMP_WORDS[2]}}" == "rvmt" ]]; then
        enabled=1
    fi

    if [[ "$enabled" == "1" ]]; then
        COMPREPLY=( $(compgen -W {shell_single_quoted(words)} -- "$cur") )
    fi
}}

complete -F _rvmt_complete rvmt
complete -F _rvmt_complete uv
"""
        )
    elif shell == "zsh":
        words = " ".join(COMPLETION_CANDIDATES)
        print(
            f"""# rvmt completion for Zsh.
_rvmt_complete() {{
  local -a candidates
  candidates=({words})
  _describe 'rvmt task' candidates
}}

compdef _rvmt_complete rvmt
compdef _rvmt_complete uv
"""
        )
    else:
        raise TaskError(f"Unsupported completion shell: {shell}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="rvmt",
        description="rv-maltrace build helper. Example: uv run rvmt docker:build bootrom:build",
    )
    parser.add_argument(
        "tasks",
        nargs="*",
        help=(
            "Tasks to run. Supports docker:build, toolchain:build, bootrom:build, "
            "vivado:check, bitstream:build, config:show, completion:powershell. Slash groups such as "
            "tool/bootrom are expanded."
        ),
    )
    parser.add_argument("--dry-run", action="store_true", help="Print commands without running them.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    root = repo_root()
    config = load_config(root)
    env = merged_env(config)

    try:
        tasks = task_list(args.tasks or ["config:show"])
        for task in tasks:
            if task == "config:show":
                show_config(root, config)
            elif task == "help":
                parse_args(["--help"])
            elif task == "tasks:list":
                print_task_list()
            elif task == "completion:powershell":
                print_completion("powershell")
            elif task == "completion:bash":
                print_completion("bash")
            elif task == "completion:zsh":
                print_completion("zsh")
            elif task == "docker:build":
                task_docker_build(root, config, env, args.dry_run)
            elif task == "toolchain:build":
                task_toolchain_build(root, config, env, args.dry_run)
            elif task == "bootrom:build":
                task_bootrom_build(root, config, env, args.dry_run)
            elif task == "vivado:check":
                task_vivado_check(root, config, env, args.dry_run)
            elif task == "bitstream:build":
                task_bitstream_build(root, config, env, args.dry_run)
            else:
                raise TaskError(f"Unhandled task: {task}")
    except TaskError as exc:
        print(f"rvmt: error: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
