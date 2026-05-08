# uv Workflow

Use `uv` as the single entry for local build tasks:

```powershell
uv run rvmt config:show
uv run rvmt docker:build
uv run rvmt toolchain:build
uv run rvmt bootrom:build
uv run rvmt vivado:check
uv run rvmt bitstream:build
```

Slash groups are expanded, so this runs the long build sequence:

```powershell
uv run rvmt docker/toolchain/bootrom/bitstream
```

The Windows executable itself is `rvmt`. Task names can contain colons because they are arguments, not Windows executable filenames.

## Configuration

Edit `[tool.rv-maltrace]` in `pyproject.toml`:

```toml
[tool.rv-maltrace]
vivado = "C:/Xilinx/Vivado/2024.2/bin/vivado.bat"
vivado_board_repo_paths = ["vendor/vivado-boards/new/board_files"]
vivado_subst_drive = "R:"
make = "make.exe"
make_path_prepend = ["D:/env/tools/MinGW/msys/1.0/bin"]
build_dir = "build"
board = "genesys2"
# Optional override. By default this is derived from board.
# xilinx_part = "xc7k325tffg900-2"
# xilinx_board = "digilentinc.com:genesys2:part0:1.1"
target = "cv64a6_imafdc_sv39"
xlen = 64
num_jobs = 8
```

`make` is resolved only from `make_path_prepend`. Keep this pointed at the MSYS toolchain bin directory; `rvmt` intentionally does not fall back to any other global `PATH` entry for `make`.

For `bitstream:build`, `rvmt` also prepends the configured Vivado `bin` directory to the child process `PATH`. CVA6's nested Xilinx IP Makefiles call `vivado` directly, so this keeps those calls on the same Vivado installation configured above.

Digilent board files are provided by the `vendor/vivado-boards` submodule. `rvmt` injects `vivado_board_repo_paths` into Vivado with `board.repoPaths`, including nested CVA6 Xilinx IP generation calls.

On Windows, `vivado_subst_drive` maps the repository to a short drive path before running Vivado. This avoids Vivado's 260-character path limit during Xilinx IP synthesis.

`bitstream:build` writes the stable FPGA deliverables under:

```text
build/vivado/<board>-<target>/
  work-fpga/      # bitstream, flash image, netlists, checkpoints, generated IP xci copies
  reports/        # timing and utilization reports
```

Set `vivado_artifact_dir` if you want to override that exact directory instead of deriving it from `build_dir`, `board`, and `target`.

The upstream CVA6 Vivado project database (`ariane.xpr`, `ariane.runs`, `ariane.cache`, and related state) is still created in `rtl/cva6/corev_apu/fpga/`, because the CVA6 scripts create the project from that directory. `rvmt` rewrites the generated `.xpr` away from the temporary subst drive so it can be opened from the normal `D:` path.

If Vivado is already in `PATH`, keep:

```toml
vivado = "vivado"
```

## Tasks

```text
docker:build      Build the Ubuntu 24.04 Docker image.
toolchain:build   Build the CVA6 RISC-V GCC/newlib toolchain in Docker.
bootrom:build     Generate CVA6 FPGA bootrom_64.sv using the Docker toolchain.
vivado:check      Check whether Vivado has the configured FPGA part and board files.
bitstream:build   Run CVA6 make fpga with Windows Vivado.
bitstream:collect Copy existing CVA6 FPGA outputs into build/vivado/<board>-<target>.
config:show       Print resolved configuration.
tasks:list        Print task names.
completion:*      Print shell completion scripts.
```

Aliases:

```text
tool -> toolchain:build
bootrom -> bootrom:build
bitstream/fpga -> bitstream:build
```

## Completion

PowerShell, temporary for the current shell:

```powershell
uv run --quiet rvmt completion:powershell | Out-String | Invoke-Expression
```

PowerShell, persistent:

```powershell
New-Item -ItemType Directory -Force .\scripts\completions | Out-Null
uv run --quiet rvmt completion:powershell | Set-Content .\scripts\completions\rvmt.ps1
Add-Content $PROFILE "`n. `"$PWD\scripts\completions\rvmt.ps1`""
```

Then restart PowerShell. Completion works for both forms:

```powershell
uv run rvmt <TAB>
rvmt <TAB>
```

Bash:

```bash
uv run --quiet rvmt completion:bash >> ~/.bashrc
source ~/.bashrc
```

Zsh:

```zsh
uv run --quiet rvmt completion:zsh >> ~/.zshrc
source ~/.zshrc
```

List task names:

```powershell
uv run rvmt tasks:list
```
