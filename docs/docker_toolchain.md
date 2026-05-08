# CVA6 Toolchain Docker

This project uses Windows Docker Desktop to build the CVA6 bare-metal RISC-V toolchain in an Ubuntu 24.04 container.

The dependency list follows the CVA6 `util/toolchain-builder` README prerequisites. The CVA6 scripts still perform the real source fetch and toolchain build:

```text
rtl/cva6/util/toolchain-builder/get-toolchain.sh
rtl/cva6/util/toolchain-builder/build-toolchain.sh
```

## Build The Image

From Windows PowerShell at the repository root:

```powershell
docker compose -f docker-compose.toolchain.yml build
```

## Build The Toolchain

```powershell
docker compose -f docker-compose.toolchain.yml run --rm cva6-toolchain
```

Defaults:

```text
TOOLCHAIN_CONFIG=gcc-13.1.0-baremetal
NUM_JOBS=8
RISCV=/opt/riscv
SRC_DIR=/opt/cva6-toolchain/src
BUILD_DIR=/opt/cva6-toolchain/build
```

The toolchain source, build, and install directories are Docker named volumes:

```text
cva6_toolchain_src
cva6_toolchain_build
cva6_toolchain_install
```

This keeps multi-GB GCC/binutils/newlib artifacts out of the Windows workspace.

## Rebuild From Scratch

```powershell
$env:FORCE_REBUILD = "1"
docker compose -f docker-compose.toolchain.yml run --rm cva6-toolchain
Remove-Item Env:\FORCE_REBUILD
```

## Open A Shell

```powershell
docker compose -f docker-compose.toolchain.yml run --rm cva6-toolchain bash
```

Inside the container:

```bash
export PATH=/opt/riscv/bin:$PATH
riscv-none-elf-gcc --version
```

## Build The CVA6 FPGA Bootrom

After the toolchain is installed, generate the FPGA bootrom SystemVerilog file:

```powershell
docker compose -f docker-compose.toolchain.yml run --rm cva6-toolchain bash docker/toolchain/build-cva6-bootrom.sh
```

Defaults:

```text
BOARD=genesys2
XLEN=64
PLATFORM=PLAT_XILINX
```

This writes:

```text
rtl/cva6/corev_apu/fpga/src/bootrom/bootrom_64.sv
```

## Notes

- Windows Vivado remains outside Docker.
- Docker builds the RISC-V bare-metal toolchain and later can build test ELF/HEX/MEM files.
- Vivado should consume generated files from the repository directory using Windows paths.
