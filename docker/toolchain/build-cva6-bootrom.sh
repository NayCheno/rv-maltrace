#!/usr/bin/env bash
set -euo pipefail

repo_root="${REPO_ROOT:-/workspace/rv-maltrace}"
board="${BOARD:-genesys2}"
xlen="${XLEN:-64}"
platform="${PLATFORM:-PLAT_XILINX}"
install_dir="${RISCV:-/opt/riscv}"

src_dir="${repo_root}/rtl/cva6/corev_apu/fpga/src/bootrom"
work_dir="/opt/cva6-toolchain/bootrom-work"

if [ ! -x "${install_dir}/bin/riscv-none-elf-gcc" ]; then
  echo "Missing ${install_dir}/bin/riscv-none-elf-gcc." >&2
  echo "Build the CVA6 toolchain first: docker compose -f docker-compose.toolchain.yml run --rm cva6-toolchain" >&2
  exit 1
fi

rm -rf "${work_dir}"
mkdir -p "${work_dir}"
cp -a "${src_dir}/." "${work_dir}/"
cp "${repo_root}/rtl/cva6/corev_apu/bootrom/gen_rom.py" "${work_dir}/gen_rom.py"
chmod +x "${work_dir}/gen_rom.py"

# Normalize the copied workspace only; keep the mounted CVA6 submodule untouched.
find "${work_dir}" -type f -print0 | xargs -0 sed -i 's/\r$//'

cd "${work_dir}"
make \
  BOARD="${board}" \
  XLEN="${xlen}" \
  PLATFORM="${platform}" \
  RISCV="${install_dir}" \
  "bootrom_${xlen}.sv"

cp "bootrom_${xlen}.sv" "${src_dir}/bootrom_${xlen}.sv"
echo "Generated ${src_dir}/bootrom_${xlen}.sv"
