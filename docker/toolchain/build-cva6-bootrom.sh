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
artifact_dir="${repo_root}/build/bootrom/${board}-cva6"
mkdir -p "${artifact_dir}"
cp "bootrom_${xlen}.elf" "${artifact_dir}/bootrom_${xlen}.elf"
cp "bootrom_${xlen}.bin" "${artifact_dir}/bootrom_${xlen}.bin"
cp "bootrom_${xlen}.img" "${artifact_dir}/bootrom_${xlen}.img"
cp "bootrom_${xlen}.sv" "${artifact_dir}/bootrom_${xlen}.sv"
if [ -f "cv${xlen}a6.dtb" ]; then
  cp "cv${xlen}a6.dtb" "${artifact_dir}/cv${xlen}a6.dtb"
fi
"${install_dir}/bin/riscv-none-elf-objdump" -d "bootrom_${xlen}.elf" > "${artifact_dir}/bootrom_${xlen}.disasm.txt"
"${install_dir}/bin/riscv-none-elf-objdump" -s -j .rodata "bootrom_${xlen}.elf" > "${artifact_dir}/bootrom_${xlen}.rodata.txt" || true

manifest="${artifact_dir}/build_manifest.json"
source_rel="rtl/cva6/corev_apu/fpga/src/bootrom/src/main.c"
sv_rel="rtl/cva6/corev_apu/fpga/src/bootrom/bootrom_${xlen}.sv"
cat > "${manifest}" <<EOF
{
  "schema": "rvmt.genesys2.bootrom_build.v1",
  "status": "PASS",
  "board": "${board}",
  "xlen": ${xlen},
  "platform": "${platform}",
  "source": {
    "path": "${source_rel}",
    "sha256": "$(sha256sum "${repo_root}/${source_rel}" | awk '{print $1}')",
    "size_bytes": $(stat -c '%s' "${repo_root}/${source_rel}")
  },
  "generated_sv": {
    "path": "${sv_rel}",
    "sha256": "$(sha256sum "${repo_root}/${sv_rel}" | awk '{print $1}')",
    "size_bytes": $(stat -c '%s' "${repo_root}/${sv_rel}")
  },
  "artifacts": {
    "elf": {
      "path": "build/bootrom/${board}-cva6/bootrom_${xlen}.elf",
      "sha256": "$(sha256sum "${artifact_dir}/bootrom_${xlen}.elf" | awk '{print $1}')",
      "size_bytes": $(stat -c '%s' "${artifact_dir}/bootrom_${xlen}.elf")
    },
    "bin": {
      "path": "build/bootrom/${board}-cva6/bootrom_${xlen}.bin",
      "sha256": "$(sha256sum "${artifact_dir}/bootrom_${xlen}.bin" | awk '{print $1}')",
      "size_bytes": $(stat -c '%s' "${artifact_dir}/bootrom_${xlen}.bin")
    },
    "img": {
      "path": "build/bootrom/${board}-cva6/bootrom_${xlen}.img",
      "sha256": "$(sha256sum "${artifact_dir}/bootrom_${xlen}.img" | awk '{print $1}')",
      "size_bytes": $(stat -c '%s' "${artifact_dir}/bootrom_${xlen}.img")
    },
    "disassembly": {
      "path": "build/bootrom/${board}-cva6/bootrom_${xlen}.disasm.txt",
      "sha256": "$(sha256sum "${artifact_dir}/bootrom_${xlen}.disasm.txt" | awk '{print $1}')",
      "size_bytes": $(stat -c '%s' "${artifact_dir}/bootrom_${xlen}.disasm.txt")
    },
    "rodata": {
      "path": "build/bootrom/${board}-cva6/bootrom_${xlen}.rodata.txt",
      "sha256": "$(sha256sum "${artifact_dir}/bootrom_${xlen}.rodata.txt" | awk '{print $1}')",
      "size_bytes": $(stat -c '%s' "${artifact_dir}/bootrom_${xlen}.rodata.txt")
    }
  },
  "counter_delegation_attempt": {
    "csr_bits": "CY_TM_IR",
    "counteren_value_hex": "0x7",
    "writes_mcounteren": true,
    "writes_scounteren": true,
    "clears_mcountinhibit": true,
    "claim_boundary": "Firmware attempts to delegate cycle/time/instret before jumping to the SD-card payload; board Linux must still prove user rdcycle or kernel perf cycles before any cycle-source PASS."
  }
}
EOF
echo "Generated ${src_dir}/bootrom_${xlen}.sv"
echo "Bootrom artifacts: ${artifact_dir}"
