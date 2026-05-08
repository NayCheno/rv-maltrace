#!/usr/bin/env bash
set -euo pipefail

config_name="${1:-${TOOLCHAIN_CONFIG:-gcc-13.1.0-baremetal}}"
repo_root="${REPO_ROOT:-/workspace/rv-maltrace}"
repo_builder_dir="${repo_root}/rtl/cva6/util/toolchain-builder"
builder_dir="${TOOLCHAIN_BUILDER_DIR:-/opt/cva6-toolchain/toolchain-builder}"
install_dir="${RISCV:-/opt/riscv}"

export SRC_DIR="${SRC_DIR:-/opt/cva6-toolchain/src}"
export BUILD_DIR="${BUILD_DIR:-/opt/cva6-toolchain/build}"
export NUM_JOBS="${NUM_JOBS:-$(nproc)}"

if [ ! -d "${repo_builder_dir}" ]; then
  echo "Missing CVA6 toolchain-builder directory: ${repo_builder_dir}" >&2
  exit 1
fi

mkdir -p "${SRC_DIR}" "${BUILD_DIR}" "${install_dir}" "${builder_dir}"
rm -rf "${builder_dir:?}/"*
cp -a "${repo_builder_dir}/." "${builder_dir}/"

# Windows checkouts can leave CVA6 shell/config files with CRLF. Normalize the
# copied toolchain-builder workspace only; do not mutate the mounted source tree.
find "${builder_dir}" -type f -print0 | xargs -0 sed -i 's/\r$//'

cd "${builder_dir}"

echo "Configuration : ${config_name}"
echo "Install dir   : ${install_dir}"
echo "Source dir    : ${SRC_DIR}"
echo "Build dir     : ${BUILD_DIR}"
echo "NUM_JOBS      : ${NUM_JOBS}"

if [ "${FORCE_REBUILD:-0}" = "1" ]; then
  echo "FORCE_REBUILD=1: clearing build and install directories"
  rm -rf "${BUILD_DIR:?}/"* "${install_dir:?}/"*
fi

echo "Fetching CVA6 toolchain sources..."
bash get-toolchain.sh "${config_name}"

if [ -x "${install_dir}/bin/riscv-none-elf-gcc" ] && [ "${FORCE_REBUILD:-0}" != "1" ]; then
  echo "Toolchain already installed at ${install_dir}; skipping rebuild."
else
  if [ -n "$(find "${install_dir}" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
    echo "Install directory is not empty but riscv-none-elf-gcc is missing: ${install_dir}" >&2
    echo "Set FORCE_REBUILD=1 to clear and rebuild it." >&2
    exit 1
  fi

  echo "Building CVA6 toolchain..."
  bash build-toolchain.sh "${config_name}" "${install_dir}"
fi

"${install_dir}/bin/riscv-none-elf-gcc" --version | head -n 1
"${install_dir}/bin/riscv-none-elf-objdump" --version | head -n 1
