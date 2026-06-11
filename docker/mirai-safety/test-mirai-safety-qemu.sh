#!/usr/bin/env bash
# Smoke-test the safety Mirai surrogate under QEMU user-mode RISC-V emulation.
#
# Usage (inside Docker):
#   bash docker/mirai-safety/test-mirai-safety-qemu.sh
#
# Prerequisites:
#   - qemu-riscv64 (from qemu-user package)
#   - riscv64-linux-gnu toolchain (for sysroot /lib)
#   - The binary must have been built first via build-mirai-safety.sh

set -euo pipefail

ROOT="${ROOT:-/workspace/rv-maltrace}"
BIN="$ROOT/build/board/artix7_35t/rootfs_exp_overlay/usr/bin/mirai_safety_comprehensive"

if [ ! -x "$BIN" ] && [ ! -f "$BIN" ]; then
  echo "Binary not found at $BIN — run build-mirai-safety.sh first" >&2
  exit 1
fi

echo "=== QEMU RISC-V Smoke Test ==="
echo "  binary: $BIN"

QEMU="${QEMU:-qemu-riscv64}"
SYSROOT="${SYSROOT:-/usr/riscv64-linux-gnu}"

# Run under QEMU with strace-like output
echo "--- Execution ---"
set +e
"$QEMU" -L "$SYSROOT" -strace "$BIN" 2>&1
status=$?
set -e

echo ""
echo "--- Exit Code: $status ---"
echo "=== Smoke Test Complete ==="
exit "$status"
