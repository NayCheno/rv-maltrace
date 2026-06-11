#!/usr/bin/env bash
# Build the safety-controlled Mirai comprehensive surrogate for RISC-V.
#
# This script cross-compiles the repo-authored safety Mirai surrogate
# (mirai_safety_comprehensive.c) for riscv64 Linux using the installed
# riscv64-linux-gnu-gcc toolchain.
#
# The output binary is placed under:
#   build/board/artix7_35t/rootfs_exp_overlay/usr/bin/mirai_safety_comprehensive
#
# For QEMU / CVA6 simulation testing, the same binary can be run via:
#   qemu-riscv64 -L /usr/riscv64-linux-gnu ./mirai_safety_comprehensive
#
# Safety: this builds only the repo-authored safe surrogate, NOT the
# external Mirai source.  The external source is referenced only in
# documentation and behavior analysis.

set -euo pipefail

ROOT="${ROOT:-/workspace/rv-maltrace}"
SRC="$ROOT/experiments/linux_behavior/real_malware_surrogate/programs/mirai_safety_comprehensive.c"
OUTDIR="$ROOT/build/board/artix7_35t/rootfs_exp_overlay/usr/bin"
OUTNAME="mirai_safety_comprehensive"

CROSS_GCC="${CROSS_GCC:-riscv64-linux-gnu-gcc}"

if ! command -v "$CROSS_GCC" &>/dev/null; then
  echo "ERROR: cross-compiler '$CROSS_GCC' not found" >&2
  exit 1
fi

echo "=== Mirai Safety Surrogate Build ==="
echo "  source:   $SRC"
echo "  compiler: $CROSS_GCC ($("$CROSS_GCC" --version | head -n 1))"
echo "  output:   $OUTDIR/$OUTNAME"

mkdir -p "$OUTDIR"

"$CROSS_GCC" -std=c99 -O2 -Wall -Wextra -static \
  -o "$OUTDIR/$OUTNAME" "$SRC"

echo "  size: $(wc -c < "$OUTDIR/$OUTNAME") bytes"
echo "  type: $(file "$OUTDIR/$OUTNAME")"

# Verify it's a static RISC-V ELF
readelf -h "$OUTDIR/$OUTNAME" | grep -q "Machine:.*RISC-V" || {
  echo "ERROR: output is not a RISC-V ELF" >&2
  exit 1
}

echo "=== Build Complete ==="
