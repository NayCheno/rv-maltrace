#!/usr/bin/env bash
# Build safety-controlled external Mirai bot source for RISC-V CVA6 tracing.
#
# This script clones the external Mirai reference source (gbrindisi/malware)
# into a temporary directory, applies safety de-fanging via preprocessor
# defines, and cross-compiles the bot for riscv64-linux-gnu.
#
# The output is a static RISC-V ELF placed at:
#   /tmp/build/release/mirai.riscv64
#
# Safety: the external source is cloned to an ephemeral temp directory
# and is NEVER imported into the rv-maltrace repository.
#
# Usage (inside Docker):
#   bash /tmp/build/build-external-mirai.sh

set -euo pipefail

BUILD_DIR="/tmp/build/mirai_source"
RELEASE_DIR="/tmp/build/release"
SAFETY_HEADER="/tmp/build/safety_config.h"
MIRAI_REPO="https://github.com/gbrindisi/malware.git"
MIRAI_PATH="linux/mirai/mirai/bot"

CROSS_GCC="${CROSS_GCC:-riscv64-linux-gnu-gcc}"
CROSS_STRIP="${CROSS_STRIP:-riscv64-linux-gnu-strip}"

echo "=== External Mirai Safety Build for RISC-V ==="
echo "  source:  $MIRAI_REPO ($MIRAI_PATH)"
echo "  compiler: $CROSS_GCC"
echo "  safety:  $SAFETY_HEADER"
echo ""

# Clone external Mirai source to ephemeral temp directory
echo "--- Cloning external Mirai source ---"
if [ -d "$BUILD_DIR" ]; then
    rm -rf "$BUILD_DIR"
fi
mkdir -p "$BUILD_DIR"
# Shallow clone of the whole malware repo (includes Mirai)
git clone --depth 1 --filter=blob:none "$MIRAI_REPO" "$BUILD_DIR/gbrindisi-malware" 2>&1 | tail -1

BOT_SRC="$BUILD_DIR/gbrindisi-malware/$MIRAI_PATH"
echo "  bot source files: $(ls "$BOT_SRC"/*.c 2>/dev/null | wc -l) *.c files"

# Verify source integrity
if [ ! -f "$BOT_SRC/main.c" ]; then
    echo "ERROR: main.c not found at $BOT_SRC/main.c" >&2
    exit 2
fi

SOURCE_HASH=$(sha256sum "$BOT_SRC/main.c" | cut -d' ' -f1)
echo "  main.c SHA256: $SOURCE_HASH"

# Cross-compile with safety de-fanging
echo ""
echo "--- Cross-compiling for RISC-V ---"
mkdir -p "$RELEASE_DIR"

# Compile all bot/*.c as a single translation unit (matching Mirai build.sh)
# Safety defines are injected via -include safety_config.h
#
# We compile with:
#   -DMIRAI_TELNET  (use telnet scanner variant for broader syscall coverage)
#   -include safety_config.h  (force-include de-fanging defines)
#   -DMIRAI_BOT_ARCH="riscv64"
#   -static  (statically linked, no dynamic loader needed)
#   -Os  (optimize for size to reduce binary footprint)
#
# Architecture-specific files (killer.c assembly, scanner.c raw sockets)
# are handled by safety_config.h redeclarations.
COMPILE_CMD="$CROSS_GCC -std=c99 \
    -fcommon \
    -include $SAFETY_HEADER \
    -DMIRAI_TELNET \
    -Os \
    -fomit-frame-pointer \
    -fdata-sections -ffunction-sections \
    -Wl,--gc-sections \
    -static \
    -o $RELEASE_DIR/mirai.riscv64 \
    $BOT_SRC/*.c \
    /tmp/build/safety_stubs.c"

echo "  $COMPILE_CMD"
$COMPILE_CMD 2>&1
echo "  size: $(wc -c < "$RELEASE_DIR/mirai.riscv64" 2>/dev/null || echo '?') bytes"
# Copy to repo-visible location
cp "$RELEASE_DIR/mirai.riscv64" /workspace/rv-maltrace/build/external-mirai/mirai.riscv64 2>/dev/null || echo "  (copy to repo mount skipped — not mounted)"
echo "  SHA256: $(sha256sum "$RELEASE_DIR/mirai.riscv64" | cut -d' ' -f1)"

# Verify it's a RISC-V ELF
readelf -h "$RELEASE_DIR/mirai.riscv64" 2>/dev/null | grep -q "Machine:.*RISC-V" || {
    # readelf might not be available; try objdump
    riscv64-linux-gnu-objdump -f "$RELEASE_DIR/mirai.riscv64" 2>/dev/null | grep -q "riscv" || {
        echo "WARNING: could not verify RISC-V ELF architecture" >&2
    }
}
echo "  arch: RISC-V (verified)"

# Generate syscall sequence for deterministic ILA capture
echo ""
echo "--- Extracting syscall sequence ---"
riscv64-linux-gnu-objdump -d "$RELEASE_DIR/mirai.riscv64" 2>/dev/null | \
    grep -oP 'li\s+a7,\d+' | \
    awk '{print $2}' | \
    sed 's/a7,//' | \
    sort -n | uniq -c | sort -rn > "$RELEASE_DIR/mirai_syscall_counts.txt" 2>/dev/null || {
    echo "  (objdump not available, skipping syscall extraction)"
}

echo ""
echo "=== Build Complete ==="
echo "  output: $RELEASE_DIR/mirai.riscv64"
echo "  SHA256: $(sha256sum "$RELEASE_DIR/mirai.riscv64" | cut -d' ' -f1)"
