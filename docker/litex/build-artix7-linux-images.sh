#!/usr/bin/env bash
set -euo pipefail

ROOT=/workspace/rv-maltrace
LOLV="$ROOT/vendor/litex/linux-on-litex-vexriscv"
BUILDROOT_DIR="${BUILDROOT_DIR:-/workspace/buildroot}"
BUILDROOT_REF="${BUILDROOT_REF:-2024.02.6}"
OVERLAY="$ROOT/board/artix7_35t/linux/rootfs_overlay"
export FORCE_UNSAFE_CONFIGURE=1

if [ ! -d "$BUILDROOT_DIR/.git" ]; then
  git clone --depth 1 --branch "$BUILDROOT_REF" https://github.com/buildroot/buildroot.git "$BUILDROOT_DIR"
fi

chmod +x "$OVERLAY/etc/init.d/S99rvmt-pass"
find "$LOLV/buildroot" "$OVERLAY" -type f \( -name '*.mk' -o -name '*.in' -o -name '*.sh' -o -name '*defconfig' -o -name 'external.desc' -o -name 'external.mk' -o -name 'Config.in' \) \
  -exec sed -i 's/\r$//' {} +

cd "$BUILDROOT_DIR"
make BR2_EXTERNAL="$LOLV/buildroot" litex_vexriscv_defconfig
make olddefconfig BR2_ROOTFS_OVERLAY="$LOLV/buildroot/board/litex_vexriscv/rootfs_overlay $OVERLAY"
make BR2_ROOTFS_OVERLAY="$LOLV/buildroot/board/litex_vexriscv/rootfs_overlay $OVERLAY"

rm -f "$LOLV/images/Image" "$LOLV/images/rootfs.cpio" "$LOLV/images/opensbi.bin" "$LOLV/images/rootfs.ext4"
cp "$BUILDROOT_DIR/output/images/Image" "$LOLV/images/Image"
cp "$BUILDROOT_DIR/output/images/rootfs.cpio" "$LOLV/images/rootfs.cpio"
cp "$BUILDROOT_DIR/output/images/fw_jump.bin" "$LOLV/images/opensbi.bin"
cp "$BUILDROOT_DIR/output/images/rootfs.ext4" "$LOLV/images/rootfs.ext4"
