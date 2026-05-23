#!/usr/bin/env bash
set -euo pipefail

ROOT=/workspace/rv-maltrace
LOLV="$ROOT/vendor/litex/linux-on-litex-vexriscv"
BUILDROOT_DIR="${BUILDROOT_DIR:-/workspace/buildroot}"
BUILDROOT_REF="${BUILDROOT_REF:-2024.02.6}"
OVERLAY="$ROOT/board/artix7_35t/linux/rootfs_overlay"
EXP_OVERLAY="$ROOT/build/board/artix7_35t/rootfs_exp_overlay"
export FORCE_UNSAFE_CONFIGURE=1

if [ ! -d "$BUILDROOT_DIR/.git" ]; then
  git clone --depth 1 --branch "$BUILDROOT_REF" https://github.com/buildroot/buildroot.git "$BUILDROOT_DIR"
fi

chmod +x "$OVERLAY/etc/init.d/S99rvmt-pass"
rm -rf "$EXP_OVERLAY"
mkdir -p "$EXP_OVERLAY/usr/bin" \
         "$EXP_OVERLAY/opt/rvmt/experiments/linux_behavior/benign" \
         "$EXP_OVERLAY/opt/rvmt/experiments/linux_behavior/malware_like"
rsync -a "$ROOT/experiments/linux_behavior/benign/fixtures" \
    "$EXP_OVERLAY/opt/rvmt/experiments/linux_behavior/benign/"
rsync -a "$ROOT/experiments/linux_behavior/malware_like/fixtures" \
    "$EXP_OVERLAY/opt/rvmt/experiments/linux_behavior/malware_like/"
find "$LOLV/buildroot" "$OVERLAY" -type f \( -name '*.mk' -o -name '*.in' -o -name '*.sh' -o -name '*defconfig' -o -name 'external.desc' -o -name 'external.mk' -o -name 'Config.in' \) \
  -exec sed -i 's/\r$//' {} +

cd "$BUILDROOT_DIR"
make BR2_EXTERNAL="$LOLV/buildroot" litex_vexriscv_defconfig
make olddefconfig BR2_ROOTFS_OVERLAY="$LOLV/buildroot/board/litex_vexriscv/rootfs_overlay $OVERLAY $EXP_OVERLAY"
make BR2_ROOTFS_OVERLAY="$LOLV/buildroot/board/litex_vexriscv/rootfs_overlay $OVERLAY $EXP_OVERLAY"

TARGET_GCC="$(find "$BUILDROOT_DIR/output/host/bin" -maxdepth 1 \( -name '*-linux-*-gcc' -o -name '*-linux-gcc' \) | sort | head -n 1)"
if [ -z "$TARGET_GCC" ]; then
  echo "could not find Buildroot target Linux gcc under $BUILDROOT_DIR/output/host/bin" >&2
  exit 1
fi

"$TARGET_GCC" -O2 -Wall -Wextra -static -o "$EXP_OVERLAY/usr/bin/rvmt_linux_user_pass" \
    "$ROOT/board/artix7_35t/linux/rvmt_linux_user_pass.c"
"$TARGET_GCC" -O2 -Wall -Wextra -static -o "$EXP_OVERLAY/usr/bin/rvmt_trace_dump" \
    "$ROOT/board/artix7_35t/linux/rvmt_trace_dump.c"
RVMT_EXP_RUNNER_TEXT_BASE="${RVMT_EXP_RUNNER_TEXT_BASE:-0x01000000}"
"$TARGET_GCC" -O2 -Wall -Wextra -static -Wl,-Ttext-segment="$RVMT_EXP_RUNNER_TEXT_BASE" -o "$EXP_OVERLAY/usr/bin/rvmt_exp_runner" \
    "$ROOT/board/artix7_35t/linux/rvmt_exp_runner.c"
"$TARGET_GCC" -O2 -Wall -Wextra -static -o "$EXP_OVERLAY/usr/bin/rvmt_benign_workload" \
    "$ROOT/board/artix7_35t/linux/rvmt_benign_workload.c"

for source in "$ROOT"/experiments/linux_behavior/malware_like/programs/*.c; do
  name="$(basename "$source" .c)"
  "$TARGET_GCC" -O2 -Wall -Wextra -static -o "$EXP_OVERLAY/usr/bin/$name" "$source"
done

for source in "$ROOT"/experiments/linux_behavior/malware_like/extension_programs/*.c; do
  name="$(basename "$source" .c)"
  "$TARGET_GCC" -O2 -Wall -Wextra -static -o "$EXP_OVERLAY/usr/bin/$name" "$source"
done

make BR2_ROOTFS_OVERLAY="$LOLV/buildroot/board/litex_vexriscv/rootfs_overlay $OVERLAY $EXP_OVERLAY"

rm -f "$LOLV/images/Image" "$LOLV/images/rootfs.cpio" "$LOLV/images/opensbi.bin" "$LOLV/images/rootfs.ext4"
cp "$BUILDROOT_DIR/output/images/Image" "$LOLV/images/Image"
cp "$BUILDROOT_DIR/output/images/rootfs.cpio" "$LOLV/images/rootfs.cpio"
cp "$BUILDROOT_DIR/output/images/fw_jump.bin" "$LOLV/images/opensbi.bin"
cp "$BUILDROOT_DIR/output/images/rootfs.ext4" "$LOLV/images/rootfs.ext4"

ROOTFS_START=$((0x41000000))
ROOTFS_SIZE="$(stat -c %s "$LOLV/images/rootfs.cpio")"
ROOTFS_END=$((ROOTFS_START + ((ROOTFS_SIZE + 4095) / 4096) * 4096))
printf -v ROOTFS_END_HEX "0x%08x" "$ROOTFS_END"
TMP_DTS="$EXP_OVERLAY/rv32.dts"
dtc -I dtb -O dts -o "$TMP_DTS" "$LOLV/images/rv32.dtb"
sed -i -E "s/linux,initrd-end = <0x[0-9a-fA-F]+>;/linux,initrd-end = <$ROOTFS_END_HEX>;/" "$TMP_DTS"
dtc -I dts -O dtb -o "$LOLV/images/rv32.dtb" "$TMP_DTS"
echo "updated rv32.dtb linux,initrd-end to $ROOTFS_END_HEX for rootfs.cpio size $ROOTFS_SIZE"
