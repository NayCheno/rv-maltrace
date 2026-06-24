# Genesys2/CVA6 Linux Source Lock

This directory records repo-owned source inputs for the next Genesys2/CVA6
Buildroot/OpenSBI/SD-card Linux rebuild. These files are source-level
provenance only. They do not claim that the currently booted SD card was rebuilt
from this directory, and they do not claim live board PMU or cycle-counter
availability.

Use:

```bash
uv run rvmt ndss:linux-source-lock
uv run rvmt ndss:linux-rebuild-prep --fetch --configure
uv run rvmt ndss:linux-rebuild-prep --execute --jobs 8
uv run rvmt ndss:boot-sdcard-image --payload build/linux/genesys2-cva6/images/fw_payload.bin --rootfs build/linux/genesys2-cva6/images/rootfs.ext2
uv run python tools/check_genesys2_boot_sdcard_image.py --root .
uv run rvmt ndss:linux-counter-preflight
```

`ndss:linux-rebuild-prep` runs inside Docker. Without `--execute`, it prepares
the generated CVA6 DTS and Buildroot defconfig and may fetch/configure
Buildroot; it does not claim a boot payload. With `--execute`, it attempts the
long full Buildroot/OpenSBI build and requires a real `fw_payload.bin` before
recording `PASS_LINUX_PAYLOAD_BUILT`.

`ndss:boot-sdcard-image` expects a real OpenSBI/Linux `fw_payload.bin` or
equivalent payload. It writes a GPT image whose first partition is only the
boot payload loaded by `rtl/cva6/corev_apu/fpga/src/bootrom/src/gpt.c`; it does
not compile Buildroot/OpenSBI by itself and does not claim that a physical SD
card was written or booted. The checker validates the image/partition hashes
and the non-claim boundary.

The live-board closure still requires exporting the rebuilt kernel config from
the board to `results/evaluation/genesys2-cva6/current/live_kernel_config.txt`
and rerunning the Genesys2 counter probes with their require-pass checkers.
