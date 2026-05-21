# 35T Board Syscall Side-Channel Smoke

Status: `STRICT_BOARD_VALIDATION_PASS_AFTER_SIDE_CHANNEL_BOOT`

Scope: Artix-7 35T / LiteX / VexRiscv only.

Claim level: 35T hardware-trace-assisted synthetic malware-like behavior audit prototype.

## What Passed

- The side-channel runner builds into the 35T rootfs image.
- The generated 35T image path is `vendor/litex/linux-on-litex-vexriscv/images/sdcard.img`.
- A temporary board runner using `PTRACE_GETREGSET` produced `RVMT_SYSCALL_OBS` UART rows on `file_scan` and `process_chain`.
- The 35T board was rebooted through the LiteX serial image path using `images/boot.json`, which loaded the updated rootfs with `/usr/bin/rvmt_exp_runner`.
- `35t-sidechannel-smoke-20260522e` captured 48 syscall side-channel rows across two files and packaged fd/path plus process-tree summaries as `PASS`.
- The full targeted validation run `35t-targeted-board-validation-20260522` passed the strict board-validation checker with fd/path `PASS`, process-tree `PASS`, and source attribution still `PARTIAL`.

## Historical Non-Passing Attempts

- `35t-sidechannel-smoke-20260522c` produced 56 syscall side-channel rows and two `syscall_side_channel.json` files, but the smoke used the pre state-machine-fix runner, so packaged fd/path and process-tree summaries remained `PARTIAL`.
- A later UART upload of the state-machine-fix runner failed hash verification (`expected_sha256=25b693f3c0974609efe5937e966e63bc702bb5e3d2b2a69061e8b403e9c80962`, board decoded hash `2f689d7dbc57d4ca99eb8fd5abba082776da516e0bf4e69b03f7bc182518bad5`) and is not valid evidence.

## Remaining Boundary

No additional 35T board rerun is required for the current prototype closure. Source-line attribution remains partial unless future runs add DWARF or source-location evidence.

## Non-Claims

- no CVA6 board claim
- no real malware detection claim
- no mature detector claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
