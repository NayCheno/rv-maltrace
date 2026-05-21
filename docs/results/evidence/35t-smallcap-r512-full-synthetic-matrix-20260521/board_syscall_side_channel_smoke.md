# 35T Board Syscall Side-Channel Smoke

Status: `SIDE_CHANNEL_CAPTURED_BUT_STRICT_VALIDATION_NOT_CLOSED`

Scope: Artix-7 35T / LiteX / VexRiscv only.

Claim level: 35T hardware-trace-assisted synthetic malware-like behavior audit prototype.

## What Passed

- The side-channel runner builds into the 35T rootfs image.
- The generated 35T image path is `vendor/litex/linux-on-litex-vexriscv/images/sdcard.img`.
- A temporary board runner using `PTRACE_GETREGSET` produced `RVMT_SYSCALL_OBS` UART rows on `file_scan` and `process_chain`.

## What Did Not Close

- The committed strict board-validation status is still not PASS.
- `35t-sidechannel-smoke-20260522c` produced 56 syscall side-channel rows and two `syscall_side_channel.json` files, but the smoke used the pre state-machine-fix runner, so packaged fd/path and process-tree summaries remained `PARTIAL`.
- A later UART upload of the state-machine-fix runner failed hash verification (`expected_sha256=25b693f3c0974609efe5937e966e63bc702bb5e3d2b2a69061e8b403e9c80962`, board decoded hash `2f689d7dbc57d4ca99eb8fd5abba082776da516e0bf4e69b03f7bc182518bad5`) and is not valid evidence.

## Required Next Action

Boot the 35T board from the newly generated rootfs/sdcard image, or use a reliable binary transfer path with hash verification. Then rerun the full 13-sample validation command with `--syscall-side-channel`.

## Non-Claims

- no CVA6 board claim
- no real malware detection claim
- no mature detector claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
