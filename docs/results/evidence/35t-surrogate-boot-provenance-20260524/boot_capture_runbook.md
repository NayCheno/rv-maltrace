# Surrogate Boot Capture Runbook

Capture a run-scoped Linux boot log before or with the surrogate board validation run:

```powershell
# target log: results/board/artix7_35t_litex/35t-surrogate-darthra-p0a-r512-abba-r5-20260524/06_linux_boot/uart_linux_boot.log
# reboot/load the Artix-7 35T Linux image used by the surrogate rootfs
# preserve the full UART boot transcript including serialboot summary, kernel jump, Linux version, and RVMT_LINUX_USER_PASS
```

After capture, rerun:

```powershell
uv run python tools/check_35t_surrogate_boot_provenance.py --no-write
```
