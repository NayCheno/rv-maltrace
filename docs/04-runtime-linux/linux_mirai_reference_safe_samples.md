# Linux Mirai-reference Safe Samples

This note records the safe extension samples derived from a static review of
the Linux/Mirai portion of `gbrindisi/malware.git`. The reference repository
contains real Mirai source and downloader binaries; those files were not
imported, built, retained, or executed.

## Scope

The samples are repository-authored synthetic C programs for RV-MalTrace test
coverage. They are not real malware, not repackaged malware, and not malware
detection quality evidence.

| Sample | Reference behavior | Safety boundary | Expected behavior rule |
| --- | --- | --- | --- |
| `mirai_proc_scan_sim` | process enumeration used by competitor-killer logic | reads bounded `/proc` metadata only; no signals or process mutation | `mirai_proc_scan_simulation` |
| `mirai_watchdog_probe_sim` | watchdog and environment checks | opens only non-existent safe `/tmp/rvmt_safe_*watchdog` paths and reads `pid_max`; never opens a real watchdog device | `mirai_watchdog_probe` |
| `mirai_encoded_table_sim` | encoded string table/config access | decodes local path constants and reads `/proc/self/status` plus `/etc/resolv.conf`; no network resolution or connection | `mirai_encoded_table_access` |
| `mirai_c2_loopback_probe` | C2/report callback connection shape | optional loopback-only `127.0.0.1:48101` connection attempt; disabled by default | `mirai_loopback_c2_probe` |

## Staged Comprehensive Mirai Prototype

A staged `mirai_safety_comprehensive` prototype bundles the reviewed Mirai
behavior patterns into a single safety-controlled binary for local build and
QEMU smoke testing:

| Behavior module | Reference source | Observable syscalls |
| --- | --- | --- |
| Encoded table decode | `mirai/bot/table.c` toggle_obf + add_entry | `openat`, `read`, `close` on `/proc/self/status` and `/proc/sys/kernel/pid_max` |
| /proc process enumeration | `mirai/bot/killer.c` readdir + readlink + open loop | `getpid`, `getppid`, `readlinkat` on `/proc/<pid>/exe`, `openat`/`read`/`close` on `/proc/<pid>/status` |
| Watchdog device probe | `mirai/bot/main.c` watchdog disable block | `openat` on safe `/tmp/rvmt_safe_dev_*` paths (fails) + real `/dev/watchdog` (fails) + `/proc` sanity read |
| Self-process name hiding | `mirai/bot/main.c` prctl + argv0 overwrite | `prctl(PR_SET_NAME)` |
| Singleton instance check | `mirai/bot/main.c` ensure_single_instance | `socket`, `bind(loopback:48101)`, `listen`, `close` |
| Loopback C2 connection | `mirai/bot/main.c` establish_connection | `socket`, `connect(loopback:48101)` → ECONNREFUSED, `close` |

This prototype is not part of the current default `malware_like_synthetic`
manifest and is not part of the current `real_malware_surrogate` validation
manifest. It includes loopback socket, bind/listen, and connect shapes, so it
requires a separate loopback/network-explicit claim and gate before it can be
promoted to board-backed evidence. All destructive capabilities remain absent:
no fork/daemonization, no kill/unlink, no raw-socket scanning, no internet C2,
no credential brute-force, no DDoS attack, no persistence, no privilege
escalation.

### Docker Build

```powershell
docker compose -f docker-compose.toolchain.yml build mirai-safety
docker compose -f docker-compose.toolchain.yml run --rm mirai-safety bash docker/mirai-safety/build-mirai-safety.sh
```

### QEMU Smoke Test

```powershell
docker compose -f docker-compose.toolchain.yml run --rm linux-behavior bash -c `
  "qemu-riscv64 -L /usr/riscv64-linux-gnu -strace build/board/artix7_35t/rootfs_exp_overlay/usr/bin/mirai_safety_comprehensive"
```

### Promotion Gate

Before this prototype can be used as evidence, create a dedicated run profile
that records loopback-only network isolation, captures board trace artifacts,
emits the standard `hardware_trace/`, `local_code_analysis/`,
`malware_analysis/`, and `integrated_validation.json` layout, and updates the
relevant manifest only after the gate passes.

## Test Route

Use explicit sample selection so the default 35T matrix remains unchanged:

```text
uv run python tools/experiment_35t.py --stage groundtruth --run-id <run-id> --include-extension-samples --sample mirai_proc_scan_sim --sample mirai_watchdog_probe_sim --sample mirai_encoded_table_sim
```

The loopback probe should be selected only in a network-explicit run:

```text
uv run python tools/experiment_35t.py --stage groundtruth --run-id <run-id> --include-extension-samples --sample mirai_c2_loopback_probe
```

Real malware remains out of scope until source policy, legal/ethical approval,
containment, non-destructive replay, network isolation, and artifact
sanitization gates are complete.
