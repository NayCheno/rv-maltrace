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
