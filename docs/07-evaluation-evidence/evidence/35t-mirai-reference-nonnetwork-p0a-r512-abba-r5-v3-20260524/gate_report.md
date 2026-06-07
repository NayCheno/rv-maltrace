# 35T Extension Gate Check: 35t-mirai-reference-nonnetwork-p0a-r512-abba-r5-v3-20260524

Status: PASS

Scope: Artix-7 35T / LiteX / VexRiscv.

## Checks

- results_root_exists: PASS
- gate_report_available_or_derived: PASS
- metrics_exists: PASS
- run_config_exists: PASS
- expected_samples_present: PASS
- network_optional_samples_excluded: PASS
- all_samples_pass: PASS
- trace_records_512: PASS
- trace_profile_policy_35t_small_capacity: PASS
- runtime_order_abba: PASS
- real_malware_forbidden: PASS
- network_disabled: PASS
- include_extension_samples_explicit: PASS

## Samples

| Sample | Status | Gate | DROP median | Evidence | Matched expected |
| --- | --- | --- | ---: | --- | --- |
| `mirai_proc_scan_sim` | `PASS` | `PASS` | 0.0 | `behavior_audit` | `mirai_proc_scan_simulation` |
| `mirai_watchdog_probe_sim` | `PASS` | `PASS` | 0.0 | `behavior_audit` | `mirai_watchdog_probe` |
| `mirai_encoded_table_sim` | `PASS` | `PASS` | 0.0 | `behavior_audit` | `mirai_encoded_table_access` |

## Failures

- none

## Non-claims

- no CVA6 board claim
- no real malware detection claim
- no mature detector claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
- extension gate is reported separately from the primary 13-sample gate
