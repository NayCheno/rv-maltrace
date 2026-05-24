# 35T Claim Boundary

Status: PASS

True real-malware gate status: REAL_MALWARE_VALIDATION_BLOCKED_NO_RUN_ARTIFACTS

## Checks

- manifest_schema: PASS
- sample_class_real_malware: PASS
- default_disabled: PASS
- external_quarantine_hash_only: PASS
- repository_payloads_disallowed: PASS
- no_repository_payload_files: PASS
- manual_real_malware_results_absent: PASS
- mirai_network_optional_samples_excluded: PASS

## Non-claims

- CCF-A-style evidence discipline is not a CCF-A acceptance guarantee
- true real-malware validation remains blocked until external quarantine evidence exists
- surrogate samples are repository-authored safe reimplementations
- Mirai-reference samples are non-network synthetic reference behaviors
- no CVA6 board claim
- no mature detector or classifier-accuracy claim
- no complete semantic reconstruction claim under p0a arg-mem-disabled tracing
