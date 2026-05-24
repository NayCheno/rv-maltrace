# 35T Evidence-chain Reproduction Commands

```powershell
uv run python tools/experiment_35t.py --run-id 35t-surrogate-darthra-p0a-r512-abba-r5-20260524 --runtime-order abba --reps 5 --trace-records 512 --trace-profile p0a_syscall_drop --include-surrogate-samples --sample darthra_elf_header_probe --sample darthra_rootkit_device_probe --sample darthra_virus_fixture_walk_sim
```
```powershell
uv run python tools/check_real_malware_surrogate_gate.py --run-id 35t-surrogate-darthra-p0a-r512-abba-r5-20260524 --no-write
```
```powershell
uv run rvmt explain:35t --flow --run-id 35t-surrogate-darthra-p0a-r512-abba-r5-20260524
```
```powershell
uv run python tools/experiment_35t.py --run-id 35t-mirai-reference-nonnetwork-p0a-r512-abba-r5-v3-20260524 --runtime-order abba --reps 5 --trace-records 512 --trace-profile p0a_syscall_drop --trace-profile-policy 35t_small_capacity --include-extension-samples --sample mirai_proc_scan_sim --sample mirai_watchdog_probe_sim --sample mirai_encoded_table_sim
```
```powershell
uv run python tools/check_35t_extension_gate.py --run-id 35t-mirai-reference-nonnetwork-p0a-r512-abba-r5-v3-20260524 --expected-samples mirai_proc_scan_sim,mirai_watchdog_probe_sim,mirai_encoded_table_sim --no-write
```
```powershell
uv run rvmt explain:35t --flow --run-id 35t-mirai-reference-nonnetwork-p0a-r512-abba-r5-v3-20260524
```
```powershell
uv run python tools/check_real_malware_validation_gate.py --no-write
```
```powershell
uv run python tools/check_35t_real_malware_derived_lineage.py --no-write
```
```powershell
uv run python tools/check_35t_artifact_package_readiness.py --no-write
```
```powershell
uv run python tools/check_35t_evidence_consistency.py --no-write
```
```powershell
uv run python tools/check_35t_ccfa_evidence_chain.py --no-write
```
# Primary 35T evidence root: docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521
# Strengthened evidence root: docs/results/evidence/35t-ccfa-strong-evidence-chain-20260524
