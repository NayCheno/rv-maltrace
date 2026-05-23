# RV-MalTrace 35T Explain Examples

Primary sample explanation:

```powershell
uv run rvmt explain:35t --run-id 35t-smallcap-r512-full-synthetic-matrix-20260521 --sample file_scan --rep auto
```

Tool wrapper equivalent:

```powershell
uv run python tools/explain_35t_sample.py --run-id 35t-smallcap-r512-full-synthetic-matrix-20260521 --sample file_scan --rep rep_00
```

Save Markdown while still printing:

```powershell
uv run python tools/explain_35t_sample.py --run-id 35t-smallcap-r512-full-synthetic-matrix-20260521 --sample anti_debug_like --rep auto --format markdown --tee-out reports/anti_debug_like_explain.md
```

Validation:

```powershell
uv run python tools/explain_35t_sample.py --self-test
uv run python -m compileall tools src/rv_maltrace
```

Expected interpretation:

- Suspicious cues are rule and syscall-pattern findings.
- Each cue includes an evidence source.
- Weak, inferred, side-channel, and bounded evidence is marked explicitly.
- The output preserves non-claims for CVA6, real malware detection, classifier accuracy, mature detector status, and complete semantic reconstruction.
