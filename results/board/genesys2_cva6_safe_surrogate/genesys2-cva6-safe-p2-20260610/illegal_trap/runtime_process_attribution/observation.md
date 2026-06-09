# Runtime Process Attribution Observation

Status: `RUNTIME_PROCESS_MAP_PASS_MARKER_SCOPE_MISSING`

The Genesys2/CVA6 board run now has a `rvmt.runtime_process_map.v1` snapshot for `illegal_trap`. The target child was observed as PID `3379`, command `illegal_trap`, executable `/tmp/rvmt_p2/illegal_trap`, with `4` runtime map entries.

The trace/code join was rerun with `runtime_process_map.json`. It records `runtime_process_map_status=PASS`, but `marker_scope.status=MISSING`, so `runtime_process_attribution_proven=false`. This removes the missing runtime-map blocker but does not yet prove strong process attribution.

Boundary: this is safe synthetic/surrogate evidence only. It does not demonstrate real malware validation, real malware detection quality, or single-window hardware marker-scoped attribution.
