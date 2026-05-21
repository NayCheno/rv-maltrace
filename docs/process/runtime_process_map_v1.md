# Runtime Process Map v1

Schema id: `rvmt.runtime_process_map.v1`

This artifact is emitted once for each trace-on board repetition. It records the runtime process context used for process attribution. It is not a detector result.

Required top-level fields:

- `schema`: must be `rvmt.runtime_process_map.v1`.
- `sample_id`, `sample_class`, `mode`, `rep`, `warmup`.
- `pid`, `tgid`, `comm`, `exe`, `maps`: aliases for the target child process.
- `processes`: process records observed by the runner.
- `owners`: process records keyed by role.
- `process_roles`: must include `runner_parent`, `target_child`, `kernel`, and `unknown`.
- `provenance`: collector, method, sampling time, status, and warnings.
- `status`: `PASS` only when the target child `/proc/<pid>/exe`, `/proc/<pid>/comm`, and `/proc/<pid>/maps` were captured at the exec stop.

Each process record contains:

- `role`: `runner_parent`, `target_child`, `kernel`, or `unknown`.
- `pid`, `tgid`, `comm`, `exe`.
- `maps`: runtime map entries with `start`, `end`, `perms`, `offset`, `dev`, `inode`, and `path`.
- `status` and local provenance when available.

Attribution rule:

Process-attributed strong evidence requires all of:

- a valid marker scope for the trace-on repetition,
- a `PASS` runtime process map,
- the event PC inside the target child runtime map,
- the event PC matching the target code map site.

If the same PC is covered by both `runner_parent` and `target_child` runtime maps, attribution is ambiguous and must not be counted as process-attributed strong evidence.

Static `pc_owner=target_sample` by itself remains code-range evidence and is not complete process attribution.
