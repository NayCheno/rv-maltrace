# Check Suites

Use check suites instead of picking commands from the long workflow catalog.
The suite manifest is `tools/check_suites.json`, and the runner is:

```powershell
uv run python tools/run_check_suite.py --list-suites
```

## Current Route

Current Digilent Genesys2 + CVA6 gate:

```powershell
uv run python tools/run_check_suite.py --suite genesys2-current
```

Compatibility wrapper:

```powershell
uv run python tools/check_genesys2_current.py
```

This is the default fast round. It checks existing repository evidence and local
policy gates; it must not run Vivado synthesis, implementation, or bitstream
generation.

Board-only subset without safe surrogate evidence:

```powershell
uv run python tools/run_check_suite.py --suite genesys2-board
```

Existing bitstream artifact inventory:

```powershell
uv run python tools/run_check_suite.py --suite genesys2-artifacts
uv run python tools/check_genesys2_bitstream_artifacts.py --strict
```

This inventory is still a fast check: it fails quickly when reusable artifacts
are missing or timing is not clean. It must not repair the artifacts or start a
Vivado rebuild by itself.

Fast fixture self-tests for the current checkers:

```powershell
uv run python tools/run_check_suite.py --suite genesys2-self-test
```

## Long Vivado Tasks

Vivado bitstream builds are not part of the default fast round. They are
explicit long tasks and the suite runner refuses to execute them unless
`--include-long` is passed.

Dry-run a trace-enabled rebuild command:

```powershell
uv run python tools/run_check_suite.py --suite genesys2-trace-bitstream-long --dry-run
```

Run a trace-enabled rebuild only when trace RTL or trace bitstream artifacts
actually need regeneration:

```powershell
uv run python tools/run_check_suite.py --suite genesys2-trace-bitstream-long --include-long
```

The baseline rebuild suite is similarly explicit:

```powershell
uv run python tools/run_check_suite.py --suite genesys2-baseline-bitstream-long --include-long
```

## Local Analysis

Repository-local Linux behavior and code-analysis checks:

```powershell
uv run python tools/run_check_suite.py --suite linux-behavior-local
```

Repository hygiene inventory:

```powershell
uv run python tools/run_check_suite.py --suite repo-hygiene
```

## Boundaries

The current suites must not include 35T checks. The manifest self-test enforces
that rule for suites marked `current: true` and `legacy: false`.

Legacy 35T tools and documents may remain for historical reference or tool
design reference, but they are not current Genesys2/CVA6 completion evidence.
Real malware validation remains blocked unless the real-malware gate has
authorization, containment, hash metadata, hardware trace, local code analysis,
malware analysis, and integrated validation.
