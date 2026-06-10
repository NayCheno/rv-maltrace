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

Board-only subset without safe surrogate evidence:

```powershell
uv run python tools/run_check_suite.py --suite genesys2-board
```

Fast fixture self-tests for the current checkers:

```powershell
uv run python tools/run_check_suite.py --suite genesys2-self-test
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
