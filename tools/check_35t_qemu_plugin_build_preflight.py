from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


RUN_ID = "35t-qemu-plugin-build-preflight-20260523"
SOURCE_RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
DEFAULT_EVIDENCE_ROOT = Path("docs/results/evidence") / SOURCE_RUN_ID
SCHEMA = "rvmt.35t.qemu_plugin_build_preflight.v1"
STATUS = "QEMU_PLUGIN_SYSTEM_BUILD_LOAD_PREFLIGHT_PASS_USER_BASELINE_BLOCKED"
QEMU_VERSION_TAG = "v8.2.2"
QEMU_HEADER_URL = f"https://gitlab.com/qemu-project/qemu/-/raw/{QEMU_VERSION_TAG}/include/qemu/qemu-plugin.h"
QEMU_HEADER_SHA256 = "c53a2af163e80e3f4bc6c60dbdfc84003db329d757e37cd8a16a77e1d82606ff"
EXPECTED_SCOPE = "Artix-7 35T / LiteX / VexRiscv"
EXPECTED_CLAIM_LEVEL = "35T hardware-trace-assisted synthetic malware-like behavior audit prototype"
NON_CLAIMS = [
    "no CVA6 board claim",
    "no real malware detection claim",
    "no mature detector claim",
    "no classifier accuracy claim",
    "no complete semantic reconstruction claim",
    "no completed QEMU-plugin 13-sample baseline claim",
]


PLUGIN_SOURCE = r'''
#include <stdio.h>
#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info, int argc, char **argv)
{
    (void)id;
    (void)info;
    (void)argc;
    (void)argv;
    fprintf(stderr, "RVMT_QEMU_PLUGIN_INSTALL\n");
    return 0;
}
'''.strip()


DOCKER_PROBE_SCRIPT = rf'''
set -euo pipefail
work=/tmp/rvmt_qemu_plugin_build_preflight
rm -rf "$work"
mkdir -p "$work"
qemu_path="$(command -v qemu-riscv64 2>/dev/null || true)"
qemu_system_path="$(command -v qemu-system-riscv64 2>/dev/null || true)"
qemu_version=""
qemu_system_version=""
if [ -n "$qemu_path" ]; then
  qemu_version="$(qemu-riscv64 --version 2>&1 | head -n 1 || true)"
fi
if [ -n "$qemu_system_path" ]; then
  qemu_system_version="$(qemu-system-riscv64 --version 2>&1 | head -n 1 || true)"
fi
qemu_user_has_plugin=0
qemu_system_has_plugin=0
if [ -n "$qemu_path" ] && qemu-riscv64 --help 2>&1 | grep -- "-plugin" >/dev/null; then
  qemu_user_has_plugin=1
fi
if [ -n "$qemu_system_path" ] && qemu-system-riscv64 --help 2>&1 | grep -- "-plugin" >/dev/null; then
  qemu_system_has_plugin=1
fi
python3 - <<'PY'
import hashlib
import urllib.request
url = "{QEMU_HEADER_URL}"
path = "/tmp/rvmt_qemu_plugin_build_preflight/qemu-plugin.h"
with urllib.request.urlopen(url, timeout=30) as response:
    data = response.read()
with open(path, "wb") as fh:
    fh.write(data)
print("header_bytes=%d" % len(data))
print("header_sha256=%s" % hashlib.sha256(data).hexdigest())
PY
cat > "$work/rvmt_qemu_plugin_probe.c" <<'C'
{PLUGIN_SOURCE}
C
set +e
gcc -fPIC -shared -O2 -Wall -Wextra -I"$work" "$work/rvmt_qemu_plugin_probe.c" -o "$work/rvmt_qemu_plugin_probe.so" >"$work/gcc.out" 2>"$work/gcc.err"
gcc_exit="$?"
set -e
plugin_so_bytes=0
if [ -f "$work/rvmt_qemu_plugin_probe.so" ]; then
  plugin_so_bytes="$(stat -c%s "$work/rvmt_qemu_plugin_probe.so")"
fi
set +e
timeout 3 qemu-system-riscv64 -machine none -display none -monitor none -serial none -plugin "$work/rvmt_qemu_plugin_probe.so" -S >"$work/qemu.out" 2>"$work/qemu.err"
qemu_exit="$?"
set -e
printf 'qemu_path=%s\n' "$qemu_path"
printf 'qemu_version=%s\n' "$qemu_version"
printf 'qemu_system_path=%s\n' "$qemu_system_path"
printf 'qemu_system_version=%s\n' "$qemu_system_version"
printf 'qemu_user_has_plugin=%s\n' "$qemu_user_has_plugin"
printf 'qemu_system_has_plugin=%s\n' "$qemu_system_has_plugin"
printf 'gcc_exit=%s\n' "$gcc_exit"
printf 'plugin_so_bytes=%s\n' "$plugin_so_bytes"
printf 'qemu_exit=%s\n' "$qemu_exit"
printf 'gcc_stdout=%s\n' "$(tr '\n' '|' < "$work/gcc.out" | cut -c1-400)"
printf 'gcc_stderr=%s\n' "$(tr '\n' '|' < "$work/gcc.err" | cut -c1-400)"
printf 'qemu_stdout=%s\n' "$(tr '\n' '|' < "$work/qemu.out" | cut -c1-400)"
printf 'qemu_stderr=%s\n' "$(tr '\n' '|' < "$work/qemu.err" | cut -c1-400)"
'''.strip()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def repo_path(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def rel(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def parse_key_values(stdout: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in stdout.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key and all(ch.isalnum() or ch == "_" for ch in key):
            values[key] = value.strip()
    return values


def bool_field(values: dict[str, str], key: str) -> bool:
    return values.get(key) in {"1", "true", "True", "yes", "YES"}


def int_field(values: dict[str, str], key: str) -> int:
    try:
        return int(values.get(key, "0"))
    except ValueError:
        return 0


def docker_compose_base() -> list[str]:
    return ["docker", "compose", "-f", "docker-compose.toolchain.yml"]


def run_docker_probe(repo_root: Path, timeout_s: int) -> dict[str, Any]:
    cmd = [*docker_compose_base(), "run", "--rm", "linux-behavior", "bash", "-lc", DOCKER_PROBE_SCRIPT]
    try:
        completed = subprocess.run(
            cmd,
            cwd=str(repo_root),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_s,
        )
    except FileNotFoundError as exc:
        return {"argv": cmd, "exit_code": 127, "stdout": "", "stderr": str(exc)}
    except subprocess.TimeoutExpired as exc:
        return {
            "argv": cmd,
            "exit_code": 124,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or f"timeout after {timeout_s}s",
        }
    return {
        "argv": cmd,
        "exit_code": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def build_report_from_probe(probe: dict[str, Any]) -> dict[str, Any]:
    values = parse_key_values(str(probe.get("stdout", "")))
    checks = {
        "docker_probe_command_passed": probe.get("exit_code") == 0,
        "qemu_system_available": bool(values.get("qemu_system_path")),
        "qemu_system_exposes_plugin_option": bool_field(values, "qemu_system_has_plugin"),
        "qemu_user_available": bool(values.get("qemu_path")),
        "qemu_user_plugin_option_missing": not bool_field(values, "qemu_user_has_plugin"),
        "header_fetched_from_official_qemu_gitlab": int_field(values, "header_bytes") > 0,
        "header_sha256_matches_qemu_8_2_2": values.get("header_sha256") == QEMU_HEADER_SHA256,
        "plugin_compiled": int_field(values, "gcc_exit") == 0 and int_field(values, "plugin_so_bytes") > 0,
        "qemu_system_loads_plugin": "RVMT_QEMU_PLUGIN_INSTALL" in values.get("qemu_stderr", ""),
        "qemu_system_probe_timeout_expected": values.get("qemu_exit") == "124",
    }
    status = STATUS if all(checks.values()) else "FAIL"
    return {
        "schema": SCHEMA,
        "run_id": RUN_ID,
        "source_run_id": SOURCE_RUN_ID,
        "generated_utc": utc_now(),
        "status": status,
        "scope": EXPECTED_SCOPE,
        "claim_level": EXPECTED_CLAIM_LEVEL,
        "environment": "docker_linux_behavior",
        "qemu_header": {
            "url": QEMU_HEADER_URL,
            "version_tag": QEMU_VERSION_TAG,
            "bytes": int_field(values, "header_bytes"),
            "sha256": values.get("header_sha256", ""),
            "expected_sha256": QEMU_HEADER_SHA256,
        },
        "observed": {
            "qemu_path": values.get("qemu_path", ""),
            "qemu_version": values.get("qemu_version", ""),
            "qemu_system_path": values.get("qemu_system_path", ""),
            "qemu_system_version": values.get("qemu_system_version", ""),
            "qemu_user_has_plugin": bool_field(values, "qemu_user_has_plugin"),
            "qemu_system_has_plugin": bool_field(values, "qemu_system_has_plugin"),
            "gcc_exit": int_field(values, "gcc_exit"),
            "plugin_so_bytes": int_field(values, "plugin_so_bytes"),
            "qemu_exit": values.get("qemu_exit", ""),
            "qemu_stderr_excerpt": values.get("qemu_stderr", ""),
            "gcc_stderr_excerpt": values.get("gcc_stderr", ""),
        },
        "checks": checks,
        "probe": {
            "argv": probe.get("argv", []),
            "exit_code": probe.get("exit_code"),
            "stderr_tail": str(probe.get("stderr", ""))[-2000:],
        },
        "current_condition": (
            "qemu-system-riscv64 can load a freshly built minimal QEMU TCG plugin when the matching official "
            "QEMU 8.2.2 plugin header is fetched at probe time; qemu-riscv64 user-mode still does not expose "
            "-plugin, and no 13-sample QEMU-plugin baseline is recorded"
        ),
        "remaining_work": [
            "provide a plugin-capable RISC-V user-mode QEMU or a qemu-system harness that can execute the 13 Linux samples",
            "record per-sample QEMU-plugin trace output and timing for all 13 samples",
            "keep qemu_native and qemu_strace timing separate from QEMU-plugin trace evidence",
        ],
        "non_claims": NON_CLAIMS,
        "failures": [key for key, ok in checks.items() if not ok],
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# 35T QEMU-Plugin Build Preflight: {report['run_id']}",
        "",
        f"Status: {report['status']}",
        "",
        f"Environment: `{report['environment']}`",
        "",
        "## Checks",
        "",
    ]
    for key, ok in report["checks"].items():
        lines.append(f"- {key}: {'PASS' if ok else 'FAIL'}")
    observed = report["observed"]
    header = report["qemu_header"]
    lines += [
        "",
        "## Observed",
        "",
        f"- qemu-system: `{observed['qemu_system_path']}` ({observed['qemu_system_version']})",
        f"- qemu-user: `{observed['qemu_path']}` ({observed['qemu_version']})",
        f"- plugin SO bytes: {observed['plugin_so_bytes']}",
        f"- header: `{header['version_tag']}` sha256 `{header['sha256']}`",
        "",
        "## Current Condition",
        "",
        f"- {report['current_condition']}",
        "",
        "## Remaining Work",
        "",
    ]
    lines.extend(f"- {item}" for item in report["remaining_work"])
    lines += ["", "## Non-claims", ""]
    lines.extend(f"- {item}" for item in report["non_claims"])
    lines += ["", "## Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    return "\n".join(lines) + "\n"


def write_outputs(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    (evidence_root / "qemu_plugin_build_preflight.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (evidence_root / "qemu_plugin_build_preflight.md").write_text(
        render_markdown(report),
        encoding="utf-8",
        newline="\n",
    )


def fake_probe(*, user_plugin: bool = False, bad_hash: bool = False) -> dict[str, Any]:
    header_sha = "bad" if bad_hash else QEMU_HEADER_SHA256
    stdout = "\n".join(
        [
            "qemu_path=/usr/bin/qemu-riscv64",
            "qemu_version=qemu-riscv64 version 8.2.2",
            "qemu_system_path=/usr/bin/qemu-system-riscv64",
            "qemu_system_version=QEMU emulator version 8.2.2",
            f"qemu_user_has_plugin={1 if user_plugin else 0}",
            "qemu_system_has_plugin=1",
            "header_bytes=23814",
            f"header_sha256={header_sha}",
            "gcc_exit=0",
            "plugin_so_bytes=15672",
            "qemu_exit=124",
            "qemu_stderr=RVMT_QEMU_PLUGIN_INSTALL|qemu-system-riscv64: terminating on signal 15 from pid 19 (timeout)|",
            "gcc_stderr=",
        ]
    )
    return {"argv": ["fake"], "exit_code": 0, "stdout": stdout, "stderr": ""}


def self_test() -> int:
    report = build_report_from_probe(fake_probe())
    if report["status"] != STATUS:
        print("[FAIL] expected QEMU-plugin build preflight fixture to pass", file=sys.stderr)
        print(json.dumps(report, indent=2), file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        evidence = Path(tmp) / DEFAULT_EVIDENCE_ROOT
        write_outputs(report, evidence)
        if not (evidence / "qemu_plugin_build_preflight.md").is_file():
            print("[FAIL] missing markdown output", file=sys.stderr)
            return 1

    bad = build_report_from_probe(fake_probe(bad_hash=True))
    if bad["status"] != "FAIL" or "header_sha256_matches_qemu_8_2_2" not in bad["failures"]:
        print("[FAIL] expected bad header hash fixture to fail", file=sys.stderr)
        print(json.dumps(bad, indent=2), file=sys.stderr)
        return 1
    print("[PASS] 35T QEMU-plugin build preflight self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build and load a minimal QEMU TCG plugin in the current Docker environment.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--timeout-s", type=int, default=120)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    repo_root = args.repo_root.resolve()
    evidence_root = repo_path(repo_root, args.evidence_root).resolve()
    try:
        probe = run_docker_probe(repo_root, args.timeout_s)
        report = build_report_from_probe(probe)
        if not args.no_write:
            write_outputs(report, evidence_root)
    except Exception as exc:
        print(f"check_35t_qemu_plugin_build_preflight: error: {exc}", file=sys.stderr)
        return 2
    print(f"[{report['status']}] 35T QEMU-plugin build preflight")
    for failure in report["failures"]:
        print(f"failure: {failure}", file=sys.stderr)
    return 0 if report["status"] == STATUS else 1


if __name__ == "__main__":
    raise SystemExit(main())
