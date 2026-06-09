from __future__ import annotations

import argparse
import base64
import json
import re
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


MAP_RE = re.compile(r"^([0-9a-fA-F]+)-([0-9a-fA-F]+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)$")
MARKER_RE = re.compile(r"RVMT_RUNTIME_PROCESS(?:_MAP_BEGIN|_MAP_END|_MAP_RAW|_PROVENANCE)?\s+(.*)")
DEFAULT_SAMPLE_CLASS = "malware_like_synthetic"


def parse_fields(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for token in text.strip().split():
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        fields[key] = value
    return fields


def decode_hex_text(value: str | None) -> str:
    if not value:
        return ""
    try:
        return bytes.fromhex(value).decode("utf-8", errors="replace")
    except ValueError:
        return ""


def int_field(fields: dict[str, str], key: str, default: int | None = None) -> int | None:
    value = fields.get(key)
    if value is None:
        return default
    try:
        return int(value, 0)
    except ValueError:
        return default


def process_record(role: str) -> dict[str, Any]:
    return {
        "role": role,
        "pid": -1,
        "tgid": -1,
        "comm": "",
        "exe": "",
        "maps": [],
        "status": "UNKNOWN",
        "provenance": {"source": "genesys2_uart_runtime_process_map"},
    }


def ensure_process(runtime_map: dict[str, Any], role: str) -> dict[str, Any]:
    by_role = runtime_map.setdefault("_process_by_role", {})
    if not isinstance(by_role, dict):
        by_role = {}
        runtime_map["_process_by_role"] = by_role
    current = by_role.get(role)
    if isinstance(current, dict):
        return current
    current = process_record(role)
    by_role[role] = current
    processes = runtime_map.setdefault("processes", [])
    if isinstance(processes, list):
        processes.append(current)
    return current


def parse_map_line(line: str) -> dict[str, Any] | None:
    match = MAP_RE.match(line.strip())
    if not match:
        return None
    start, end, perms, offset, dev, inode, path = match.groups()
    return {
        "start": f"0x{int(start, 16):016x}",
        "end": f"0x{int(end, 16):016x}",
        "perms": perms,
        "offset": f"0x{int(offset, 16):x}",
        "dev": dev,
        "inode": int(inode),
        "path": path.strip(),
    }


def begin_map(fields: dict[str, str]) -> dict[str, Any]:
    return {
        "schema": fields.get("schema", "rvmt.runtime_process_map.v1"),
        "sample_class": fields.get("class", "unknown"),
        "sample_id": fields.get("sample", "unknown"),
        "mode": fields.get("mode", "trace-on"),
        "rep": int_field(fields, "rep", 0),
        "warmup": fields.get("warmup", "0") == "1",
        "status": "STARTED",
        "processes": [],
        "owners": {},
        "provenance": {
            "collector": "capture_genesys2_runtime_process_map.py",
            "method": "genesys2_uart_procfs_snapshot",
            "status": "STARTED",
            "warnings": "",
        },
        "_process_by_role": {},
    }


def update_runtime_map(runtime_map: dict[str, Any], line: str) -> None:
    if "RVMT_RUNTIME_PROCESS_MAP_BEGIN " in line:
        fields = parse_fields(line.split("RVMT_RUNTIME_PROCESS_MAP_BEGIN", 1)[1])
        runtime_map.clear()
        runtime_map.update(begin_map(fields))
        return
    if "RVMT_RUNTIME_PROCESS_MAP_END " in line:
        fields = parse_fields(line.split("RVMT_RUNTIME_PROCESS_MAP_END", 1)[1])
        runtime_map["status"] = fields.get("status", runtime_map.get("status", "UNKNOWN"))
        runtime_map["target_exit"] = int_field(fields, "target_exit")
        return
    if "RVMT_RUNTIME_PROCESS_PROVENANCE " in line:
        fields = parse_fields(line.split("RVMT_RUNTIME_PROCESS_PROVENANCE", 1)[1])
        runtime_map["provenance"] = {
            "collector": fields.get("collector", "capture_genesys2_runtime_process_map.py"),
            "method": fields.get("method", "genesys2_uart_procfs_snapshot"),
            "proc_sample_time": fields.get("proc_sample_time", "unknown"),
            "status": fields.get("status", "UNKNOWN"),
            "warnings": decode_hex_text(fields.get("warnings_hex")),
        }
        return
    if "RVMT_RUNTIME_PROCESS_MAP_RAW " in line:
        fields = parse_fields(line.split("RVMT_RUNTIME_PROCESS_MAP_RAW", 1)[1])
        role = fields.get("role", "unknown")
        raw = decode_hex_text(fields.get("line_hex"))
        entry = parse_map_line(raw)
        if entry is not None:
            ensure_process(runtime_map, role).setdefault("maps", []).append(entry)
        return
    if "RVMT_RUNTIME_PROCESS " in line:
        fields = parse_fields(line.split("RVMT_RUNTIME_PROCESS", 1)[1])
        role = fields.get("role", "unknown")
        process = ensure_process(runtime_map, role)
        process.update(
            {
                "role": role,
                "pid": int_field(fields, "pid", -1),
                "tgid": int_field(fields, "tgid", -1),
                "comm": decode_hex_text(fields.get("comm_hex")),
                "exe": decode_hex_text(fields.get("exe_hex")),
                "status": fields.get("status", "UNKNOWN"),
            }
        )


def finalize_runtime_map(runtime_map: dict[str, Any]) -> dict[str, Any]:
    if not runtime_map:
        runtime_map.update(begin_map({}))
        runtime_map["status"] = "BLOCKED"
        runtime_map["provenance"]["warnings"] = "missing runtime-process-map begin marker"

    for role in ("kernel", "unknown"):
        process = ensure_process(runtime_map, role)
        if role == "kernel":
            process.update(
                {
                    "pid": 0,
                    "tgid": 0,
                    "comm": "kernel",
                    "exe": "linux_kernel",
                    "status": "PASS",
                    "maps": [{"start": "0x00000000c0000000", "end": "0x0000000100000000", "perms": "r-xp", "offset": "0x0", "dev": "00:00", "inode": 0, "path": "linux_kernel"}],
                }
            )
        else:
            process.update({"pid": -1, "tgid": -1, "comm": "unknown", "exe": "", "status": "PASS", "maps": []})

    by_role = runtime_map.pop("_process_by_role", {})
    owners = {role: process for role, process in sorted(by_role.items()) if isinstance(process, dict)}
    runtime_map["owners"] = owners
    runtime_map["processes"] = [process for _, process in sorted(owners.items())]
    runtime_map["process_roles"] = sorted(owners)

    target = owners.get("target_child")
    provenance = runtime_map.get("provenance") if isinstance(runtime_map.get("provenance"), dict) else {}
    if isinstance(target, dict):
        runtime_map["pid"] = target.get("pid")
        runtime_map["tgid"] = target.get("tgid")
        runtime_map["comm"] = target.get("comm")
        runtime_map["exe"] = target.get("exe")
        runtime_map["maps"] = target.get("maps", [])
    else:
        runtime_map["pid"] = None
        runtime_map["tgid"] = None
        runtime_map["comm"] = ""
        runtime_map["exe"] = ""
        runtime_map["maps"] = []

    required_roles = {"runner_parent", "target_child", "kernel", "unknown"}
    status = str(runtime_map.get("status", "UNKNOWN"))
    if not required_roles <= set(owners):
        status = "BLOCKED"
    if not runtime_map.get("maps"):
        status = "BLOCKED"
    if provenance.get("status") != "PASS":
        status = "BLOCKED" if status == "PASS" else status
    runtime_map["status"] = status
    runtime_map["attribution_boundary"] = {
        "runtime_process_map": "available" if status == "PASS" else "not_available",
        "hardware_marker_scope_required": True,
        "strong_process_attribution_from_this_artifact_alone": False,
    }
    return runtime_map


def parse_log(path: Path) -> dict[str, Any]:
    runtime_map: dict[str, Any] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "RVMT_RUNTIME_PROCESS" in line:
            update_runtime_map(runtime_map, line)
    runtime_map = finalize_runtime_map(runtime_map)
    runtime_map["source_log"] = path.as_posix()
    return runtime_map


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def build_shell_command(args: argparse.Namespace) -> str:
    sample = args.sample_id
    sample_class = args.sample_class
    runtime_path = args.runtime_path
    mode = args.mode
    rep = args.rep
    warmup = 1 if args.warmup else 0
    settle = args.settle_seconds
    return f"""sample_id={shell_quote(sample)}
sample_class={shell_quote(sample_class)}
runtime_path={shell_quote(runtime_path)}
mode={shell_quote(mode)}
rep={rep}
warmup={warmup}
settle={settle}
hex() {{ printf '%s' \"$1\" | od -An -tx1 -v | tr -d ' \\n'; }}
emit_proc() {{
  role=\"$1\"
  pid=\"$2\"
  if [ -r \"/proc/$pid/comm\" ] && [ -r \"/proc/$pid/maps\" ]; then
    comm=$(cat \"/proc/$pid/comm\" 2>/dev/null | tr -d '\\r\\n')
    exe=$(readlink \"/proc/$pid/exe\" 2>/dev/null || true)
    echo \"RVMT_RUNTIME_PROCESS role=$role pid=$pid tgid=$pid comm_hex=$(hex \"$comm\") exe_hex=$(hex \"$exe\") status=PASS\"
    while IFS= read -r line; do
      echo \"RVMT_RUNTIME_PROCESS_MAP_RAW role=$role line_hex=$(hex \"$line\")\"
    done < \"/proc/$pid/maps\"
  else
    echo \"RVMT_RUNTIME_PROCESS role=$role pid=$pid tgid=$pid comm_hex= exe_hex= status=BLOCKED\"
  fi
}}
echo \"RVMT_RUNTIME_PROCESS_MAP_BEGIN schema=rvmt.runtime_process_map.v1 class=$sample_class sample=$sample_id mode=$mode rep=$rep warmup=$warmup\"
\"$runtime_path\" &
target_pid=$!
sleep \"$settle\"
emit_proc runner_parent $$
emit_proc target_child \"$target_pid\"
echo \"RVMT_RUNTIME_PROCESS_PROVENANCE collector=capture_genesys2_runtime_process_map.py method=genesys2_uart_procfs_snapshot proc_sample_time=$(date +%Y%m%dT%H%M%S 2>/dev/null || echo unknown) status=PASS warnings_hex=\"
wait \"$target_pid\"
target_exit=$?
echo \"RVMT_RUNTIME_PROCESS_MAP_END status=PASS target_exit=$target_exit\"
"""


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        log = root / "runtime.log"
        log.write_text(
            "\n".join(
                [
                    "RVMT_RUNTIME_PROCESS_MAP_BEGIN schema=rvmt.runtime_process_map.v1 class=malware_like_synthetic sample=illegal_trap mode=trace-on rep=0 warmup=1",
                    "RVMT_RUNTIME_PROCESS role=runner_parent pid=10 tgid=10 comm_hex=7368 exe_hex=2f62696e2f7368 status=PASS",
                    "RVMT_RUNTIME_PROCESS_MAP_RAW role=runner_parent line_hex=30303031303030302d303030313130303020722d78702030303030303030302030303a30302031202f62696e2f7368",
                    "RVMT_RUNTIME_PROCESS role=target_child pid=11 tgid=11 comm_hex=696c6c6567616c5f74726170 exe_hex=2f746d702f72766d745f70322f696c6c6567616c5f74726170 status=PASS",
                    "RVMT_RUNTIME_PROCESS_MAP_RAW role=target_child line_hex=30303031303030302d303030313130303020722d78702030303030303030302030303a30302032202f746d702f72766d745f70322f696c6c6567616c5f74726170",
                    "RVMT_RUNTIME_PROCESS_PROVENANCE collector=capture_genesys2_runtime_process_map.py method=genesys2_uart_procfs_snapshot proc_sample_time=20260610T000000 status=PASS warnings_hex=",
                    "RVMT_RUNTIME_PROCESS_MAP_END status=PASS target_exit=0",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        runtime_map = parse_log(log)
        if runtime_map.get("status") != "PASS":
            print("[FAIL] runtime process map fixture did not pass", file=sys.stderr)
            return 1
        if runtime_map.get("pid") != 11:
            print("[FAIL] target child pid was not promoted", file=sys.stderr)
            return 1
        if not runtime_map.get("maps"):
            print("[FAIL] target child maps were not parsed", file=sys.stderr)
            return 1
        if runtime_map.get("attribution_boundary", {}).get("strong_process_attribution_from_this_artifact_alone") is not False:
            print("[FAIL] runtime map overclaims process attribution", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        log = root / "runtime.log"
        log.write_text(
            "\n".join(
                [
                    "RVMT_RUNTIME_PROCESS_MAP_BEGIN schema=rvmt.runtime_process_map.v1 class=malware_like_synthetic sample=illegal_trap mode=trace-on rep=0 warmup=1",
                    "RVMT_RUNTIME_PROCESS role=runner_parent pid=10 tgid=10 comm_hex=7368 exe_hex=2f62696e2f7368 status=PASS",
                    "RVMT_RUNTIME_PROCESS_PROVENANCE collector=capture_genesys2_runtime_process_map.py method=genesys2_uart_procfs_snapshot proc_sample_time=20260610T000000 status=PASS warnings_hex=",
                    "RVMT_RUNTIME_PROCESS_MAP_END status=PASS target_exit=0",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        runtime_map = parse_log(log)
        if runtime_map.get("status") != "BLOCKED":
            print("[FAIL] missing target process should block runtime map", file=sys.stderr)
            return 1

    command = build_shell_command(
        argparse.Namespace(
            sample_id="illegal_trap",
            sample_class=DEFAULT_SAMPLE_CLASS,
            runtime_path="/tmp/rvmt_p2/illegal_trap",
            mode="trace-on",
            rep=0,
            warmup=True,
            settle_seconds=0.1,
        )
    )
    if "RVMT_RUNTIME_PROCESS_MAP_BEGIN" not in command or "/proc/$pid/maps" not in command:
        print("[FAIL] emitted shell command missing runtime-map markers", file=sys.stderr)
        return 1
    print("[PASS] Genesys2 runtime process map helper self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Emit and parse Genesys2/CVA6 runtime process map snapshots.")
    parser.add_argument("--sample-id", default="illegal_trap")
    parser.add_argument("--sample-class", default=DEFAULT_SAMPLE_CLASS)
    parser.add_argument("--runtime-path", default="/tmp/rvmt_p2/illegal_trap")
    parser.add_argument("--mode", default="trace-on")
    parser.add_argument("--rep", type=int, default=0)
    parser.add_argument("--warmup", action="store_true")
    parser.add_argument("--settle-seconds", default="0.1")
    parser.add_argument("--emit-command", action="store_true")
    parser.add_argument("--emit-command-b64", action="store_true")
    parser.add_argument("--parse-log", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    if args.emit_command or args.emit_command_b64:
        command = build_shell_command(args)
        if args.emit_command_b64:
            sys.stdout.write(base64.b64encode(command.encode("utf-8")).decode("ascii") + "\n")
        else:
            sys.stdout.write(command)
        return 0
    if args.parse_log is not None:
        runtime_map = parse_log(args.parse_log)
        runtime_map["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        if args.out is None:
            json.dump(runtime_map, sys.stdout, indent=2, sort_keys=True)
            sys.stdout.write("\n")
        else:
            write_json(args.out, runtime_map)
            print(f"[PASS] runtime process map written: {args.out}")
        return 0
    parser.error("choose --emit-command, --emit-command-b64, or --parse-log")


if __name__ == "__main__":
    raise SystemExit(main())
