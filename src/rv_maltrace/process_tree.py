from __future__ import annotations

import json
from pathlib import Path
from typing import Any


PROCESS_SYSCALLS = {"clone", "fork", "vfork", "execve", "waitid", "wait4", "waitpid"}


def parse_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(text, 16) if text.startswith("0x") else int(text, 10)
        except ValueError:
            return None
    return None


def positive_pid(value: Any) -> int | None:
    number = parse_int(value)
    if number is None or number <= 0:
        return None
    if number >= 0xFFFFF000 or number >= (1 << 63):
        return None
    return number


def syscall_arg(row: dict[str, Any], name: str) -> Any:
    args = row.get("args", {})
    if isinstance(args, dict):
        return args.get(name)
    return None


def is_target_relevant(row: dict[str, Any]) -> bool:
    if row.get("process_owner") == "target_child":
        return True
    confidence = str(row.get("confidence") or "")
    if "target" in confidence:
        return True
    ret = row.get("return")
    return isinstance(ret, dict) and ret.get("return_site_process_owner") == "target_child"


def path_value(row: dict[str, Any], arg_name: str) -> tuple[str | None, str | None]:
    direct = row.get("path") or row.get("path_string") or row.get("exec_path")
    if isinstance(direct, str) and direct:
        return direct, None
    args = row.get("args", {})
    if isinstance(args, dict):
        for key in (f"{arg_name}_string", f"{arg_name}_path", "path", "path_string"):
            value = args.get(key)
            if isinstance(value, str) and value:
                return value, None
        pointer = args.get(arg_name)
        if pointer is not None:
            return None, str(pointer)
    return None, None


def recover_process_tree(syscalls: list[dict[str, Any]], *, sample: str = "process_chain") -> dict[str, Any]:
    process_events: list[dict[str, Any]] = []
    processes: dict[int, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    pending_child_pids: list[int] = []
    limitations: list[str] = []
    clone_count = 0
    exec_count = 0
    wait_count = 0
    missing_clone_returns = 0
    path_strings_seen = False

    for row in syscalls:
        if not isinstance(row, dict) or row.get("name") not in PROCESS_SYSCALLS:
            continue
        if not is_target_relevant(row):
            continue
        name = str(row.get("name"))
        event = {
            "seq": row.get("seq"),
            "name": name,
            "return_value": row.get("return_value"),
            "confidence": row.get("confidence"),
            "process_owner": row.get("process_owner"),
        }

        if name in {"clone", "fork", "vfork"}:
            clone_count += 1
            child_pid = positive_pid(row.get("return_value"))
            event["child_pid_from_return"] = child_pid
            if child_pid is None:
                missing_clone_returns += 1
                event["limitation"] = "clone return did not provide a positive child PID in current semantic evidence"
            else:
                pending_child_pids.append(child_pid)
                processes.setdefault(
                    child_pid,
                    {
                        "pid": child_pid,
                        "ppid": "target_parent_unresolved",
                        "exec": None,
                        "observed_events": [],
                        "confidence": "medium",
                    },
                )["observed_events"].append(name)
                edges.append(
                    {
                        "parent_pid": "target_parent_unresolved",
                        "child_pid": child_pid,
                        "evidence": ["clone_return"],
                        "confidence": "medium",
                    }
                )
        elif name == "execve":
            exec_count += 1
            path, pointer = path_value(row, "a0")
            if path:
                path_strings_seen = True
            event["path"] = path
            event["path_pointer"] = pointer
            if pending_child_pids:
                pid = pending_child_pids[0]
                processes.setdefault(
                    pid,
                    {
                        "pid": pid,
                        "ppid": "target_parent_unresolved",
                        "exec": None,
                        "observed_events": [],
                        "confidence": "medium",
                    },
                )
                processes[pid]["exec"] = path or "path_unavailable"
                processes[pid]["observed_events"].append("execve")
                if path is None:
                    processes[pid]["confidence"] = "weak"
            elif path is None:
                event["limitation"] = "execve path string unavailable and no pending child PID from clone return"
        else:
            wait_count += 1
            wait_pid = positive_pid(syscall_arg(row, "a1"))
            event["wait_pid_arg"] = wait_pid
            if wait_pid is None:
                event["limitation"] = "wait target PID argument unavailable"
            matched = False
            for edge in edges:
                if edge.get("child_pid") == wait_pid:
                    edge["evidence"].append(name)
                    edge["confidence"] = "strong"
                    matched = True
            if not matched and wait_pid is not None:
                processes.setdefault(
                    wait_pid,
                    {
                        "pid": wait_pid,
                        "ppid": "target_parent_unresolved",
                        "exec": None,
                        "observed_events": [],
                        "confidence": "weak",
                    },
                )["observed_events"].append(name)
        process_events.append({key: value for key, value in event.items() if value is not None})

    if missing_clone_returns:
        limitations.append("one or more clone/fork events lack a positive child PID return")
    if exec_count and not path_strings_seen:
        limitations.append("execve path strings are unavailable; pointers are not dereferenced")
    if clone_count and wait_count and not edges:
        limitations.append("clone/wait shape exists, but strict parent-child edge closure is unavailable")

    if not process_events:
        status = "UNAVAILABLE"
        limitations.append("no target-attributed process-chain syscalls found")
    elif clone_count and exec_count and wait_count and edges and all(edge.get("confidence") == "strong" for edge in edges) and path_strings_seen:
        status = "PASS"
    else:
        status = "PARTIAL"

    return {
        "schema": "rvmt.process_tree.summary.v1",
        "sample": sample,
        "status": status,
        "root_process": "target_process",
        "processes": sorted(processes.values(), key=lambda row: int(row["pid"])),
        "edges": edges,
        "events": process_events,
        "observed_counts": {
            "clone_or_fork": clone_count,
            "execve": exec_count,
            "wait": wait_count,
        },
        "limitations": sorted(set(limitations)),
        "non_claims": [
            "no real malware detection claim",
            "no classifier accuracy claim",
            "no complete semantic reconstruction claim",
        ],
    }


def load_semantic_events(path: Path) -> list[dict[str, Any]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected semantic_events JSON object")
    rows = value.get("syscall_sequence")
    if not isinstance(rows, list):
        raise ValueError(f"{path}: missing syscall_sequence list")
    return [row for row in rows if isinstance(row, dict)]


def render_markdown(summary: dict[str, Any]) -> str:
    lines = [
        f"# Process Tree Summary: {summary['sample']}",
        "",
        f"Status: {summary['status']}",
        "",
        "Scope: Artix-7 35T / LiteX / VexRiscv only.",
        "",
        "Claim level: 35T hardware-trace-assisted synthetic malware-like behavior audit prototype.",
        "",
        "## Observed Counts",
        "",
    ]
    for key, value in summary["observed_counts"].items():
        lines.append(f"- {key}: {value}")
    lines += ["", "## Edges", ""]
    if summary["edges"]:
        for edge in summary["edges"]:
            evidence = ", ".join(str(item) for item in edge.get("evidence", []))
            lines.append(f"- {edge.get('parent_pid')} -> {edge.get('child_pid')}: confidence={edge.get('confidence')}, evidence={evidence}")
    else:
        lines.append("- none strictly closed")
    lines += ["", "## Limitations", ""]
    for item in summary["limitations"]:
        lines.append(f"- {item}")
    lines += [
        "",
        "## Non-claims",
        "",
        "- no real malware detection claim",
        "- no classifier accuracy claim",
        "- no complete semantic reconstruction claim",
    ]
    return "\n".join(lines) + "\n"
