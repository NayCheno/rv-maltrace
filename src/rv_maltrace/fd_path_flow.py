from __future__ import annotations

import json
from pathlib import Path
from typing import Any


FD_PATH_SYSCALLS = {"openat", "read", "write", "getdents64", "close", "execve"}
FD_OPS = {"read", "write", "getdents64", "close"}


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


def syscall_return_fd(value: Any) -> int | None:
    number = parse_int(value)
    if number is None:
        return None
    if number >= 0xFFFFF000 or number >= (1 << 63):
        return None
    if number < 0:
        return None
    return number


def syscall_return_value(row: dict[str, Any]) -> Any:
    if row.get("return_value") is not None:
        return row.get("return_value")
    ret = row.get("return")
    if isinstance(ret, dict):
        return ret.get("return_value")
    return None


def syscall_arg(row: dict[str, Any], name: str) -> Any:
    args = row.get("args", {})
    if isinstance(args, dict):
        return args.get(name)
    return None


def return_only_snapshot(row: dict[str, Any]) -> bool:
    return str(row.get("confidence") or "").startswith("return_only")


def path_value(row: dict[str, Any], arg_name: str) -> tuple[str | None, str | None, str]:
    confidence = str(row.get("confidence") or "")
    string_source = "board_syscall_side_channel" if confidence.startswith("board_syscall_side_channel") else "dereferenced_user_string"
    direct = row.get("path") or row.get("path_string") or row.get("exec_path")
    if isinstance(direct, str) and direct:
        return direct, None, string_source
    args = row.get("args", {})
    if isinstance(args, dict):
        for key in (f"{arg_name}_string", f"{arg_name}_path", "path", "path_string"):
            value = args.get(key)
            if isinstance(value, str) and value:
                return value, None, string_source
        pointer = args.get(arg_name)
        if pointer is not None:
            return None, str(pointer), "unavailable"
    return None, None, "unavailable"


def is_target_relevant(row: dict[str, Any]) -> bool:
    if row.get("process_owner") == "target_child":
        return True
    confidence = str(row.get("confidence") or "")
    if "target" in confidence:
        return True
    ret = row.get("return")
    return isinstance(ret, dict) and ret.get("return_site_process_owner") == "target_child"


def event_record(
    row: dict[str, Any],
    *,
    fd: int | None = None,
    fd_generation: int | None = None,
    path: str | None = None,
    path_pointer: str | None = None,
    path_source: str | None = None,
) -> dict[str, Any]:
    record = {
        "seq": row.get("seq"),
        "name": row.get("name"),
        "fd": fd,
        "fd_generation": fd_generation,
        "path": path,
        "path_pointer": path_pointer,
        "path_source": path_source,
        "return_value": syscall_return_value(row),
        "confidence": row.get("confidence"),
        "process_owner": row.get("process_owner"),
    }
    return {key: value for key, value in record.items() if value is not None}


def recover_fd_path_flow(syscalls: list[dict[str, Any]], *, sample: str = "unknown") -> dict[str, Any]:
    flows: list[dict[str, Any]] = []
    active: dict[int, dict[str, Any]] = {}
    fd_generations: dict[int, int] = {}
    pending_openats: list[dict[str, Any]] = []
    unresolved_fds: list[dict[str, Any]] = []
    unresolved_paths: list[dict[str, Any]] = []
    execve_events: list[dict[str, Any]] = []
    return_only_fd_ops: list[dict[str, Any]] = []
    return_only_execve_events: list[dict[str, Any]] = []
    target_fd_path_events = 0
    register_args_seen = False
    return_values_seen = False
    path_strings_seen = False

    for row in syscalls:
        if not isinstance(row, dict) or row.get("name") not in FD_PATH_SYSCALLS:
            continue
        if not is_target_relevant(row):
            continue
        target_fd_path_events += 1
        args = row.get("args")
        if isinstance(args, dict) and args:
            register_args_seen = True
        if syscall_return_value(row) is not None:
            return_values_seen = True

        name = str(row.get("name"))
        if name == "openat":
            path, pointer, path_source = path_value(row, "a1")
            if path:
                path_strings_seen = True
            fd = syscall_return_fd(syscall_return_value(row))
            next_generation = fd_generations.get(fd, 0) + 1 if fd is not None else None
            open_event = event_record(
                row,
                fd=fd,
                fd_generation=next_generation,
                path=path,
                path_pointer=pointer,
                path_source=path_source,
            )
            if fd is None:
                pending_openats.append(open_event)
                unresolved_paths.append(
                    {
                        "seq": row.get("seq"),
                        "syscall": "openat",
                        "reason": "openat return fd unavailable or failed in current semantic evidence",
                        "path_pointer": pointer,
                        "path_source": path_source,
                    }
                )
                continue
            fd_generations[fd] = next_generation or 1
            flow = {
                "process": row.get("process_owner") or "target_child",
                "path": path,
                "path_pointer": pointer,
                "path_source": path_source,
                "fd": fd,
                "fd_generation": fd_generations[fd],
                "open_seq": row.get("seq"),
                "ops": [],
                "status": "open",
                "events": [open_event],
                "confidence": "weak" if return_only_snapshot(row) else ("medium" if path is None else "strong"),
                "limitations": [],
            }
            if return_only_snapshot(row):
                flow["limitations"].append(
                    "openat fd came from a return-only snapshot; path pointer may be stale and must not be treated as a dereferenced path"
                )
            if path is None:
                flow["limitations"].append("path string unavailable; only pointer/register evidence is present")
            active[fd] = flow
            flows.append(flow)
            continue

        if name == "execve":
            if return_only_snapshot(row):
                return_only_execve_events.append(event_record(row))
                continue
            path, pointer, path_source = path_value(row, "a0")
            if path:
                path_strings_seen = True
            execve_events.append(event_record(row, path=path, path_pointer=pointer, path_source=path_source))
            if path is None:
                unresolved_paths.append(
                    {
                        "seq": row.get("seq"),
                        "syscall": "execve",
                        "reason": "execve path string unavailable; only pointer/register evidence is present",
                        "path_pointer": pointer,
                        "path_source": path_source,
                    }
                )
            continue

        if return_only_snapshot(row):
            return_only_fd_ops.append(
                {
                    "seq": row.get("seq"),
                    "syscall": name,
                    "reason": "return-only register snapshot does not preserve the fd argument reliably",
                    "return_value": syscall_return_value(row),
                    "confidence": row.get("confidence"),
                }
            )
            continue

        fd = parse_int(syscall_arg(row, "a0"))
        if fd is None:
            unresolved_fds.append({"seq": row.get("seq"), "syscall": name, "reason": "fd argument unavailable"})
            continue
        flow = active.get(fd)
        if flow is None:
            unresolved_fds.append(
                {
                    "seq": row.get("seq"),
                    "syscall": name,
                    "fd": fd,
                    "reason": "fd operation observed without a prior successful openat fd return in current semantic evidence",
                }
            )
            continue
        op_event = event_record(row, fd=fd, fd_generation=flow.get("fd_generation"))
        flow["events"].append(op_event)
        flow["ops"].append(name)
        if name == "close":
            flow["status"] = "closed"
            active.pop(fd, None)

    limitations: list[str] = []
    if not path_strings_seen:
        limitations.append("argument-level path strings are unavailable in current evidence; pointers are not dereferenced")
    if not return_values_seen:
        limitations.append("syscall return values are unavailable in current evidence")
    if pending_openats:
        limitations.append("some openat entries do not have paired successful fd return evidence")
    if unresolved_fds:
        limitations.append("some fd operations cannot be linked to a prior successful openat return")
    if return_only_fd_ops:
        limitations.append("some fd operations are return-only snapshots without reliable entry fd arguments")
    if active:
        limitations.append("one or more opened fds do not have a reliable close event in current semantic evidence")

    closed_flows = [flow for flow in flows if flow.get("status") == "closed"]
    if target_fd_path_events == 0:
        status = "UNAVAILABLE"
        limitations.append("no target-attributed fd/path syscalls found")
    elif path_strings_seen and flows and len(closed_flows) == len(flows) and not unresolved_fds and not pending_openats and not return_only_fd_ops:
        status = "PASS"
    else:
        status = "PARTIAL"
    if not register_args_seen:
        status = "UNAVAILABLE"
        limitations.append("syscall argument registers are unavailable")

    return {
        "schema": "rvmt.fd_path_flow.summary.v1",
        "sample": sample,
        "status": status,
        "flows": flows,
        "execve_events": execve_events,
        "return_only_fd_ops": return_only_fd_ops,
        "return_only_execve_events": return_only_execve_events,
        "unresolved_fds": unresolved_fds,
        "unresolved_paths": unresolved_paths,
        "pending_openats": pending_openats,
        "open_fds_at_end": [
            {
                "fd": fd,
                "fd_generation": flow.get("fd_generation"),
                "open_seq": flow.get("open_seq"),
                "path": flow.get("path"),
                "path_pointer": flow.get("path_pointer"),
                "path_source": flow.get("path_source"),
                "status": flow.get("status"),
                "confidence": flow.get("confidence"),
            }
            for fd, flow in sorted(active.items())
        ],
        "observed_counts": {
            "flows": len(flows),
            "closed_flows": len(closed_flows),
            "execve_events": len(execve_events),
            "return_only_fd_ops": len(return_only_fd_ops),
            "pending_openats": len(pending_openats),
            "unresolved_fds": len(unresolved_fds),
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
        f"# fd/path Flow Summary: {summary['sample']}",
        "",
        f"Status: {summary['status']}",
        "",
        "Scope: Artix-7 35T / LiteX / VexRiscv only.",
        "",
        "Claim level: 35T hardware-trace-assisted synthetic malware-like behavior audit prototype.",
        "",
        "## Flows",
        "",
    ]
    if summary["flows"]:
        for flow in summary["flows"]:
            event_names = ", ".join(str(event.get("name")) for event in flow.get("events", []))
            path = flow.get("path") or "unavailable"
            pointer = flow.get("path_pointer") or "unavailable"
            ops = ", ".join(str(op) for op in flow.get("ops", [])) or "none"
            lines.append(
                f"- fd {flow.get('fd')} gen {flow.get('fd_generation')}: status={flow.get('status')}, "
                f"path={path}, path_source={flow.get('path_source')}, path_pointer={pointer}, "
                f"ops={ops}, events={event_names}, confidence={flow.get('confidence')}"
            )
    else:
        lines.append("- none fully linked")
    lines += ["", "## Execve", ""]
    if summary["execve_events"]:
        for event in summary["execve_events"]:
            lines.append(f"- seq {event.get('seq')}: path={event.get('path') or 'unavailable'}, path_pointer={event.get('path_pointer') or 'unavailable'}")
    else:
        lines.append("- none")
    lines += ["", "## Return-only fd snapshots", ""]
    if summary.get("return_only_fd_ops"):
        for event in summary["return_only_fd_ops"]:
            lines.append(f"- seq {event.get('seq')}: {event.get('syscall')} ({event.get('reason')})")
    else:
        lines.append("- none")
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
