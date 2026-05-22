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


def is_target_relevant(row: dict[str, Any]) -> bool:
    if row.get("process_owner") == "target_child":
        return True
    confidence = str(row.get("confidence") or "")
    if "target" in confidence:
        return True
    ret = row.get("return")
    return isinstance(ret, dict) and ret.get("return_site_process_owner") == "target_child"


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


def recover_process_tree(syscalls: list[dict[str, Any]], *, sample: str = "process_chain") -> dict[str, Any]:
    process_events: list[dict[str, Any]] = []
    processes: dict[int, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    partial_edges: list[dict[str, Any]] = []
    unclosed_edges: list[dict[str, Any]] = []
    clone_return_candidates: list[dict[str, Any]] = []
    wait_pid_candidates: list[int] = []
    unmatched_clone_return_candidates: list[dict[str, Any]] = []
    pending_exec_paths: list[dict[str, Any]] = []
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
            "return_value": syscall_return_value(row),
            "confidence": row.get("confidence"),
            "process_owner": row.get("process_owner"),
        }

        if name in {"clone", "fork", "vfork"}:
            clone_count += 1
            child_pid = positive_pid(syscall_return_value(row))
            event["child_pid_from_return"] = child_pid
            event["clone_return_child_pid"] = child_pid
            if child_pid is None:
                missing_clone_returns += 1
                event["limitation"] = "clone return did not provide a positive child PID in current semantic evidence"
                unclosed_edges.append(
                    {
                        "clone_seq": row.get("seq"),
                        "reason": "clone/fork event did not provide a positive parent-side child PID return",
                        "evidence": [name],
                        "edge_confidence": "unavailable",
                    }
                )
            else:
                candidate = {
                    "seq": row.get("seq"),
                    "child_pid": child_pid,
                    "clone_return_child_pid": child_pid,
                    "evidence": ["clone_return"],
                    "matched_wait": False,
                    "confidence": "medium",
                    "edge_confidence": "medium",
                }
                clone_return_candidates.append(candidate)
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
        elif name == "execve":
            exec_count += 1
            path, pointer, path_source = path_value(row, "a0")
            if path:
                path_strings_seen = True
            event["path"] = path
            event["path_pointer"] = pointer
            event["exec_path_source"] = path_source
            pending_exec_paths.append({"seq": row.get("seq"), "path": path, "path_pointer": pointer, "path_source": path_source})
            unmatched = [candidate for candidate in clone_return_candidates if not candidate.get("exec_attached")]
            if unmatched:
                pid = int(unmatched[0]["child_pid"])
                unmatched[0]["exec_attached"] = True
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
                processes[pid]["exec_path_source"] = path_source
                processes[pid]["observed_events"].append("execve")
                if path is None:
                    processes[pid]["confidence"] = "weak"
            elif path is None:
                event["limitation"] = "execve path string unavailable and no pending child PID from clone return"
        else:
            wait_count += 1
            wait_pid = positive_pid(syscall_arg(row, "a1"))
            event["wait_pid_arg"] = wait_pid
            event["wait_target_pid"] = wait_pid
            if wait_pid is None:
                event["limitation"] = "wait target PID argument unavailable"
            if wait_pid is not None:
                wait_pid_candidates.append(wait_pid)
            matched_candidate = None
            for candidate in clone_return_candidates:
                if candidate.get("child_pid") == wait_pid and not candidate.get("matched_wait"):
                    matched_candidate = candidate
                    break
            if matched_candidate is not None and wait_pid is not None:
                matched_candidate["matched_wait"] = True
                evidence = list(matched_candidate.get("evidence", []))
                evidence.append(name)
                edges.append(
                    {
                        "parent_pid": "target_parent_unresolved",
                        "child_pid": wait_pid,
                        "evidence": evidence,
                        "confidence": "strong",
                        "edge_confidence": "strong",
                    }
                )
                processes.setdefault(
                    wait_pid,
                    {
                        "pid": wait_pid,
                        "ppid": "target_parent_unresolved",
                        "exec": None,
                        "observed_events": [],
                        "confidence": "medium",
                    },
                )["observed_events"].append(name)
            elif wait_pid is not None:
                partial_edges.append(
                    {
                        "parent_pid": "target_parent_unresolved",
                        "child_pid": wait_pid,
                        "evidence": [name],
                        "reason": "wait PID was observed without matching positive clone-return child PID evidence",
                        "confidence": "weak",
                        "edge_confidence": "weak",
                    }
                )
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

    unmatched_clone_return_candidates = [
        candidate for candidate in clone_return_candidates if not candidate.get("matched_wait")
    ]
    for candidate in unmatched_clone_return_candidates:
        unclosed_edges.append(
            {
                "clone_seq": candidate.get("seq"),
                "child_pid": candidate.get("child_pid"),
                "reason": "positive clone-return child PID did not match observed wait PID evidence",
                "evidence": candidate.get("evidence", []),
                "confidence": candidate.get("confidence"),
                "edge_confidence": candidate.get("edge_confidence"),
            }
        )
    if missing_clone_returns:
        limitations.append("one or more clone/fork events lack a positive child PID return")
    if exec_count and not path_strings_seen:
        limitations.append("execve path strings are unavailable; pointers are not dereferenced")
    if clone_count and wait_count and not edges:
        limitations.append("clone/wait shape exists, but strict parent-child edge closure is unavailable")
    if unmatched_clone_return_candidates:
        limitations.append("one or more positive clone-return candidates do not match observed wait PID evidence")
    if partial_edges:
        limitations.append("one or more wait PID observations remain partial because matching clone-return evidence is unavailable")

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
        "partial_edges": partial_edges,
        "unclosed_edges": unclosed_edges,
        "clone_return_candidates": clone_return_candidates,
        "wait_pid_candidates": wait_pid_candidates,
        "unmatched_clone_return_candidates": unmatched_clone_return_candidates,
        "pending_exec_paths": pending_exec_paths,
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
            lines.append(
                f"- {edge.get('parent_pid')} -> {edge.get('child_pid')}: "
                f"edge_confidence={edge.get('edge_confidence', edge.get('confidence'))}, evidence={evidence}"
            )
    else:
        lines.append("- none strictly closed")
    lines += ["", "## Partial Edges", ""]
    if summary.get("partial_edges"):
        for edge in summary["partial_edges"]:
            evidence = ", ".join(str(item) for item in edge.get("evidence", []))
            lines.append(
                f"- {edge.get('parent_pid')} -> {edge.get('child_pid')}: "
                f"edge_confidence={edge.get('edge_confidence', edge.get('confidence'))}, evidence={evidence}, reason={edge.get('reason')}"
            )
    else:
        lines.append("- none")
    lines += ["", "## Unclosed Edges", ""]
    if summary.get("unclosed_edges"):
        for edge in summary["unclosed_edges"]:
            child = edge.get("child_pid", "unavailable")
            lines.append(f"- clone seq {edge.get('clone_seq')}: child_pid={child}, reason={edge.get('reason')}")
    else:
        lines.append("- none")
    lines += ["", "## PID Candidates", ""]
    if summary.get("clone_return_candidates"):
        for candidate in summary["clone_return_candidates"]:
            matched = "yes" if candidate.get("matched_wait") else "no"
            lines.append(f"- clone seq {candidate.get('seq')}: child_pid={candidate.get('child_pid')}, wait_matched={matched}")
    else:
        lines.append("- no positive clone-return child PID candidates")
    if summary.get("wait_pid_candidates"):
        waits = ", ".join(str(pid) for pid in summary["wait_pid_candidates"])
        lines.append(f"- wait PID candidates: {waits}")
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
