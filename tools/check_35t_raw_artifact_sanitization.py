from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


RUN_ID = "35t-smallcap-r512-full-synthetic-matrix-20260521"
DEFAULT_RESULTS_ROOT = Path("results/experiments/35t") / RUN_ID
DEFAULT_EVIDENCE_ROOT = Path("docs/07-evaluation-evidence/evidence") / RUN_ID
SCHEMA = "rvmt.35t.raw_artifact_sanitization.v1"
STATUS = "RAW_ARTIFACT_HASH_EXCERPT_READY_FULL_RAW_DEFERRED"
CLAIM_LEVEL = "35T hardware-trace-assisted synthetic malware-like behavior audit prototype"
SCOPE = "Artix-7 35T / LiteX / VexRiscv"
MAX_UART_EXCERPT_LINES = 12
MAX_JSONL_EXCERPT_EVENTS = 8
MAX_EXCERPT_CHARS = 240
JSONL_PUBLIC_KEYS = (
    "record_index",
    "cycle",
    "evt",
    "evt_code",
    "priv",
    "pc",
    "syscall_id",
    "duration",
    "target",
    "value",
)


@dataclass(frozen=True)
class RawClassSpec:
    artifact_id: str
    description: str
    min_count: int
    globs: tuple[str, ...]
    excerpt_kind: str


RAW_CLASSES = (
    RawClassSpec(
        "raw_uart_log",
        "raw board UART capture logs",
        1,
        ("**/raw_uart.log",),
        "text",
    ),
    RawClassSpec(
        "decoded_trace_jsonl",
        "decoded per-repetition trace JSONL",
        13,
        ("samples/**/board/trace-on/rep_*/trace.jsonl",),
        "jsonl",
    ),
)

REDACTION_PATTERNS = (
    ("private_key_marker", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghs|ghr)_[A-Za-z0-9_]{20,}\b|github_pat_[A-Za-z0-9_]{20,}")),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("bearer_token", re.compile(r"(?i)\bAuthorization:\s*Bearer\s+(?!<redacted>)[A-Za-z0-9._~+/=-]+")),
    ("key_value_secret", re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*(?!<redacted>)[^\s,;]+")),
    ("email_address", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("windows_user_path", re.compile(r"(?i)\b[A-Z]:\\Users\\(?!<redacted>)[^\\\s]+")),
    ("ipv4_address", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def repo_path(repo_root: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo_root / path


def rel(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def class_digest(files: list[Path], repo_root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(files, key=lambda item: rel(item, repo_root)):
        digest.update(rel(path, repo_root).encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(path.stat().st_size).encode("ascii"))
        digest.update(b"\0")
        digest.update(file_digest(path).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def count_lines(path: Path) -> int:
    lines = 0
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            lines += chunk.count(b"\n")
    return lines


def resolve_files(results_root: Path, spec: RawClassSpec) -> list[Path]:
    files: list[Path] = []
    seen: set[Path] = set()
    for pattern in spec.globs:
        for path in results_root.glob(pattern):
            if not path.is_file():
                continue
            resolved = path.resolve()
            if resolved in seen:
                continue
            files.append(path)
            seen.add(resolved)
    return sorted(files, key=lambda item: item.as_posix())


def scan_text(text: str) -> dict[str, int]:
    return {
        name: len(pattern.findall(text))
        for name, pattern in REDACTION_PATTERNS
        if pattern.findall(text)
    }


def redact_text(text: str) -> tuple[str, dict[str, int]]:
    findings: dict[str, int] = {}
    redacted = text
    for name, pattern in REDACTION_PATTERNS:
        matches = pattern.findall(redacted)
        if not matches:
            continue
        findings[name] = len(matches)
        if name == "key_value_secret":
            redacted = pattern.sub(lambda match: f"{match.group(1)}=<redacted>", redacted)
        elif name == "bearer_token":
            redacted = pattern.sub("Authorization: Bearer <redacted>", redacted)
        elif name == "windows_user_path":
            redacted = pattern.sub(r"C:\\Users\\<redacted>", redacted)
        else:
            redacted = pattern.sub(f"<redacted:{name}>", redacted)
    return redacted, findings


def merge_findings(rows: list[dict[str, int]]) -> dict[str, int]:
    merged: dict[str, int] = {}
    for row in rows:
        for key, value in row.items():
            merged[key] = merged.get(key, 0) + int(value)
    return merged


def sanitize_line(line: str) -> tuple[str, dict[str, int]]:
    redacted, findings = redact_text(line.rstrip("\r\n"))
    if len(redacted) > MAX_EXCERPT_CHARS:
        redacted = redacted[: MAX_EXCERPT_CHARS - 12] + "...<truncated>"
    return redacted.rstrip(), findings


def text_excerpt(path: Path) -> tuple[list[str], dict[str, int]]:
    lines: list[str] = []
    findings: list[dict[str, int]] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if len(lines) >= MAX_UART_EXCERPT_LINES:
                break
            sanitized, row_findings = sanitize_line(line)
            lines.append(sanitized)
            findings.append(row_findings)
    return lines, merge_findings(findings)


def public_trace_event(value: dict[str, Any]) -> dict[str, Any]:
    event = {key: value[key] for key in JSONL_PUBLIC_KEYS if key in value}
    warnings = value.get("parser_warnings")
    if isinstance(warnings, list):
        event["parser_warning_count"] = len(warnings)
    if "raw_words" in value:
        event["raw_word_count"] = len(value["raw_words"]) if isinstance(value["raw_words"], list) else None
    return event


def sanitize_public_value(value: Any) -> tuple[Any, dict[str, int]]:
    if isinstance(value, str):
        redacted, findings = redact_text(value)
        if len(redacted) > MAX_EXCERPT_CHARS:
            redacted = redacted[: MAX_EXCERPT_CHARS - 12] + "...<truncated>"
        return redacted, findings
    if isinstance(value, list):
        values = []
        findings = []
        for item in value:
            sanitized, row_findings = sanitize_public_value(item)
            values.append(sanitized)
            findings.append(row_findings)
        return values, merge_findings(findings)
    if isinstance(value, dict):
        sanitized_dict: dict[str, Any] = {}
        findings = []
        for key, item in value.items():
            sanitized, row_findings = sanitize_public_value(item)
            sanitized_dict[key] = sanitized
            findings.append(row_findings)
        return sanitized_dict, merge_findings(findings)
    return value, {}


def sanitize_public_event(event: dict[str, Any]) -> tuple[dict[str, Any], dict[str, int]]:
    sanitized, findings = sanitize_public_value(event)
    if not isinstance(sanitized, dict):
        return {"non_object_event": str(sanitized)[:MAX_EXCERPT_CHARS]}, findings
    return sanitized, findings


def jsonl_excerpt(path: Path) -> tuple[list[dict[str, Any]], dict[str, int], int]:
    events: list[dict[str, Any]] = []
    findings: list[dict[str, int]] = []
    invalid = 0
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if len(events) >= MAX_JSONL_EXCERPT_EVENTS:
                break
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                invalid += 1
                sanitized, row_findings = sanitize_line(line)
                findings.append(row_findings)
                events.append({"invalid_json_excerpt": sanitized})
                continue
            if isinstance(value, dict):
                event, row_findings = sanitize_public_event(public_trace_event(value))
                findings.append(row_findings)
                events.append(event)
            else:
                invalid += 1
                sanitized, row_findings = sanitize_public_value(value)
                findings.append(row_findings)
                events.append({"non_object_json_excerpt": str(sanitized)[:MAX_EXCERPT_CHARS]})
    return events, merge_findings(findings), invalid


def validate_jsonl(path: Path) -> dict[str, Any]:
    line_count = 0
    invalid_count = 0
    first_invalid_line = None
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line_number, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            line_count += 1
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                invalid_count += 1
                if first_invalid_line is None:
                    first_invalid_line = line_number
                continue
            if not isinstance(value, dict):
                invalid_count += 1
                if first_invalid_line is None:
                    first_invalid_line = line_number
    return {
        "line_count": line_count,
        "invalid_json_line_count": invalid_count,
        "first_invalid_json_line": first_invalid_line,
    }


def scan_file_for_sensitive_patterns(path: Path) -> dict[str, int]:
    findings: dict[str, int] = {}
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            for key, value in scan_text(line).items():
                findings[key] = findings.get(key, 0) + value
    return findings


def representative_row(path: Path, repo_root: Path, *, jsonl: bool) -> dict[str, Any]:
    row = {
        "path": rel(path, repo_root),
        "bytes": path.stat().st_size,
        "sha256": file_digest(path),
    }
    if jsonl:
        row.update(validate_jsonl(path))
    else:
        row["line_count"] = count_lines(path)
    return row


def build_class_row(repo_root: Path, results_root: Path, spec: RawClassSpec) -> dict[str, Any]:
    files = resolve_files(results_root, spec)
    total_bytes = sum(path.stat().st_size for path in files)
    representatives = [representative_row(path, repo_root, jsonl=spec.excerpt_kind == "jsonl") for path in files[:8]]
    source_findings = merge_findings([scan_file_for_sensitive_patterns(path) for path in files])

    excerpt: dict[str, Any] = {}
    excerpt_findings: dict[str, int] = {}
    if files and spec.excerpt_kind == "text":
        lines, excerpt_findings = text_excerpt(files[0])
        excerpt = {"source_path": rel(files[0], repo_root), "lines": lines}
    elif files and spec.excerpt_kind == "jsonl":
        events, excerpt_findings, invalid_excerpt_lines = jsonl_excerpt(files[0])
        excerpt = {
            "source_path": rel(files[0], repo_root),
            "events": events,
            "invalid_excerpt_lines": invalid_excerpt_lines,
        }

    invalid_json_line_count = sum(
        int(row.get("invalid_json_line_count", 0) or 0)
        for row in representatives
        if spec.excerpt_kind == "jsonl"
    )
    total_lines = sum(int(row.get("line_count", 0) or 0) for row in representatives)
    sanitized_text = json.dumps(excerpt, sort_keys=True)
    unsanitized_excerpt_findings = scan_text(sanitized_text)
    return {
        "artifact_id": spec.artifact_id,
        "description": spec.description,
        "file_count": len(files),
        "min_count": spec.min_count,
        "total_bytes": total_bytes,
        "representative_total_lines": total_lines,
        "class_digest": class_digest(files, repo_root) if files else None,
        "representative_files": representatives,
        "source_sensitive_pattern_findings": source_findings,
        "excerpt_redaction_findings": excerpt_findings,
        "sanitized_excerpt_unredacted_findings": unsanitized_excerpt_findings,
        "sanitized_excerpt": excerpt,
        "jsonl_invalid_line_count_in_representatives": invalid_json_line_count,
        "release_mode": "hash_and_sanitized_excerpt_public",
        "full_raw_status": "DEFERRED_PENDING_SANITIZATION_APPROVAL_AND_CONTROLLED_RELEASE",
    }


def build_report(repo_root: Path, results_root_arg: Path, evidence_root_arg: Path) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    results_root = repo_path(repo_root, results_root_arg).resolve()
    evidence_root = repo_path(repo_root, evidence_root_arg).resolve()
    rows = [build_class_row(repo_root, results_root, spec) for spec in RAW_CLASSES]
    by_id = {row["artifact_id"]: row for row in rows}
    raw_uart = by_id.get("raw_uart_log", {})
    decoded = by_id.get("decoded_trace_jsonl", {})
    checks = {
        "results_root_exists": results_root.is_dir(),
        "evidence_root_exists": evidence_root.is_dir(),
        "raw_uart_inventory_present": int(raw_uart.get("file_count", 0) or 0) >= 1,
        "decoded_trace_inventory_present": int(decoded.get("file_count", 0) or 0) >= 13,
        "decoded_trace_representatives_valid_jsonl": int(decoded.get("jsonl_invalid_line_count_in_representatives", 0) or 0) == 0,
        "hashes_recorded_for_all_raw_classes": all(row.get("class_digest") for row in rows),
        "sanitized_excerpts_generated": all(row.get("sanitized_excerpt") for row in rows),
        "sanitized_excerpts_do_not_expose_scanned_patterns": all(
            not row.get("sanitized_excerpt_unredacted_findings") for row in rows
        ),
        "full_raw_release_deferred": all(
            row.get("full_raw_status") == "DEFERRED_PENDING_SANITIZATION_APPROVAL_AND_CONTROLLED_RELEASE"
            for row in rows
        ),
    }
    failures = [key for key, ok in checks.items() if not ok]
    return {
        "schema": SCHEMA,
        "run_id": RUN_ID,
        "scope": SCOPE,
        "claim_level": CLAIM_LEVEL,
        "generated_utc": utc_now(),
        "status": STATUS if not failures else "FAIL",
        "source_results_root": rel(results_root, repo_root),
        "evidence_root": rel(evidence_root, repo_root),
        "checks": checks,
        "raw_artifact_classes": rows,
        "class_count": len(rows),
        "release_policy": {
            "public_material": "class hashes, representative file hashes, counts, and sanitized excerpts only",
            "full_raw_material": "deferred until explicit sanitization approval or controlled-release approval",
            "local_only_full_raw_classes": [row["artifact_id"] for row in rows],
        },
        "interpretation": [
            "raw UART logs and decoded trace JSONL are inventoried with hashes and representative sanitized excerpts",
            "this report does not publish full raw logs or full decoded trace JSONL",
            "full raw artifact release remains a P6 external condition until approval, escrow, or controlled-release policy is complete",
        ],
        "failures": failures,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# 35T Raw Artifact Sanitization: {report['run_id']}",
        "",
        f"Status: {report['status']}",
        "",
        f"Scope: {report['scope']}.",
        "",
        f"Claim level: {report['claim_level']}.",
        "",
        "## Checks",
        "",
    ]
    for key, ok in report["checks"].items():
        lines.append(f"- {key}: {'PASS' if ok else 'FAIL'}")
    lines += [
        "",
        "## Raw Artifact Classes",
        "",
        "| Class | Files | Bytes | Release Mode | Full Raw Status |",
        "| --- | ---: | ---: | --- | --- |",
    ]
    for row in report["raw_artifact_classes"]:
        lines.append(
            "| `{artifact_id}` | {count}/{minimum} | {bytes} | `{mode}` | `{raw}` |".format(
                artifact_id=row["artifact_id"],
                count=row["file_count"],
                minimum=row["min_count"],
                bytes=row["total_bytes"],
                mode=row["release_mode"],
                raw=row["full_raw_status"],
            )
        )
    lines += ["", "## Representative Excerpts", ""]
    for row in report["raw_artifact_classes"]:
        excerpt = row.get("sanitized_excerpt", {})
        lines.append(f"### {row['artifact_id']}")
        lines.append("")
        lines.append(f"Source: `{excerpt.get('source_path')}`")
        if "lines" in excerpt:
            lines.append("")
            lines.append("```text")
            lines.extend(str(line) for line in excerpt["lines"])
            lines.append("```")
        elif "events" in excerpt:
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(excerpt["events"], indent=2, sort_keys=True))
            lines.append("```")
        lines.append("")
    lines += ["## Interpretation", ""]
    lines.extend(f"- {item}" for item in report["interpretation"])
    lines += ["", "## Failures", ""]
    lines.extend(f"- {item}" for item in report["failures"] or ["none"])
    return "\n".join(lines) + "\n"


def write_outputs(report: dict[str, Any], evidence_root: Path) -> None:
    evidence_root.mkdir(parents=True, exist_ok=True)
    (evidence_root / "raw_artifact_sanitization.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (evidence_root / "raw_artifact_sanitization.md").write_text(
        render_markdown(report),
        encoding="utf-8",
        newline="\n",
    )


def write_fixture(root: Path, *, missing_trace: bool = False) -> None:
    results = root / DEFAULT_RESULTS_ROOT
    evidence = root / DEFAULT_EVIDENCE_ROOT
    evidence.mkdir(parents=True, exist_ok=True)
    raw = results / "board/raw_uart.log"
    raw.parent.mkdir(parents=True, exist_ok=True)
    raw.write_text(
        "# port=COM5 baud=921600 framing=8N1\n"
        "[000001.000] token=swordfish\n"
        "[000002.000] RVMT_EXP_BEGIN mode=abba reps=1\n",
        encoding="utf-8",
    )
    if not missing_trace:
        for index in range(13):
            trace = results / "samples/malware_like_synthetic" / f"sample_{index}" / "board/trace-on/rep_00/trace.jsonl"
            trace.parent.mkdir(parents=True, exist_ok=True)
            trace.write_text(
                json.dumps(
                    {
                        "record_index": 0,
                        "cycle": index,
                        "evt": "MARKER",
                        "evt_code": 12,
                        "pc": "0x0",
                        "raw_words": ["0x0", "0x1"],
                        "parser_warnings": [],
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        report = build_report(root, DEFAULT_RESULTS_ROOT, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != STATUS:
            print("[FAIL] expected complete fixture to pass raw artifact sanitization", file=sys.stderr)
            print(json.dumps(report, indent=2), file=sys.stderr)
            return 1
        raw_row = next(row for row in report["raw_artifact_classes"] if row["artifact_id"] == "raw_uart_log")
        excerpt_text = "\n".join(raw_row["sanitized_excerpt"]["lines"])
        if "ghp_" in excerpt_text or "swordfish" in excerpt_text:
            print("[FAIL] expected sensitive fixture values to be redacted", file=sys.stderr)
            return 1
        write_outputs(report, root / DEFAULT_EVIDENCE_ROOT)
        if not (root / DEFAULT_EVIDENCE_ROOT / "raw_artifact_sanitization.md").is_file():
            print("[FAIL] missing markdown output", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root, missing_trace=True)
        report = build_report(root, DEFAULT_RESULTS_ROOT, DEFAULT_EVIDENCE_ROOT)
        if report["status"] != "FAIL" or "decoded_trace_inventory_present" not in report["failures"]:
            print("[FAIL] expected missing trace fixture to fail", file=sys.stderr)
            return 1
    print("[PASS] 35T raw artifact sanitization self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inventory and sanitize bounded public excerpts for 35T raw artifacts.")
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS_ROOT)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    report = build_report(args.repo_root, args.results_root, args.evidence_root)
    evidence_root = repo_path(args.repo_root.resolve(), args.evidence_root).resolve()
    if not args.no_write:
        write_outputs(report, evidence_root)
    print(f"[{report['status']}] raw artifact sanitization: {len(report['raw_artifact_classes'])} classes")
    return 0 if report["status"] == STATUS else 1


if __name__ == "__main__":
    raise SystemExit(main())
