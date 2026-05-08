from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any


DEFAULT_SPEC = Path("experiments/linux_behavior/semantic_enrichment_routes.json")
DEFAULT_DOC = Path("docs/semantic_enrichment_routes.md")
DEFAULT_TRACE_FORMAT = Path("docs/trace_format.md")
DEFAULT_UV_DOC = Path("docs/uv_workflow.md")

SPEC_KEYS = {
    "phase",
    "status",
    "policy_ref",
    "current_trace_mem_mode",
    "routes",
}
ROUTE_KEYS = {
    "id",
    "label",
    "class",
    "status",
    "purpose",
    "examples",
    "trigger",
    "risks",
    "guardrails",
}
EXPECTED_ROUTES = {
    "selective_memory_snapshot": {
        "label": "Route A",
        "class": "hardware",
        "status": "DEFERRED_POST_FPGA",
        "purpose": "Capture bounded pointer data around selected syscalls.",
        "examples": ["openat_pathname_prefix", "write_buffer_prefix"],
        "trigger": "after_fpga_trace_works",
        "risks": ["extra_memory_read_path", "timing_impact", "integration_complexity"],
        "guardrails": ["no_current_jsonl_memory_payload", "no_default_memory_trace_enable", "must_not_backpressure_core"],
    },
    "kernel_helper_metadata": {
        "label": "Route B",
        "class": "kernel_helper",
        "status": "DEFERRED_POST_FPGA",
        "purpose": "Expose pid, fd, and path metadata for offline alignment.",
        "examples": ["fd_path_table", "pid_exec_path"],
        "trigger": "after_linux_recovery_workflow_has_evidence",
        "risks": ["os_intrusion", "pure_hardware_narrative_dilution"],
        "guardrails": ["metadata_only", "hardware_trace_remains_authoritative", "must_be_optional"],
    },
    "ebpf_metadata_alignment": {
        "label": "Route C",
        "class": "ebpf",
        "status": "DEFERRED_POST_FPGA",
        "purpose": "Record high-level kernel semantic events for offline timestamp or cycle alignment.",
        "examples": ["kernel_semantic_event_stream", "timestamp_cycle_alignment"],
        "trigger": "after_linux_experiments_have_trace_evidence",
        "risks": ["kernel_version_dependency", "mvp_scope_drift", "core_contribution_dilution"],
        "guardrails": ["not_mvp_dependency", "not_core_contribution", "comparison_or_enrichment_only"],
    },
}
REQUIRED_DOC_TEXT = (
    "Phase 7.2 defines three deferred semantic enrichment routes.",
    "route comparison and gating plan, not an implementation claim and not experiment evidence.",
    "experiments/linux_behavior/semantic_enrichment_routes.json",
    "TRACE_MEM_MODE_NONE",
    "selective_memory_snapshot",
    "kernel_helper_metadata",
    "ebpf_metadata_alignment",
    "extra memory read path",
    "OS intrusive",
    "eBPF is not an MVP dependency",
    "is not the core contribution",
    "All routes remain deferred in this phase.",
    "No route changes the JSONL event set",
    "replaces RTL-level committed behavior trace",
)
FORBIDDEN_DOC_PATTERNS = (
    re.compile(r"\bPASS\b", re.IGNORECASE),
    re.compile(r"\b(?:route\s+[ABC]|selective\s+memory\s+snapshot|kernel\s+helper|eBPF)\s+(?:is|are|has|have)?\s*(?:been\s+)?(?:implemented|complete|completed|validated|passed)\b", re.IGNORECASE),
    re.compile(r"\b(?:phase\s*7(?:\.2)?\s+)?(?:implementation|semantic\s+enrichment\s+routes?|routes?)\s+(?:is|are|has|have)?\s*(?:been\s+)?(?:implemented|complete|completed|validated|passed)\b", re.IGNORECASE),
    re.compile(r"\bTRACE_MEM_MODE_(?:ADDR|RANGE)\s+(?:is\s+)?(?:enabled|default)\b", re.IGNORECASE),
    re.compile(r"\b(?:load/store\s+trace\s+records?|load/store|memory(?:\s+trace)?)\s+payloads?\s+(?:are\s+)?(?:enabled|implemented|available)\b", re.IGNORECASE),
    re.compile(r"\bload/store\s+trace\s+records?\s+(?:are\s+)?(?:enabled|implemented|available)\b", re.IGNORECASE),
    re.compile(r"\beBPF\s+(?:is\s+)?(?:required|mandatory|needed)\s+for\s+(?:the\s+)?MVP\b", re.IGNORECASE),
    re.compile(r"\beBPF\s+(?:is\s+)?(?:an?\s+)?MVP\s+dependency\b", re.IGNORECASE),
    re.compile(r"\bthe\s+MVP\s+(?:depends\s+on|requires)\s+eBPF\b", re.IGNORECASE),
    re.compile(r"\beBPF\s+(?:is|becomes)\s+(?:an?\s+|the\s+)?(?:core|main|primary)\s+contribution\b", re.IGNORECASE),
    re.compile(r"\broute\s+[ABC]\s+has\s+no\s+timing\s+impact\b", re.IGNORECASE),
    re.compile(r"\broute\s+[ABC]\s+cannot\s+backpressure\s+(?:the\s+)?core\b", re.IGNORECASE),
    re.compile(r"\bhardware\s+trace\s+is\s+no\s+longer\s+authoritative\b", re.IGNORECASE),
    re.compile(r"\bsoftware[- ]only\s+tracing\s+(?:replaces|supersedes)\s+(?:the\s+)?RTL\s+trace\b", re.IGNORECASE),
)


def resolve(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path


def normalized_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def routes_by_id(spec: dict[str, Any]) -> dict[str, dict[str, Any]]:
    routes = spec.get("routes")
    if not isinstance(routes, list):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for route in routes:
        if isinstance(route, dict) and isinstance(route.get("id"), str):
            result[route["id"]] = route
    return result


def check_spec(path: Path) -> list[str]:
    spec = load_json(path)
    errors: list[str] = []
    extra_keys = set(spec) - SPEC_KEYS
    missing_keys = SPEC_KEYS - set(spec)
    if extra_keys:
        errors.append(f"{path}: unexpected spec keys are not allowed: {sorted(extra_keys)}")
    if missing_keys:
        errors.append(f"{path}: missing required spec keys: {sorted(missing_keys)}")
    if spec.get("phase") != "7.2":
        errors.append(f"{path}: phase must be 7.2")
    if spec.get("status") != "DEFERRED_POST_FPGA":
        errors.append(f"{path}: status must be DEFERRED_POST_FPGA")
    if spec.get("policy_ref") != "experiments/linux_behavior/semantic_enrichment_rationale.json":
        errors.append(f"{path}: policy_ref must point at the Phase 7.1 rationale")
    if spec.get("current_trace_mem_mode") != "TRACE_MEM_MODE_NONE":
        errors.append(f"{path}: current_trace_mem_mode must remain TRACE_MEM_MODE_NONE")

    raw_routes = spec.get("routes")
    if not isinstance(raw_routes, list):
        errors.append(f"{path}: routes must be a list")
        raw_routes = []
    if len(raw_routes) != len(EXPECTED_ROUTES):
        errors.append(f"{path}: routes must contain exactly {len(EXPECTED_ROUTES)} entries")
    seen_route_ids: set[str] = set()
    for index, route in enumerate(raw_routes):
        if not isinstance(route, dict):
            errors.append(f"{path}: route entry {index} must be an object")
        elif not isinstance(route.get("id"), str):
            errors.append(f"{path}: route entry {index} must have a string id")
        elif route["id"] in seen_route_ids:
            errors.append(f"{path}: duplicate route id is not allowed: {route['id']}")
        else:
            seen_route_ids.add(route["id"])

    routes = routes_by_id(spec)
    if set(routes) != set(EXPECTED_ROUTES):
        errors.append(f"{path}: route ids differ from expected set: {sorted(routes)}")
    for route_id, expected in EXPECTED_ROUTES.items():
        route = routes.get(route_id, {})
        extra_route_keys = set(route) - ROUTE_KEYS
        missing_route_keys = ROUTE_KEYS - set(route)
        if extra_route_keys:
            errors.append(f"{path}: {route_id} has unexpected route keys: {sorted(extra_route_keys)}")
        if missing_route_keys:
            errors.append(f"{path}: {route_id} is missing route keys: {sorted(missing_route_keys)}")
        for field, value in expected.items():
            if route.get(field) != value:
                errors.append(f"{path}: {route_id}.{field} must be {value!r}")
    return errors


def check_doc(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    normalized = normalized_text(text)
    errors: list[str] = []
    for required in REQUIRED_DOC_TEXT:
        if normalized_text(required) not in normalized:
            errors.append(f"{path}: missing required text: {required}")
    for pattern in FORBIDDEN_DOC_PATTERNS:
        if pattern.search(text):
            errors.append(f"{path}: must not claim Phase 7.2 implementation, memory enablement, or eBPF MVP/core status")
    return errors


def check_trace_format(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    if "`TRACE_MEM_MODE_DEFAULT` is `TRACE_MEM_MODE_NONE`" not in text:
        errors.append(f"{path}: trace memory default must remain TRACE_MEM_MODE_NONE")
    if "does not define load/store trace records or memory data payload fields" not in text:
        errors.append(f"{path}: trace format must not define current load/store payloads")
    return errors


def check_uv_doc(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    for token, label in (
        ("tools/check_semantic_enrichment_routes.py", "Phase 7.2 checker command"),
        ("docs/semantic_enrichment_routes.md", "Phase 7.2 doc reference"),
        ("experiments/linux_behavior/semantic_enrichment_routes.json", "Phase 7.2 spec reference"),
    ):
        if token not in text:
            errors.append(f"{path}: missing {label}")
    return errors


def run_checks(root: Path, spec: Path, doc: Path, trace_format: Path, uv_doc: Path) -> list[str]:
    spec_path = resolve(root, spec)
    doc_path = resolve(root, doc)
    trace_format_path = resolve(root, trace_format)
    uv_path = resolve(root, uv_doc)
    errors: list[str] = []
    for path, label in (
        (spec_path, "spec"),
        (doc_path, "doc"),
        (trace_format_path, "trace format"),
        (uv_path, "uv workflow"),
    ):
        if not path.exists():
            errors.append(f"missing {label}: {path}")
    if errors:
        return errors
    errors.extend(check_spec(spec_path))
    errors.extend(check_doc(doc_path))
    errors.extend(check_trace_format(trace_format_path))
    errors.extend(check_uv_doc(uv_path))
    return errors


def write_fixture(root: Path) -> None:
    (root / "experiments/linux_behavior").mkdir(parents=True)
    (root / "docs").mkdir(parents=True)
    routes = []
    for route_id, expected in EXPECTED_ROUTES.items():
        routes.append({"id": route_id, **expected})
    (root / DEFAULT_SPEC).write_text(
        json.dumps(
            {
                "phase": "7.2",
                "status": "DEFERRED_POST_FPGA",
                "policy_ref": "experiments/linux_behavior/semantic_enrichment_rationale.json",
                "current_trace_mem_mode": "TRACE_MEM_MODE_NONE",
                "routes": routes,
            }
        ),
        encoding="utf-8",
    )
    (root / DEFAULT_DOC).write_text(
        """# Semantic Enrichment Routes

Phase 7.2 defines three deferred semantic enrichment routes.
route comparison and gating plan, not an implementation claim and not experiment evidence.
experiments/linux_behavior/semantic_enrichment_routes.json
TRACE_MEM_MODE_NONE
selective_memory_snapshot
kernel_helper_metadata
ebpf_metadata_alignment
extra memory read path
OS intrusive
eBPF is not an MVP dependency
is not the core contribution
All routes remain deferred in this phase.
No route changes the JSONL event set
replaces RTL-level committed behavior trace
""",
        encoding="utf-8",
    )
    (root / DEFAULT_TRACE_FORMAT).write_text(
        "`TRACE_MEM_MODE_DEFAULT` is `TRACE_MEM_MODE_NONE`.\n"
        "does not define load/store trace records or memory data payload fields\n",
        encoding="utf-8",
    )
    (root / DEFAULT_UV_DOC).write_text(
        "uv run python tools/check_semantic_enrichment_routes.py\n"
        "docs/semantic_enrichment_routes.md\n"
        "experiments/linux_behavior/semantic_enrichment_routes.json\n",
        encoding="utf-8",
    )


def expect_error(root: Path, expected: str) -> bool:
    return any(expected in error for error in run_checks(root, DEFAULT_SPEC, DEFAULT_DOC, DEFAULT_TRACE_FORMAT, DEFAULT_UV_DOC))


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        errors = run_checks(root, DEFAULT_SPEC, DEFAULT_DOC, DEFAULT_TRACE_FORMAT, DEFAULT_UV_DOC)
        if errors:
            for error in errors:
                print(f"[FAIL] self-test false positive: {error}", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        spec = load_json(root / DEFAULT_SPEC)
        spec["status"] = "PASS"
        (root / DEFAULT_SPEC).write_text(json.dumps(spec), encoding="utf-8")
        if not expect_error(root, "status must be DEFERRED"):
            print("[FAIL] self-test missed spec status regression", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        spec = load_json(root / DEFAULT_SPEC)
        spec["current_trace_mem_mode"] = "TRACE_MEM_MODE_RANGE"
        (root / DEFAULT_SPEC).write_text(json.dumps(spec), encoding="utf-8")
        if not expect_error(root, "TRACE_MEM_MODE_NONE"):
            print("[FAIL] self-test missed memory mode regression", file=sys.stderr)
            return 1

    for route_id in EXPECTED_ROUTES:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root)
            spec = load_json(root / DEFAULT_SPEC)
            spec["routes"] = [route for route in spec["routes"] if route["id"] != route_id]
            (root / DEFAULT_SPEC).write_text(json.dumps(spec), encoding="utf-8")
            if not expect_error(root, "route ids differ"):
                print(f"[FAIL] self-test missed missing route: {route_id}", file=sys.stderr)
                return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        spec = load_json(root / DEFAULT_SPEC)
        spec["routes"][0]["implemented"] = True
        (root / DEFAULT_SPEC).write_text(json.dumps(spec), encoding="utf-8")
        if not expect_error(root, "unexpected route keys"):
            print("[FAIL] self-test missed route overclaim key", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        spec = load_json(root / DEFAULT_SPEC)
        spec["routes"].append({"implemented": True, "status": "PASS"})
        (root / DEFAULT_SPEC).write_text(json.dumps(spec), encoding="utf-8")
        if not expect_error(root, "must have a string id"):
            print("[FAIL] self-test missed route entry without id", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        spec = load_json(root / DEFAULT_SPEC)
        spec["routes"].insert(
            0,
            {
                "id": "selective_memory_snapshot",
                "status": "PASS",
                "implemented": True,
            },
        )
        (root / DEFAULT_SPEC).write_text(json.dumps(spec), encoding="utf-8")
        if not expect_error(root, "duplicate route id"):
            print("[FAIL] self-test missed duplicate route id", file=sys.stderr)
            return 1

    for phrase in (
        "PASS",
        "Route A is implemented.",
        "selective memory snapshot has been validated.",
        "Phase 7.2 implementation is complete.",
        "Semantic enrichment routes have been validated.",
        "TRACE_MEM_MODE_RANGE is enabled.",
        "memory payloads are implemented.",
        "memory trace payloads are available.",
        "load/store trace records are available.",
        "eBPF is required for the MVP.",
        "eBPF is an MVP dependency.",
        "The MVP requires eBPF metadata alignment.",
        "eBPF becomes the primary contribution.",
        "Route A has no timing impact.",
        "Route A cannot backpressure the core.",
        "hardware trace is no longer authoritative.",
        "software-only tracing replaces RTL trace.",
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root)
            doc = root / DEFAULT_DOC
            doc.write_text(doc.read_text(encoding="utf-8") + f"\n{phrase}\n", encoding="utf-8")
            if not expect_error(root, "must not claim Phase 7.2"):
                print(f"[FAIL] self-test missed unsafe doc phrase: {phrase}", file=sys.stderr)
                return 1

    for old, expected in (
        ("`TRACE_MEM_MODE_DEFAULT` is `TRACE_MEM_MODE_NONE`", "trace memory default"),
        ("does not define load/store trace records or memory data payload fields", "load/store payloads"),
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root)
            trace_format = root / DEFAULT_TRACE_FORMAT
            trace_format.write_text(trace_format.read_text(encoding="utf-8").replace(old, ""), encoding="utf-8")
            if not expect_error(root, expected):
                print(f"[FAIL] self-test missed trace_format guardrail: {old}", file=sys.stderr)
                return 1

    for token, expected in (
        ("tools/check_semantic_enrichment_routes.py", "checker command"),
        ("docs/semantic_enrichment_routes.md", "doc reference"),
        ("experiments/linux_behavior/semantic_enrichment_routes.json", "spec reference"),
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root)
            uv_doc = root / DEFAULT_UV_DOC
            uv_doc.write_text(uv_doc.read_text(encoding="utf-8").replace(token, ""), encoding="utf-8")
            if not expect_error(root, expected):
                print(f"[FAIL] self-test missed missing uv reference: {token}", file=sys.stderr)
                return 1

    print("[PASS] semantic enrichment routes self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Phase 7.2 semantic enrichment routes.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--spec", type=Path, default=DEFAULT_SPEC)
    parser.add_argument("--doc", type=Path, default=DEFAULT_DOC)
    parser.add_argument("--trace-format", type=Path, default=DEFAULT_TRACE_FORMAT)
    parser.add_argument("--uv-doc", type=Path, default=DEFAULT_UV_DOC)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    try:
        errors = run_checks(args.root.resolve(), args.spec, args.doc, args.trace_format, args.uv_doc)
    except Exception as exc:
        print(f"check_semantic_enrichment_routes: error: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    print("[PASS] Phase 7.2 semantic enrichment routes are specified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
