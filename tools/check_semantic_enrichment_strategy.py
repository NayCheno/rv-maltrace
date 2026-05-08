from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any


DEFAULT_SPEC = Path("experiments/linux_behavior/semantic_enrichment_strategy.json")
DEFAULT_DOC = Path("docs/semantic_enrichment_strategy.md")
DEFAULT_RATIONALE = Path("experiments/linux_behavior/semantic_enrichment_rationale.json")
DEFAULT_ROUTES = Path("experiments/linux_behavior/semantic_enrichment_routes.json")
DEFAULT_TRACE_FORMAT = Path("docs/trace_format.md")
DEFAULT_UV_DOC = Path("docs/uv_workflow.md")

SPEC_KEYS = {
    "phase",
    "status",
    "rationale_ref",
    "routes_ref",
    "current_mvp_policy",
    "strategy",
    "deprioritized_routes",
    "non_goals",
}
STEP_KEYS = {
    "order",
    "id",
    "stage",
    "decision",
    "dependency",
    "route",
    "allowed_work",
    "forbidden_work",
    "exit_gate",
}
DEPRIORITIZED_KEYS = {"route", "status", "reason"}
EXPECTED_STEPS = [
    {
        "order": 1,
        "id": "mvp_no_ebpf",
        "stage": "mvp",
        "decision": "no_ebpf",
        "dependency": "none",
        "route": None,
        "allowed_work": ["rtl_committed_behavior_trace"],
        "forbidden_work": [
            "ebpf_mvp_dependency",
            "kernel_helper_mvp_dependency",
            "memory_snapshot_mvp_dependency",
        ],
        "exit_gate": "cva6_vivado_mvp_trace_correct",
    },
    {
        "order": 2,
        "id": "evaluate_selective_memory_snapshot",
        "stage": "after_fpga_trace_works",
        "decision": "evaluate_only",
        "dependency": "fpga_trace_path_works",
        "route": "selective_memory_snapshot",
        "allowed_work": [
            "bounded_pointer_snapshot_design_review",
            "timing_resource_assessment",
            "noninterference_check",
        ],
        "forbidden_work": [
            "default_memory_trace_enable",
            "jsonl_payload_change_without_gate",
            "core_backpressure",
        ],
        "exit_gate": "timing_and_trace_noninterference_evidence",
    },
    {
        "order": 3,
        "id": "optional_ebpf_metadata_alignment",
        "stage": "after_linux_experiments",
        "decision": "optional_enrichment_only",
        "dependency": "linux_behavior_experiments_have_trace_evidence",
        "route": "ebpf_metadata_alignment",
        "allowed_work": [
            "offline_alignment_experiment",
            "comparison_experiment",
        ],
        "forbidden_work": [
            "mvp_dependency",
            "core_contribution_claim",
            "software_trace_replaces_rtl_trace",
        ],
        "exit_gate": "optional_comparison_result",
    },
]
EXPECTED_DEPRIORITIZED = [
    {
        "route": "kernel_helper_metadata",
        "status": "NOT_RECOMMENDED_FOR_MVP",
        "reason": "OS intrusive; revisit only if fd/path metadata is a blocking analysis gap after Linux experiments.",
    }
]
EXPECTED_NON_GOALS = [
    "ebpf_mvp_dependency",
    "kernel_helper_mvp_dependency",
    "memory_snapshot_mvp_dependency",
    "phase7_route_enablement",
    "load_store_payloads",
]
REQUIRED_DOC_TEXT = (
    "Phase 7.3 records the recommended semantic enrichment strategy.",
    "strategy gate record, not implementation evidence and not experiment evidence.",
    "experiments/linux_behavior/semantic_enrichment_strategy.json",
    "MVP: no eBPF",
    "no kernel helper and no memory snapshot dependency",
    "After FPGA trace works: evaluate selective memory snapshot as a gated option.",
    "The default trace memory mode remains `TRACE_MEM_MODE_NONE`",
    "no default memory trace, JSONL payload change, or core backpressure is allowed",
    "After Linux experiments: optionally add eBPF metadata alignment",
    "eBPF is not an MVP dependency",
    "is not the core contribution",
    "must not replace RTL-level committed behavior trace",
    "kernel_helper_metadata",
    "not on the recommended MVP path",
    "does not enable any Phase 7 route",
    "does not change the JSONL event set",
    "does not add load/store payloads",
)
FORBIDDEN_DOC_PATTERNS = (
    re.compile(r"\bPASS\b", re.IGNORECASE),
    re.compile(r"\b(?:phase\s*7(?:\.3)?\s+)?(?:strategy|semantic\s+enrichment\s+strategy)\s+(?:is|has|have)?\s*(?:been\s+)?(?:implemented|complete|completed|validated|passed)\b", re.IGNORECASE),
    re.compile(r"\b(?:semantic\s+enrichment|enrichment)\s+(?:is|has|have)?\s*(?:been\s+)?(?:enabled|implemented|available|validated|passed)\b", re.IGNORECASE),
    re.compile(r"\b(?:phase\s*7(?:\.\d+)?\s+)?(?:routes?|semantic\s+enrichment\s+routes?)\s+(?:are|is|has|have)?\s*(?:been\s+)?(?:enabled|implemented|available|validated|passed)\b", re.IGNORECASE),
    re.compile(r"\b(?:eBPF(?:\s+metadata\s+alignment)?|kernel\s+helper(?:\s+metadata)?|selective\s+memory\s+snapshot|memory\s+snapshot)\s+(?:is|are|has|have)?\s*(?:been\s+)?(?:enabled|implemented|available|validated|passed)\b", re.IGNORECASE),
    re.compile(r"\beBPF\s+(?:is\s+)?(?:required|mandatory|needed)\s+for\s+(?:the\s+)?MVP\b", re.IGNORECASE),
    re.compile(r"\beBPF\s+(?:is\s+)?(?:part\s+of|included\s+in)\s+(?:the\s+)?MVP\b", re.IGNORECASE),
    re.compile(r"\bthe\s+MVP\s+(?:depends\s+on|requires)\s+eBPF\b", re.IGNORECASE),
    re.compile(r"\beBPF\s+(?:is|becomes)\s+(?:an?\s+|the\s+)?(?:core|main|primary)\s+contribution\b", re.IGNORECASE),
    re.compile(r"\beBPF\s+(?:replaces|supersedes)\s+(?:the\s+)?RTL(?:-level)?\s+trace\b", re.IGNORECASE),
    re.compile(r"\b(?:kernel\s+helper|memory\s+snapshot|selective\s+memory\s+snapshot)\s+(?:is\s+)?(?:required|mandatory|needed)\s+for\s+(?:the\s+)?MVP\b", re.IGNORECASE),
    re.compile(r"\b(?:kernel\s+helper(?:\s+metadata)?|memory\s+snapshot|selective\s+memory\s+snapshot)\s+(?:is\s+)?(?:part\s+of|included\s+in)\s+(?:the\s+)?MVP\b", re.IGNORECASE),
    re.compile(r"\bthe\s+MVP\s+(?:depends\s+on|requires)\s+(?:a\s+)?(?:kernel\s+helper|memory\s+snapshot|selective\s+memory\s+snapshot)\b", re.IGNORECASE),
    re.compile(r"\b(?:selective\s+memory\s+snapshot|memory\s+snapshot)\s+(?:is|has)?\s*(?:been\s+)?(?:enabled|implemented|available|validated|passed)\b", re.IGNORECASE),
    re.compile(r"\bTRACE_MEM_MODE_(?:ADDR|RANGE)\s+(?:is\s+)?(?:enabled|default)\b", re.IGNORECASE),
    re.compile(r"\b(?:load/store\s+trace\s+records?|load/store|memory(?:\s+trace)?)\s+payloads?\s+(?:are\s+)?(?:enabled|implemented|available)\b", re.IGNORECASE),
    re.compile(r"\bload/store\s+trace\s+records?\s+(?:are\s+)?(?:enabled|implemented|available)\b", re.IGNORECASE),
    re.compile(r"\bsoftware[- ]only\s+tracing\s+(?:replaces|supersedes)\s+(?:the\s+)?RTL\s+trace\b", re.IGNORECASE),
)
FORBIDDEN_TRACE_FORMAT_PATTERNS = (
    re.compile(r"\bTRACE_MEM_MODE_(?:ADDR|RANGE)\s+(?:is\s+)?(?:enabled|default)\b", re.IGNORECASE),
    re.compile(r"\b(?:load/store\s+trace\s+records?|load/store|memory(?:\s+trace)?)\s+payloads?\s+(?:are\s+)?(?:enabled|implemented|available)\b", re.IGNORECASE),
    re.compile(r"\bload/store\s+trace\s+records?\s+(?:are\s+)?(?:enabled|implemented|available)\b", re.IGNORECASE),
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


def route_statuses(routes_spec: dict[str, Any]) -> dict[str, str]:
    routes = routes_spec.get("routes")
    if not isinstance(routes, list):
        return {}
    statuses: dict[str, str] = {}
    for route in routes:
        if isinstance(route, dict) and isinstance(route.get("id"), str):
            statuses[route["id"]] = str(route.get("status"))
    return statuses


def check_spec(path: Path) -> list[str]:
    spec = load_json(path)
    errors: list[str] = []
    extra_keys = set(spec) - SPEC_KEYS
    missing_keys = SPEC_KEYS - set(spec)
    if extra_keys:
        errors.append(f"{path}: unexpected spec keys are not allowed: {sorted(extra_keys)}")
    if missing_keys:
        errors.append(f"{path}: missing required spec keys: {sorted(missing_keys)}")
    if spec.get("phase") != "7.3":
        errors.append(f"{path}: phase must be 7.3")
    if spec.get("status") != "STRATEGY_ONLY":
        errors.append(f"{path}: status must be STRATEGY_ONLY")
    if spec.get("rationale_ref") != DEFAULT_RATIONALE.as_posix():
        errors.append(f"{path}: rationale_ref must point at the Phase 7.1 rationale")
    if spec.get("routes_ref") != DEFAULT_ROUTES.as_posix():
        errors.append(f"{path}: routes_ref must point at the Phase 7.2 routes")
    if spec.get("current_mvp_policy") != "NO_EBPF_NO_KERNEL_HELPER_NO_MEMORY_SNAPSHOT":
        errors.append(f"{path}: current_mvp_policy must keep eBPF, kernel helper, and memory snapshot out of the MVP")

    strategy = spec.get("strategy")
    if not isinstance(strategy, list):
        errors.append(f"{path}: strategy must be a list")
        strategy = []
    if len(strategy) != len(EXPECTED_STEPS):
        errors.append(f"{path}: strategy must contain exactly {len(EXPECTED_STEPS)} steps")
    seen_step_ids: set[str] = set()
    for index, step in enumerate(strategy):
        if not isinstance(step, dict):
            errors.append(f"{path}: strategy step {index} must be an object")
            continue
        if not isinstance(step.get("id"), str):
            errors.append(f"{path}: strategy step {index} must have a string id")
        elif step["id"] in seen_step_ids:
            errors.append(f"{path}: duplicate strategy step id is not allowed: {step['id']}")
        else:
            seen_step_ids.add(step["id"])
        extra_step_keys = set(step) - STEP_KEYS
        missing_step_keys = STEP_KEYS - set(step)
        if extra_step_keys:
            errors.append(f"{path}: strategy step {index} has unexpected keys: {sorted(extra_step_keys)}")
        if missing_step_keys:
            errors.append(f"{path}: strategy step {index} is missing keys: {sorted(missing_step_keys)}")

    for index, expected in enumerate(EXPECTED_STEPS):
        step = strategy[index] if index < len(strategy) and isinstance(strategy[index], dict) else {}
        if step != expected:
            errors.append(f"{path}: strategy step {index + 1} must be {expected!r}")

    deprioritized = spec.get("deprioritized_routes")
    if not isinstance(deprioritized, list):
        errors.append(f"{path}: deprioritized_routes must be a list")
        deprioritized = []
    if deprioritized != EXPECTED_DEPRIORITIZED:
        errors.append(f"{path}: deprioritized_routes must keep kernel_helper_metadata off the MVP path")
    for index, route in enumerate(deprioritized):
        if not isinstance(route, dict):
            errors.append(f"{path}: deprioritized_routes entry {index} must be an object")
            continue
        extra_keys = set(route) - DEPRIORITIZED_KEYS
        missing_keys = DEPRIORITIZED_KEYS - set(route)
        if extra_keys:
            errors.append(f"{path}: deprioritized_routes entry {index} has unexpected keys: {sorted(extra_keys)}")
        if missing_keys:
            errors.append(f"{path}: deprioritized_routes entry {index} is missing keys: {sorted(missing_keys)}")

    if spec.get("non_goals") != EXPECTED_NON_GOALS:
        errors.append(f"{path}: non_goals must block MVP dependencies and Phase 7 route enablement")
    return errors


def check_rationale(path: Path) -> list[str]:
    rationale = load_json(path)
    errors: list[str] = []
    if rationale.get("phase") != "7.1":
        errors.append(f"{path}: expected Phase 7.1 rationale")
    if rationale.get("mvp_dependency") is not False:
        errors.append(f"{path}: rationale must keep eBPF out of the MVP")
    if rationale.get("core_contribution") != "rtl_commit_level_trace":
        errors.append(f"{path}: rationale must keep RTL trace as the core contribution")
    if rationale.get("optional_enrichment") is not True:
        errors.append(f"{path}: rationale must keep enrichment optional")
    helpers = rationale.get("allowed_later_helpers")
    expected_helpers = [
        "selective_memory_snapshot",
        "kernel_helper_metadata",
        "ebpf_metadata_alignment",
    ]
    if helpers != expected_helpers:
        errors.append(f"{path}: allowed_later_helpers must match the Phase 7.2 route set")
    return errors


def check_routes(path: Path) -> list[str]:
    routes = load_json(path)
    errors: list[str] = []
    if routes.get("phase") != "7.2":
        errors.append(f"{path}: expected Phase 7.2 route record")
    if routes.get("status") != "DEFERRED_POST_FPGA":
        errors.append(f"{path}: Phase 7.2 routes must remain DEFERRED_POST_FPGA")
    if routes.get("current_trace_mem_mode") != "TRACE_MEM_MODE_NONE":
        errors.append(f"{path}: route record must keep TRACE_MEM_MODE_NONE")
    statuses = route_statuses(routes)
    expected_routes = {
        "selective_memory_snapshot",
        "kernel_helper_metadata",
        "ebpf_metadata_alignment",
    }
    if set(statuses) != expected_routes:
        errors.append(f"{path}: route ids must stay aligned with Phase 7.3 strategy")
    for route_id in expected_routes:
        if statuses.get(route_id) != "DEFERRED_POST_FPGA":
            errors.append(f"{path}: {route_id} must remain DEFERRED_POST_FPGA")
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
            errors.append(f"{path}: must not claim Phase 7.3 implementation, route enablement, or eBPF MVP/core status")
    return errors


def check_trace_format(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    if "`TRACE_MEM_MODE_DEFAULT` is `TRACE_MEM_MODE_NONE`" not in text:
        errors.append(f"{path}: trace memory default must remain TRACE_MEM_MODE_NONE")
    if "does not define load/store trace records or memory data payload fields" not in text:
        errors.append(f"{path}: trace format must not define current load/store payloads")
    for pattern in FORBIDDEN_TRACE_FORMAT_PATTERNS:
        if pattern.search(text):
            errors.append(f"{path}: trace format must not claim current memory trace enablement or payload availability")
    return errors


def check_uv_doc(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    for token, label in (
        ("tools/check_semantic_enrichment_strategy.py", "Phase 7.3 checker command"),
        ("docs/semantic_enrichment_strategy.md", "Phase 7.3 doc reference"),
        ("experiments/linux_behavior/semantic_enrichment_strategy.json", "Phase 7.3 spec reference"),
    ):
        if token not in text:
            errors.append(f"{path}: missing {label}")
    return errors


def run_checks(
    root: Path,
    spec: Path,
    doc: Path,
    rationale: Path,
    routes: Path,
    trace_format: Path,
    uv_doc: Path,
) -> list[str]:
    spec_path = resolve(root, spec)
    doc_path = resolve(root, doc)
    rationale_path = resolve(root, rationale)
    routes_path = resolve(root, routes)
    trace_format_path = resolve(root, trace_format)
    uv_path = resolve(root, uv_doc)
    errors: list[str] = []
    for path, label in (
        (spec_path, "spec"),
        (doc_path, "doc"),
        (rationale_path, "rationale"),
        (routes_path, "routes"),
        (trace_format_path, "trace format"),
        (uv_path, "uv workflow"),
    ):
        if not path.exists():
            errors.append(f"missing {label}: {path}")
    if errors:
        return errors
    errors.extend(check_spec(spec_path))
    errors.extend(check_doc(doc_path))
    errors.extend(check_rationale(rationale_path))
    errors.extend(check_routes(routes_path))
    errors.extend(check_trace_format(trace_format_path))
    errors.extend(check_uv_doc(uv_path))
    return errors


def write_fixture(root: Path) -> None:
    (root / "experiments/linux_behavior").mkdir(parents=True)
    (root / "docs").mkdir(parents=True)
    (root / DEFAULT_SPEC).write_text(
        json.dumps(
            {
                "phase": "7.3",
                "status": "STRATEGY_ONLY",
                "rationale_ref": DEFAULT_RATIONALE.as_posix(),
                "routes_ref": DEFAULT_ROUTES.as_posix(),
                "current_mvp_policy": "NO_EBPF_NO_KERNEL_HELPER_NO_MEMORY_SNAPSHOT",
                "strategy": EXPECTED_STEPS,
                "deprioritized_routes": EXPECTED_DEPRIORITIZED,
                "non_goals": EXPECTED_NON_GOALS,
            }
        ),
        encoding="utf-8",
    )
    (root / DEFAULT_DOC).write_text(
        """# Semantic Enrichment Strategy

Phase 7.3 records the recommended semantic enrichment strategy.
strategy gate record, not implementation evidence and not experiment evidence.
experiments/linux_behavior/semantic_enrichment_strategy.json
MVP: no eBPF
no kernel helper and no memory snapshot dependency
After FPGA trace works: evaluate selective memory snapshot as a gated option.
The default trace memory mode remains `TRACE_MEM_MODE_NONE`
no default memory trace, JSONL payload change, or core backpressure is allowed
After Linux experiments: optionally add eBPF metadata alignment
eBPF is not an MVP dependency
is not the core contribution
must not replace RTL-level committed behavior trace
kernel_helper_metadata
not on the recommended MVP path
does not enable any Phase 7 route
does not change the JSONL event set
does not add load/store payloads
""",
        encoding="utf-8",
    )
    (root / DEFAULT_RATIONALE).write_text(
        json.dumps(
            {
                "phase": "7.1",
                "status": "DEFERRED_POST_FPGA",
                "mvp_dependency": False,
                "core_contribution": "rtl_commit_level_trace",
                "optional_enrichment": True,
                "hardware_trace_strengths": [],
                "semantic_gaps": [],
                "allowed_later_helpers": [
                    "selective_memory_snapshot",
                    "kernel_helper_metadata",
                    "ebpf_metadata_alignment",
                ],
                "blocked_claims": [],
            }
        ),
        encoding="utf-8",
    )
    (root / DEFAULT_ROUTES).write_text(
        json.dumps(
            {
                "phase": "7.2",
                "status": "DEFERRED_POST_FPGA",
                "policy_ref": DEFAULT_RATIONALE.as_posix(),
                "current_trace_mem_mode": "TRACE_MEM_MODE_NONE",
                "routes": [
                    {"id": "selective_memory_snapshot", "status": "DEFERRED_POST_FPGA"},
                    {"id": "kernel_helper_metadata", "status": "DEFERRED_POST_FPGA"},
                    {"id": "ebpf_metadata_alignment", "status": "DEFERRED_POST_FPGA"},
                ],
            }
        ),
        encoding="utf-8",
    )
    (root / DEFAULT_TRACE_FORMAT).write_text(
        "`TRACE_MEM_MODE_DEFAULT` is `TRACE_MEM_MODE_NONE`.\n"
        "does not define load/store trace records or memory data payload fields\n",
        encoding="utf-8",
    )
    (root / DEFAULT_UV_DOC).write_text(
        "uv run python tools/check_semantic_enrichment_strategy.py\n"
        "docs/semantic_enrichment_strategy.md\n"
        "experiments/linux_behavior/semantic_enrichment_strategy.json\n",
        encoding="utf-8",
    )


def expect_error(root: Path, expected: str) -> bool:
    return any(
        expected in error
        for error in run_checks(
            root,
            DEFAULT_SPEC,
            DEFAULT_DOC,
            DEFAULT_RATIONALE,
            DEFAULT_ROUTES,
            DEFAULT_TRACE_FORMAT,
            DEFAULT_UV_DOC,
        )
    )


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        errors = run_checks(root, DEFAULT_SPEC, DEFAULT_DOC, DEFAULT_RATIONALE, DEFAULT_ROUTES, DEFAULT_TRACE_FORMAT, DEFAULT_UV_DOC)
        if errors:
            for error in errors:
                print(f"[FAIL] self-test false positive: {error}", file=sys.stderr)
            return 1

    for field, value, expected in (
        ("status", "PASS", "status must be STRATEGY_ONLY"),
        ("current_mvp_policy", "EBPF_ALLOWED_IN_MVP", "current_mvp_policy"),
        ("non_goals", EXPECTED_NON_GOALS[:-1], "non_goals"),
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root)
            spec = load_json(root / DEFAULT_SPEC)
            spec[field] = value
            (root / DEFAULT_SPEC).write_text(json.dumps(spec), encoding="utf-8")
            if not expect_error(root, expected):
                print(f"[FAIL] self-test missed spec regression: {field}", file=sys.stderr)
                return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        spec = load_json(root / DEFAULT_SPEC)
        spec["strategy"] = spec["strategy"][:2]
        (root / DEFAULT_SPEC).write_text(json.dumps(spec), encoding="utf-8")
        if not expect_error(root, "strategy must contain exactly"):
            print("[FAIL] self-test missed missing strategy step", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        spec = load_json(root / DEFAULT_SPEC)
        spec["strategy"][0], spec["strategy"][1] = spec["strategy"][1], spec["strategy"][0]
        (root / DEFAULT_SPEC).write_text(json.dumps(spec), encoding="utf-8")
        if not expect_error(root, "strategy step 1"):
            print("[FAIL] self-test missed strategy order regression", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        spec = load_json(root / DEFAULT_SPEC)
        spec["strategy"].append(dict(EXPECTED_STEPS[0]))
        (root / DEFAULT_SPEC).write_text(json.dumps(spec), encoding="utf-8")
        if not expect_error(root, "duplicate strategy step id"):
            print("[FAIL] self-test missed duplicate strategy step id", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        spec = load_json(root / DEFAULT_SPEC)
        spec["strategy"][1]["route"] = "kernel_helper_metadata"
        (root / DEFAULT_SPEC).write_text(json.dumps(spec), encoding="utf-8")
        if not expect_error(root, "strategy step 2"):
            print("[FAIL] self-test missed route-order regression", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        spec = load_json(root / DEFAULT_SPEC)
        spec["deprioritized_routes"] = []
        (root / DEFAULT_SPEC).write_text(json.dumps(spec), encoding="utf-8")
        if not expect_error(root, "deprioritized_routes"):
            print("[FAIL] self-test missed kernel helper prioritization regression", file=sys.stderr)
            return 1

    for phrase in (
        "PASS",
        "Phase 7.3 strategy is complete.",
        "Semantic enrichment strategy has been validated.",
        "Semantic enrichment is enabled.",
        "Semantic enrichment has been validated.",
        "Phase 7 routes are enabled.",
        "Semantic enrichment routes have been validated.",
        "eBPF is required for the MVP.",
        "eBPF is part of the MVP.",
        "The MVP depends on eBPF metadata alignment.",
        "eBPF becomes the primary contribution.",
        "eBPF metadata alignment is implemented.",
        "eBPF replaces RTL trace.",
        "kernel helper is required for the MVP.",
        "kernel helper metadata is included in the MVP.",
        "The MVP requires memory snapshot.",
        "selective memory snapshot is enabled.",
        "memory snapshot is implemented.",
        "TRACE_MEM_MODE_RANGE is enabled.",
        "memory trace payloads are available.",
        "load/store trace records are available.",
        "software-only tracing replaces RTL trace.",
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root)
            doc = root / DEFAULT_DOC
            doc.write_text(doc.read_text(encoding="utf-8") + f"\n{phrase}\n", encoding="utf-8")
            if not expect_error(root, "must not claim Phase 7.3"):
                print(f"[FAIL] self-test missed unsafe doc phrase: {phrase}", file=sys.stderr)
                return 1

    for field, value, expected in (
        ("mvp_dependency", True, "out of the MVP"),
        ("core_contribution", "ebpf_metadata_alignment", "core contribution"),
        ("optional_enrichment", False, "optional"),
        ("allowed_later_helpers", ["ebpf_metadata_alignment"], "allowed_later_helpers"),
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root)
            rationale = load_json(root / DEFAULT_RATIONALE)
            rationale[field] = value
            (root / DEFAULT_RATIONALE).write_text(json.dumps(rationale), encoding="utf-8")
            if not expect_error(root, expected):
                print(f"[FAIL] self-test missed rationale regression: {field}", file=sys.stderr)
                return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        routes = load_json(root / DEFAULT_ROUTES)
        routes["current_trace_mem_mode"] = "TRACE_MEM_MODE_RANGE"
        (root / DEFAULT_ROUTES).write_text(json.dumps(routes), encoding="utf-8")
        if not expect_error(root, "TRACE_MEM_MODE_NONE"):
            print("[FAIL] self-test missed route memory mode regression", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        routes = load_json(root / DEFAULT_ROUTES)
        routes["status"] = "ENABLED"
        (root / DEFAULT_ROUTES).write_text(json.dumps(routes), encoding="utf-8")
        if not expect_error(root, "routes must remain DEFERRED_POST_FPGA"):
            print("[FAIL] self-test missed route top-level status regression", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        routes = load_json(root / DEFAULT_ROUTES)
        routes["routes"][0]["status"] = "ENABLED"
        (root / DEFAULT_ROUTES).write_text(json.dumps(routes), encoding="utf-8")
        if not expect_error(root, "DEFERRED_POST_FPGA"):
            print("[FAIL] self-test missed enabled route regression", file=sys.stderr)
            return 1

    for phrase in (
        "TRACE_MEM_MODE_RANGE is enabled.",
        "memory trace payloads are available.",
        "load/store trace records are available.",
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root)
            trace_format = root / DEFAULT_TRACE_FORMAT
            trace_format.write_text(trace_format.read_text(encoding="utf-8") + f"\n{phrase}\n", encoding="utf-8")
            if not expect_error(root, "must not claim current memory trace"):
                print(f"[FAIL] self-test missed trace_format unsafe phrase: {phrase}", file=sys.stderr)
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
        ("tools/check_semantic_enrichment_strategy.py", "checker command"),
        ("docs/semantic_enrichment_strategy.md", "doc reference"),
        ("experiments/linux_behavior/semantic_enrichment_strategy.json", "spec reference"),
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root)
            uv_doc = root / DEFAULT_UV_DOC
            uv_doc.write_text(uv_doc.read_text(encoding="utf-8").replace(token, ""), encoding="utf-8")
            if not expect_error(root, expected):
                print(f"[FAIL] self-test missed missing uv reference: {token}", file=sys.stderr)
                return 1

    print("[PASS] semantic enrichment strategy self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Phase 7.3 semantic enrichment strategy.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--spec", type=Path, default=DEFAULT_SPEC)
    parser.add_argument("--doc", type=Path, default=DEFAULT_DOC)
    parser.add_argument("--rationale", type=Path, default=DEFAULT_RATIONALE)
    parser.add_argument("--routes", type=Path, default=DEFAULT_ROUTES)
    parser.add_argument("--trace-format", type=Path, default=DEFAULT_TRACE_FORMAT)
    parser.add_argument("--uv-doc", type=Path, default=DEFAULT_UV_DOC)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    try:
        errors = run_checks(
            args.root.resolve(),
            args.spec,
            args.doc,
            args.rationale,
            args.routes,
            args.trace_format,
            args.uv_doc,
        )
    except Exception as exc:
        print(f"check_semantic_enrichment_strategy: error: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    print("[PASS] Phase 7.3 semantic enrichment strategy is specified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
