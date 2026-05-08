from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any


DEFAULT_SPEC = Path("experiments/linux_behavior/semantic_enrichment_rationale.json")
DEFAULT_DOC = Path("docs/semantic_enrichment_rationale.md")
DEFAULT_RISK_LOG = Path("docs/risk_log.md")
DEFAULT_UV_DOC = Path("docs/uv_workflow.md")

SPEC_KEYS = {
    "phase",
    "status",
    "mvp_dependency",
    "core_contribution",
    "optional_enrichment",
    "hardware_trace_strengths",
    "semantic_gaps",
    "allowed_later_helpers",
    "blocked_claims",
}
EXPECTED_STRENGTHS = [
    "true_executed_path",
    "syscall_trap_context_visibility",
    "no_guest_os_instrumentation_dependency",
    "software_evasion_resistance",
]
EXPECTED_GAPS = [
    "fd_to_path_mapping",
    "pointer_string_or_buffer_content",
    "process_name_and_executable_path",
    "kernel_object_semantics",
]
EXPECTED_HELPERS = [
    "selective_memory_snapshot",
    "kernel_helper_metadata",
    "ebpf_metadata_alignment",
]
EXPECTED_BLOCKED = [
    "ebpf_required_for_mvp",
    "ebpf_core_contribution",
    "software_only_tracing_replaces_rtl_trace",
]
REQUIRED_DOC_TEXT = (
    "Phase 7.1 records why later semantic enrichment may be useful.",
    "deferred rationale, not an implementation claim and not experiment evidence.",
    "experiments/linux_behavior/semantic_enrichment_rationale.json",
    "The RTL trace path is the project core.",
    "fd-to-path mapping",
    "pointer string or buffer content",
    "process name and executable path",
    "kernel object semantics",
    "eBPF is not an MVP dependency.",
    "eBPF is not the core contribution.",
    "optional semantic enrichment",
    "after the FPGA trace path works",
)
FORBIDDEN_DOC_PATTERNS = (
    re.compile(r"\bPASS\b", re.IGNORECASE),
    re.compile(r"\beBPF\s+(?:is\s+)?(?:required|mandatory|needed)\s+for\s+(?:the\s+)?MVP\b", re.IGNORECASE),
    re.compile(r"\beBPF\s+(?:is\s+)?(?:an?\s+)?MVP\s+dependency\b", re.IGNORECASE),
    re.compile(r"\bthe\s+MVP\s+depends\s+on\s+eBPF\b", re.IGNORECASE),
    re.compile(r"\bthe\s+MVP\s+requires\s+eBPF\b", re.IGNORECASE),
    re.compile(r"\beBPF\s+must\s+be\s+enabled\s+for\s+(?:the\s+)?MVP\b", re.IGNORECASE),
    re.compile(r"\beBPF\s+(?:is|becomes)\s+(?:an?\s+|the\s+)?(?:core|main|primary)\s+contribution\b", re.IGNORECASE),
    re.compile(r"\bsoftware[- ]only\s+tracing\s+(?:replaces|supersedes)\s+(?:the\s+)?RTL\s+trace\b", re.IGNORECASE),
    re.compile(
        r"\b(?:phase\s*7(?:\.1)?\s+)?(?:semantic\s+enrichment|enrichment|eBPF|kernel\s+helper)"
        r"(?:\s+experiments?|\s+validation|\s+implementation)?\s+"
        r"(?:is|are|has|have)?\s*(?:been\s+)?(?:complete|completed|validated|passed)\b",
        re.IGNORECASE,
    ),
)


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def normalized_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def resolve(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path


def check_spec(path: Path) -> list[str]:
    spec = load_json(path)
    errors: list[str] = []
    extra_keys = set(spec) - SPEC_KEYS
    missing_keys = SPEC_KEYS - set(spec)
    if extra_keys:
        errors.append(f"{path}: unexpected spec keys are not allowed: {sorted(extra_keys)}")
    if missing_keys:
        errors.append(f"{path}: missing required spec keys: {sorted(missing_keys)}")
    if spec.get("phase") != "7.1":
        errors.append(f"{path}: phase must be 7.1")
    if spec.get("status") != "DEFERRED_POST_FPGA":
        errors.append(f"{path}: status must be DEFERRED_POST_FPGA")
    if spec.get("mvp_dependency") is not False:
        errors.append(f"{path}: mvp_dependency must be false")
    if spec.get("core_contribution") != "rtl_commit_level_trace":
        errors.append(f"{path}: core_contribution must remain rtl_commit_level_trace")
    if spec.get("optional_enrichment") is not True:
        errors.append(f"{path}: optional_enrichment must be true")
    if spec.get("hardware_trace_strengths") != EXPECTED_STRENGTHS:
        errors.append(f"{path}: hardware_trace_strengths must be {EXPECTED_STRENGTHS}")
    if spec.get("semantic_gaps") != EXPECTED_GAPS:
        errors.append(f"{path}: semantic_gaps must be {EXPECTED_GAPS}")
    if spec.get("allowed_later_helpers") != EXPECTED_HELPERS:
        errors.append(f"{path}: allowed_later_helpers must be {EXPECTED_HELPERS}")
    if spec.get("blocked_claims") != EXPECTED_BLOCKED:
        errors.append(f"{path}: blocked_claims must be {EXPECTED_BLOCKED}")
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
            errors.append(f"{path}: must not promote eBPF to MVP/core or claim enrichment completion")
    return errors


def check_cross_refs(uv_doc: Path, risk_log: Path) -> list[str]:
    errors: list[str] = []
    uv_text = uv_doc.read_text(encoding="utf-8")
    for token, label in (
        ("tools/check_semantic_enrichment_rationale.py", "Phase 7.1 checker command"),
        ("docs/semantic_enrichment_rationale.md", "Phase 7.1 doc reference"),
        ("experiments/linux_behavior/semantic_enrichment_rationale.json", "Phase 7.1 spec reference"),
    ):
        if token not in uv_text:
            errors.append(f"{uv_doc}: missing {label}")
    risk_text = risk_log.read_text(encoding="utf-8")
    if "eBPF contribution dilution" not in risk_text:
        errors.append(f"{risk_log}: missing eBPF contribution dilution risk row")
    if "optional semantic enrichment" not in risk_text:
        errors.append(f"{risk_log}: missing optional semantic enrichment mitigation")
    return errors


def run_checks(root: Path, spec: Path, doc: Path, risk_log: Path, uv_doc: Path) -> list[str]:
    spec_path = resolve(root, spec)
    doc_path = resolve(root, doc)
    risk_path = resolve(root, risk_log)
    uv_path = resolve(root, uv_doc)
    errors: list[str] = []
    for path, label in ((spec_path, "spec"), (doc_path, "doc"), (risk_path, "risk log"), (uv_path, "uv workflow")):
        if not path.exists():
            errors.append(f"missing {label}: {path}")
    if errors:
        return errors
    errors.extend(check_spec(spec_path))
    errors.extend(check_doc(doc_path))
    errors.extend(check_cross_refs(uv_path, risk_path))
    return errors


def write_fixture(root: Path) -> None:
    (root / "experiments/linux_behavior").mkdir(parents=True)
    (root / "docs").mkdir(parents=True)
    (root / DEFAULT_SPEC).write_text(
        json.dumps(
            {
                "phase": "7.1",
                "status": "DEFERRED_POST_FPGA",
                "mvp_dependency": False,
                "core_contribution": "rtl_commit_level_trace",
                "optional_enrichment": True,
                "hardware_trace_strengths": EXPECTED_STRENGTHS,
                "semantic_gaps": EXPECTED_GAPS,
                "allowed_later_helpers": EXPECTED_HELPERS,
                "blocked_claims": EXPECTED_BLOCKED,
            }
        ),
        encoding="utf-8",
    )
    (root / DEFAULT_DOC).write_text(
        """# Semantic Enrichment Rationale

Phase 7.1 records why later semantic enrichment may be useful.
deferred rationale, not an implementation claim and not experiment evidence.
experiments/linux_behavior/semantic_enrichment_rationale.json
The RTL trace path is the project core.
fd-to-path mapping
pointer string or buffer content
process name and executable path
kernel object semantics
eBPF is not an MVP dependency.
eBPF is not the core contribution.
optional semantic enrichment
after the FPGA trace path works
""",
        encoding="utf-8",
    )
    (root / DEFAULT_UV_DOC).write_text(
        "uv run python tools/check_semantic_enrichment_rationale.py\n"
        "docs/semantic_enrichment_rationale.md\n"
        "experiments/linux_behavior/semantic_enrichment_rationale.json\n",
        encoding="utf-8",
    )
    (root / DEFAULT_RISK_LOG).write_text(
        "eBPF contribution dilution | optional semantic enrichment\n",
        encoding="utf-8",
    )


def expect_error(root: Path, expected: str) -> bool:
    return any(expected in error for error in run_checks(root, DEFAULT_SPEC, DEFAULT_DOC, DEFAULT_RISK_LOG, DEFAULT_UV_DOC))


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        errors = run_checks(root, DEFAULT_SPEC, DEFAULT_DOC, DEFAULT_RISK_LOG, DEFAULT_UV_DOC)
        if errors:
            for error in errors:
                print(f"[FAIL] self-test false positive: {error}", file=sys.stderr)
            return 1

    for field, value, expected in (
        ("mvp_dependency", True, "mvp_dependency"),
        ("core_contribution", "ebpf", "core_contribution"),
        ("optional_enrichment", False, "optional_enrichment"),
        ("semantic_gaps", EXPECTED_GAPS[:-1], "semantic_gaps"),
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
        spec["semantic_enrichment_complete"] = True
        (root / DEFAULT_SPEC).write_text(json.dumps(spec), encoding="utf-8")
        if not expect_error(root, "unexpected spec keys"):
            print("[FAIL] self-test missed extra spec key", file=sys.stderr)
            return 1

    for phrase in (
        "PASS",
        "eBPF is required for the MVP",
        "eBPF is an MVP dependency.",
        "The MVP depends on eBPF metadata alignment.",
        "The MVP requires eBPF metadata alignment.",
        "eBPF must be enabled for the MVP.",
        "eBPF is the core contribution",
        "eBPF is a core contribution.",
        "eBPF is the main contribution.",
        "eBPF becomes the primary contribution.",
        "eBPF becomes the core contribution.",
        "software-only tracing replaces RTL trace",
        "semantic enrichment implementation is complete",
        "Semantic enrichment experiments have passed.",
        "Semantic enrichment has been validated.",
        "Phase 7.1 enrichment validation is complete.",
        "Semantic enrichment validation completed.",
        "Phase 7.1 enrichment validation has completed.",
        "Semantic enrichment experiments completed.",
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root)
            doc = root / DEFAULT_DOC
            doc.write_text(doc.read_text(encoding="utf-8") + f"\n{phrase}\n", encoding="utf-8")
            if not expect_error(root, "must not promote eBPF"):
                print(f"[FAIL] self-test missed unsafe doc phrase: {phrase}", file=sys.stderr)
                return 1

    for token, expected in (
        ("uv run python tools/check_semantic_enrichment_rationale.py", "checker command"),
        ("docs/semantic_enrichment_rationale.md", "doc reference"),
        ("experiments/linux_behavior/semantic_enrichment_rationale.json", "spec reference"),
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root)
            uv_doc = root / DEFAULT_UV_DOC
            uv_doc.write_text(uv_doc.read_text(encoding="utf-8").replace(token, ""), encoding="utf-8")
            if not expect_error(root, expected):
                print(f"[FAIL] self-test missed missing uv reference: {token}", file=sys.stderr)
                return 1

    for token, expected in (
        ("eBPF contribution dilution", "eBPF contribution dilution risk row"),
        ("optional semantic enrichment", "optional semantic enrichment mitigation"),
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root)
            risk_log = root / DEFAULT_RISK_LOG
            risk_log.write_text(risk_log.read_text(encoding="utf-8").replace(token, ""), encoding="utf-8")
            if not expect_error(root, expected):
                print(f"[FAIL] self-test missed missing risk reference: {token}", file=sys.stderr)
                return 1

    print("[PASS] semantic enrichment rationale self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Phase 7.1 semantic enrichment rationale.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--spec", type=Path, default=DEFAULT_SPEC)
    parser.add_argument("--doc", type=Path, default=DEFAULT_DOC)
    parser.add_argument("--risk-log", type=Path, default=DEFAULT_RISK_LOG)
    parser.add_argument("--uv-doc", type=Path, default=DEFAULT_UV_DOC)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    try:
        errors = run_checks(args.root.resolve(), args.spec, args.doc, args.risk_log, args.uv_doc)
    except Exception as exc:
        print(f"check_semantic_enrichment_rationale: error: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    print("[PASS] Phase 7.1 semantic enrichment rationale is specified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
