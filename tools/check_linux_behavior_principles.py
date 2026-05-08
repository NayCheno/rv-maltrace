from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any


DEFAULT_POLICY = Path("experiments/linux_behavior/policy.json")
DEFAULT_DOC = Path("docs/linux_behavior_experiment_principles.md")
DEFAULT_UV_DOC = Path("docs/uv_workflow.md")
DEFAULT_RISK_LOG = Path("docs/risk_log.md")

EXPECTED_ALLOWED = ["benign", "malware_like_synthetic"]
EXPECTED_BLOCKED = ["real_malware", "unknown_provenance"]
EXPECTED_OUTPUTS = [
    "trace.jsonl",
    "semantic_events.json",
    "behavior_graph.json",
    "recovery_report.md",
]
EXPECTED_POLICY_KEYS = {
    "phase",
    "status",
    "real_malware_policy",
    "allowed_sample_classes",
    "blocked_sample_classes",
    "primary_validation_goal",
    "requires_prior_hardware_trace_gate",
    "network_policy",
    "evidence_root",
    "required_outputs",
}
REQUIRED_DOC_TEXT = (
    "These rules are a plan, not board or Linux experiment evidence.",
    "experiments/linux_behavior/policy.json",
    "results/linux_behavior/<run-id>/",
    "Do not run real malware in early experiments.",
    "Reject unknown-provenance binaries and payloads.",
    "Use only benign programs and malware-like synthetic programs.",
    "Keep network behavior disabled by default",
    "trace semantic recovery",
    "`trace.jsonl`",
    "`semantic_events.json`",
    "`behavior_graph.json`",
    "`recovery_report.md`",
    "must stay split into `benign` and `malware_like_synthetic`",
)
FORBIDDEN_DOC_PATTERNS = (
    re.compile(r"\bPASS\b", re.IGNORECASE),
    re.compile(
        r"\breal\s+malware\s+(?:is\s+)?(?:allowed|enabled|included|ready|permitted|approved)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\breal\s+malware\s+(?:may|can|should|will|is\s+permitted\s+to|is\s+allowed\s+to)\s+"
        r"(?:be\s+)?(?:run|used|included|executed)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bearly\s+experiments?\s+(?:may|can|should|will|are\s+permitted\s+to|are\s+allowed\s+to)\s+"
        r"(?:run|use|include|execute)\s+real\s+malware\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bunknown[- ]provenance(?:\s+(?:binaries|payloads|samples))?\s+(?:are\s+)?"
        r"(?:allowed|enabled|included|permitted|approved)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bmalware\s+detection\s+quality\s+is\s+validated\b", re.IGNORECASE),
    re.compile(
        r"\b(?:phase\s*6(?:\.1)?\s+)?(?:hardware|experiment|experiments|linux\s+behavior\s+experiments|linux\s+experiment|board\s+trace)\s+"
        r"(?:validation\s+)?(?:is|are|has|have)?\s*(?:complete|validated|passed)\b",
        re.IGNORECASE,
    ),
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


def check_policy(path: Path) -> list[str]:
    policy = load_json(path)
    errors: list[str] = []
    extra_keys = set(policy) - EXPECTED_POLICY_KEYS
    missing_keys = EXPECTED_POLICY_KEYS - set(policy)
    if extra_keys:
        errors.append(f"{path}: unexpected policy keys are not allowed: {sorted(extra_keys)}")
    if missing_keys:
        errors.append(f"{path}: missing required policy keys: {sorted(missing_keys)}")
    if policy.get("phase") != "6.1":
        errors.append(f"{path}: phase must be 6.1")
    if policy.get("status") != "TODO(EXPERIMENT)":
        errors.append(f"{path}: status must remain TODO(EXPERIMENT)")
    if policy.get("real_malware_policy") != "FORBIDDEN_EARLY":
        errors.append(f"{path}: real_malware_policy must be FORBIDDEN_EARLY")
    if policy.get("allowed_sample_classes") != EXPECTED_ALLOWED:
        errors.append(f"{path}: allowed_sample_classes must be {EXPECTED_ALLOWED}")
    if policy.get("blocked_sample_classes") != EXPECTED_BLOCKED:
        errors.append(f"{path}: blocked_sample_classes must be {EXPECTED_BLOCKED}")
    if policy.get("primary_validation_goal") != "trace_semantic_recovery":
        errors.append(f"{path}: primary_validation_goal must be trace_semantic_recovery")
    if policy.get("requires_prior_hardware_trace_gate") is not True:
        errors.append(f"{path}: requires_prior_hardware_trace_gate must be true")
    if policy.get("network_policy") != "disabled_by_default":
        errors.append(f"{path}: network_policy must be disabled_by_default")
    if policy.get("evidence_root") != "results/linux_behavior/<run-id>":
        errors.append(f"{path}: evidence_root must use results/linux_behavior/<run-id>")
    if policy.get("required_outputs") != EXPECTED_OUTPUTS:
        errors.append(f"{path}: required_outputs must be {EXPECTED_OUTPUTS}")
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
            errors.append(f"{path}: must not claim Phase 6.1 pass or allow early real malware")
    for target in ("syscall sequence", "control-flow segment", "trap/context transition", "privilege boundary", "basic behavior graph"):
        if target not in text:
            errors.append(f"{path}: missing recovery target {target}")
    return errors


def check_cross_refs(uv_doc: Path, risk_log: Path) -> list[str]:
    errors: list[str] = []
    uv_text = uv_doc.read_text(encoding="utf-8")
    if "tools/check_linux_behavior_principles.py" not in uv_text:
        errors.append(f"{uv_doc}: missing Phase 6.1 checker command")
    if "docs/linux_behavior_experiment_principles.md" not in uv_text:
        errors.append(f"{uv_doc}: missing Phase 6.1 principles document reference")
    if "experiments/linux_behavior/policy.json" not in uv_text:
        errors.append(f"{uv_doc}: missing Phase 6.1 policy reference")

    risk_text = risk_log.read_text(encoding="utf-8")
    if "Running real malware too early" not in risk_text:
        errors.append(f"{risk_log}: missing Phase 6.1 real-malware risk row")
    if "FORBIDDEN_EARLY" not in risk_text:
        errors.append(f"{risk_log}: missing policy keyword FORBIDDEN_EARLY")
    return errors


def run_checks(root: Path, policy: Path, doc: Path, uv_doc: Path, risk_log: Path) -> list[str]:
    policy_path = resolve(root, policy)
    doc_path = resolve(root, doc)
    uv_path = resolve(root, uv_doc)
    risk_path = resolve(root, risk_log)
    errors: list[str] = []
    for path, label in (
        (policy_path, "policy"),
        (doc_path, "doc"),
        (uv_path, "uv workflow"),
        (risk_path, "risk log"),
    ):
        if not path.exists():
            errors.append(f"missing {label}: {path}")
    if errors:
        return errors
    errors.extend(check_policy(policy_path))
    errors.extend(check_doc(doc_path))
    errors.extend(check_cross_refs(uv_path, risk_path))
    return errors


def write_fixture(root: Path) -> None:
    (root / "experiments/linux_behavior").mkdir(parents=True)
    (root / "docs").mkdir(parents=True)
    (root / DEFAULT_POLICY).write_text(
        json.dumps(
            {
                "phase": "6.1",
                "status": "TODO(EXPERIMENT)",
                "real_malware_policy": "FORBIDDEN_EARLY",
                "allowed_sample_classes": EXPECTED_ALLOWED,
                "blocked_sample_classes": EXPECTED_BLOCKED,
                "primary_validation_goal": "trace_semantic_recovery",
                "requires_prior_hardware_trace_gate": True,
                "network_policy": "disabled_by_default",
                "evidence_root": "results/linux_behavior/<run-id>",
                "required_outputs": EXPECTED_OUTPUTS,
            }
        ),
        encoding="utf-8",
    )
    (root / DEFAULT_DOC).write_text(
        """# Linux Behavior Experiment Principles

These rules are a plan, not board or Linux experiment evidence.
experiments/linux_behavior/policy.json
results/linux_behavior/<run-id>/
Do not run real malware in early experiments.
Reject unknown-provenance binaries and payloads.
Use only benign programs and malware-like synthetic programs.
Keep network behavior disabled by default
TODO(EXPERIMENT)
trace semantic recovery
syscall sequence
control-flow segment
trap/context transition
privilege boundary
basic behavior graph
`trace.jsonl`
`semantic_events.json`
`behavior_graph.json`
`recovery_report.md`
must stay split into `benign` and `malware_like_synthetic`
""",
        encoding="utf-8",
    )
    (root / DEFAULT_UV_DOC).write_text(
        "uv run python tools/check_linux_behavior_principles.py\n"
        "docs/linux_behavior_experiment_principles.md\n"
        "experiments/linux_behavior/policy.json\n",
        encoding="utf-8",
    )
    (root / DEFAULT_RISK_LOG).write_text(
        "Running real malware too early | FORBIDDEN_EARLY\n",
        encoding="utf-8",
    )


def expect_error(root: Path, expected: str) -> bool:
    return any(expected in error for error in run_checks(root, DEFAULT_POLICY, DEFAULT_DOC, DEFAULT_UV_DOC, DEFAULT_RISK_LOG))


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        errors = run_checks(root, DEFAULT_POLICY, DEFAULT_DOC, DEFAULT_UV_DOC, DEFAULT_RISK_LOG)
        if errors:
            for error in errors:
                print(f"[FAIL] self-test false positive: {error}", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        policy = load_json(root / DEFAULT_POLICY)
        policy["real_malware_policy"] = "ALLOWED"
        (root / DEFAULT_POLICY).write_text(json.dumps(policy), encoding="utf-8")
        if not expect_error(root, "real_malware_policy"):
            print("[FAIL] self-test missed real malware policy regression", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        policy = load_json(root / DEFAULT_POLICY)
        policy["allowed_sample_classes"].append("real_malware")
        (root / DEFAULT_POLICY).write_text(json.dumps(policy), encoding="utf-8")
        if not expect_error(root, "allowed_sample_classes"):
            print("[FAIL] self-test missed allowed sample class regression", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        policy = load_json(root / DEFAULT_POLICY)
        policy["blocked_sample_classes"] = ["real_malware"]
        (root / DEFAULT_POLICY).write_text(json.dumps(policy), encoding="utf-8")
        if not expect_error(root, "blocked_sample_classes"):
            print("[FAIL] self-test missed unknown-provenance block regression", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        policy = load_json(root / DEFAULT_POLICY)
        policy["primary_validation_goal"] = "malware_detection_quality"
        (root / DEFAULT_POLICY).write_text(json.dumps(policy), encoding="utf-8")
        if not expect_error(root, "primary_validation_goal"):
            print("[FAIL] self-test missed validation goal regression", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        policy = load_json(root / DEFAULT_POLICY)
        policy["requires_prior_hardware_trace_gate"] = False
        (root / DEFAULT_POLICY).write_text(json.dumps(policy), encoding="utf-8")
        if not expect_error(root, "requires_prior_hardware_trace_gate"):
            print("[FAIL] self-test missed hardware gate regression", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        policy = load_json(root / DEFAULT_POLICY)
        policy["network_policy"] = "enabled"
        (root / DEFAULT_POLICY).write_text(json.dumps(policy), encoding="utf-8")
        if not expect_error(root, "network_policy"):
            print("[FAIL] self-test missed network policy regression", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        policy = load_json(root / DEFAULT_POLICY)
        policy["hardware_validated"] = True
        (root / DEFAULT_POLICY).write_text(json.dumps(policy), encoding="utf-8")
        if not expect_error(root, "unexpected policy keys"):
            print("[FAIL] self-test missed extra policy overclaim key", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        doc = root / DEFAULT_DOC
        doc.write_text(doc.read_text(encoding="utf-8") + "\nreal malware allowed\n", encoding="utf-8")
        if not expect_error(root, "must not claim Phase 6.1"):
            print("[FAIL] self-test missed doc malware allowance", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        doc = root / DEFAULT_DOC
        doc.write_text(doc.read_text(encoding="utf-8") + "\nReal malware is permitted for early experiments.\n", encoding="utf-8")
        if not expect_error(root, "must not claim Phase 6.1"):
            print("[FAIL] self-test missed doc malware permission", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        doc = root / DEFAULT_DOC
        doc.write_text(doc.read_text(encoding="utf-8") + "\nReal malware may be run in early experiments.\n", encoding="utf-8")
        if not expect_error(root, "must not claim Phase 6.1"):
            print("[FAIL] self-test missed doc malware may-run phrasing", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        doc = root / DEFAULT_DOC
        doc.write_text(doc.read_text(encoding="utf-8") + "\nEarly experiments are permitted to run real malware.\n", encoding="utf-8")
        if not expect_error(root, "must not claim Phase 6.1"):
            print("[FAIL] self-test missed early-experiment malware permission", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        doc = root / DEFAULT_DOC
        doc.write_text(doc.read_text(encoding="utf-8") + "\nPhase 6 hardware validation is complete.\n", encoding="utf-8")
        if not expect_error(root, "must not claim Phase 6.1"):
            print("[FAIL] self-test missed hardware validation overclaim", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        doc = root / DEFAULT_DOC
        doc.write_text(doc.read_text(encoding="utf-8") + "\nexperiment validation is complete.\n", encoding="utf-8")
        if not expect_error(root, "must not claim Phase 6.1"):
            print("[FAIL] self-test missed experiment validation overclaim", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        doc = root / DEFAULT_DOC
        doc.write_text(doc.read_text(encoding="utf-8") + "\nLinux behavior experiments are validated.\n", encoding="utf-8")
        if not expect_error(root, "must not claim Phase 6.1"):
            print("[FAIL] self-test missed linux behavior validation overclaim", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        doc = root / DEFAULT_DOC
        doc.write_text(doc.read_text(encoding="utf-8") + "\nHardware validation has passed.\n", encoding="utf-8")
        if not expect_error(root, "must not claim Phase 6.1"):
            print("[FAIL] self-test missed hardware has-passed overclaim", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        doc = root / DEFAULT_DOC
        doc.write_text(doc.read_text(encoding="utf-8").replace("TODO(EXPERIMENT)", "PASS"), encoding="utf-8")
        if not expect_error(root, "must not claim Phase 6.1"):
            print("[FAIL] self-test missed premature doc PASS", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        (root / DEFAULT_UV_DOC).write_text("missing checker\n", encoding="utf-8")
        if not expect_error(root, "checker command"):
            print("[FAIL] self-test missed missing uv workflow reference", file=sys.stderr)
            return 1

    print("[PASS] linux behavior principle self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Phase 6.1 Linux behavior experiment principles.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--doc", type=Path, default=DEFAULT_DOC)
    parser.add_argument("--uv-doc", type=Path, default=DEFAULT_UV_DOC)
    parser.add_argument("--risk-log", type=Path, default=DEFAULT_RISK_LOG)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    try:
        errors = run_checks(args.root.resolve(), args.policy, args.doc, args.uv_doc, args.risk_log)
    except Exception as exc:
        print(f"check_linux_behavior_principles: error: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    print("[PASS] Phase 6.1 Linux behavior experiment principles are specified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
