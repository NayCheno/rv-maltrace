from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any


DEFAULT_MANIFEST = Path("experiments/linux_behavior/benign/manifest.json")
DEFAULT_DOC = Path("docs/04-runtime-linux/linux_benign_dataset.md")
DEFAULT_POLICY = Path("experiments/linux_behavior/policy.json")
DEFAULT_UV_DOC = Path("docs/10-process/uv_workflow.md")

EXPECTED_FIXTURES = ["experiments/linux_behavior/benign/fixtures/input.txt"]
EXPECTED_SAMPLES = {
    "hello": {
        "order": 1,
        "status": "PASS_LOCAL_LINUX_CONTROL",
        "doc_evidence_dir": "build/benign_control/hello",
        "provenance": "known_benign_rootfs",
        "network_required": False,
        "default_enabled": True,
        "source": "board/artix7_35t/linux/rvmt_benign_workload.c",
        "command": ["./rvmt_benign_workload", "hello"],
        "evidence_dir": "01_hello",
        "expected_syscalls": ["write"],
        "expected_behavior": ["stdout_write"],
    },
    "ls": {
        "order": 2,
        "status": "PASS_LOCAL_LINUX_CONTROL",
        "doc_evidence_dir": "build/benign_control/ls",
        "provenance": "known_benign_rootfs",
        "network_required": False,
        "default_enabled": True,
        "source": "board/artix7_35t/linux/rvmt_benign_workload.c",
        "command": ["./rvmt_benign_workload", "ls"],
        "evidence_dir": "02_ls",
        "expected_syscalls": ["openat", "getdents64", "write", "close"],
        "expected_behavior": ["directory_listing"],
    },
    "cat": {
        "order": 3,
        "status": "PASS_LOCAL_LINUX_CONTROL",
        "doc_evidence_dir": "build/benign_control/cat",
        "provenance": "known_benign_rootfs",
        "network_required": False,
        "default_enabled": True,
        "source": "board/artix7_35t/linux/rvmt_benign_workload.c",
        "command": ["./rvmt_benign_workload", "cat"],
        "evidence_dir": "03_cat",
        "expected_syscalls": ["openat", "read", "write", "close"],
        "expected_behavior": ["file_read", "stdout_write"],
    },
    "cp": {
        "order": 4,
        "status": "PASS_LOCAL_LINUX_CONTROL",
        "doc_evidence_dir": "build/benign_control/cp",
        "provenance": "known_benign_rootfs",
        "network_required": False,
        "default_enabled": True,
        "source": "board/artix7_35t/linux/rvmt_benign_workload.c",
        "command": ["./rvmt_benign_workload", "cp"],
        "evidence_dir": "04_cp",
        "expected_syscalls": ["openat", "read", "write", "close"],
        "expected_behavior": ["file_copy"],
    },
    "sha256sum": {
        "order": 5,
        "status": "PASS_LOCAL_LINUX_CONTROL",
        "doc_evidence_dir": "build/benign_control/sha256sum",
        "provenance": "known_benign_rootfs",
        "network_required": False,
        "default_enabled": True,
        "source": "board/artix7_35t/linux/rvmt_benign_workload.c",
        "command": ["./rvmt_benign_workload", "sha256sum"],
        "evidence_dir": "05_sha256sum",
        "expected_syscalls": ["openat", "read", "write", "close"],
        "expected_behavior": ["file_hash"],
    },
    "small_network_client": {
        "order": 6,
        "status": "OPTIONAL_DISABLED_BY_DEFAULT",
        "doc_evidence_dir": "06_small_network_client",
        "provenance": "repository_source",
        "network_required": True,
        "default_enabled": False,
        "source": "experiments/linux_behavior/benign/programs/small_network_client.c",
        "command": ["./small_network_client", "127.0.0.1", "7"],
        "evidence_dir": "06_small_network_client",
        "expected_syscalls": ["socket", "connect", "write", "read", "close"],
        "expected_behavior": ["network_client"],
    },
}
SAMPLE_KEYS = {
    "id",
    "class",
    "status",
    "provenance",
    "network_required",
    "default_enabled",
    "command",
    "evidence_dir",
    "expected_syscalls",
    "expected_behavior",
    "source",
}
REQUIRED_DOC_TEXT = (
    "Phase 6.2 defines the benign Linux behavior dataset.",
    "current evidence package includes a local Linux non-network benign-control audit",
    "not Genesys2 board benign-trace evidence and not malware detection accuracy evidence",
    "experiments/linux_behavior/benign/manifest.json",
    "results/evaluation/genesys2-cva6/current/benign_control_summary.json",
    "optional, disabled by default",
    "preserve the Phase 6.1 network policy",
    "`trace.jsonl`",
    "`semantic_events.json`",
    "`behavior_graph.json`",
    "`recovery_report.md`",
    "All samples in this dataset are benign.",
    "must not include real malware",
    "uv run python tools/check_benign_control_summary.py --root .",
)
FORBIDDEN_DOC_PATTERNS = (
    re.compile(r"\bPASS\b", re.IGNORECASE),
    re.compile(r"\breal\s+malware\s+(?:is\s+)?(?:allowed|included|permitted|approved)\b", re.IGNORECASE),
    re.compile(
        r"\breal\s+malware\s+(?:may|can|should|will|is\s+permitted\s+to|is\s+allowed\s+to)\s+"
        r"(?:be\s+)?(?:run|used|included|executed)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bunknown[- ]provenance(?:\s+(?:binaries|payloads|samples))?\s+"
        r"(?:may|can|should|will|are\s+permitted\s+to|are\s+allowed\s+to|are)?\s*"
        r"(?:be\s+)?(?:allowed|included|permitted|approved|used|run)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bnetwork\s+(?:is\s+)?enabled\s+by\s+default\b", re.IGNORECASE),
    re.compile(
        r"\b(?:linux\s+benign\s+dataset\s+)?(?:experiments|linux\s+behavior\s+experiments|dataset\s+experiments)\s+"
        r"(?:validation\s+)?(?:have|has|are|is)?\s*(?:passed|validated|complete)\b",
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


def samples_by_id(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    samples = manifest.get("samples")
    if not isinstance(samples, list):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for item in samples:
        if isinstance(item, dict) and isinstance(item.get("id"), str):
            result[item["id"]] = item
    return result


def check_policy(path: Path) -> list[str]:
    policy = load_json(path)
    errors: list[str] = []
    if policy.get("real_malware_policy") != "FORBIDDEN_EARLY":
        errors.append(f"{path}: Phase 6.1 real malware policy must remain FORBIDDEN_EARLY")
    if policy.get("network_policy") != "disabled_by_default":
        errors.append(f"{path}: Phase 6.1 network policy must remain disabled_by_default")
    if "benign" not in policy.get("allowed_sample_classes", []):
        errors.append(f"{path}: benign must remain an allowed sample class")
    if "real_malware" not in policy.get("blocked_sample_classes", []):
        errors.append(f"{path}: real_malware must remain blocked")
    if "unknown_provenance" not in policy.get("blocked_sample_classes", []):
        errors.append(f"{path}: unknown_provenance must remain blocked")
    return errors


def check_manifest(root: Path, path: Path) -> list[str]:
    manifest = load_json(path)
    errors: list[str] = []
    if manifest.get("phase") != "6.2":
        errors.append(f"{path}: phase must be 6.2")
    if manifest.get("status") != "PASS_LOCAL_LINUX_CONTROL":
        errors.append(f"{path}: status must be PASS_LOCAL_LINUX_CONTROL")
    if manifest.get("sample_class") != "benign":
        errors.append(f"{path}: sample_class must be benign")
    if manifest.get("policy_ref") != "experiments/linux_behavior/policy.json":
        errors.append(f"{path}: policy_ref must point at the Phase 6.1 policy")
    if manifest.get("evidence_root") != "results/linux_behavior/<run-id>/benign":
        errors.append(f"{path}: evidence_root must be results/linux_behavior/<run-id>/benign")
    if manifest.get("fixtures") != EXPECTED_FIXTURES:
        errors.append(f"{path}: fixtures must be {EXPECTED_FIXTURES}")
    for fixture in EXPECTED_FIXTURES:
        if not resolve(root, Path(fixture)).exists():
            errors.append(f"{path}: missing fixture {fixture}")

    samples = samples_by_id(manifest)
    if set(samples) != set(EXPECTED_SAMPLES):
        errors.append(f"{path}: sample ids differ from expected set: {sorted(samples)}")
    for sample_id, expected in EXPECTED_SAMPLES.items():
        sample = samples.get(sample_id, {})
        extra_keys = set(sample) - SAMPLE_KEYS
        if extra_keys:
            errors.append(f"{path}: {sample_id} has unexpected keys: {sorted(extra_keys)}")
        if sample.get("class") != "benign":
            errors.append(f"{path}: {sample_id}.class must be benign")
        if sample.get("provenance") in {"unknown", "unknown_provenance", "real_malware"}:
            errors.append(f"{path}: {sample_id}.provenance must not be unknown or real malware")
        for field, value in expected.items():
            if field in {"order", "doc_evidence_dir"}:
                continue
            if sample.get(field) != value:
                errors.append(f"{path}: {sample_id}.{field} must be {value!r}")
        if sample_id != "small_network_client" and sample.get("network_required") is not False:
            errors.append(f"{path}: {sample_id} must not require network")
        if sample_id != "small_network_client" and sample.get("default_enabled") is not True:
            errors.append(f"{path}: {sample_id} must be enabled by default")
        if sample_id == "small_network_client":
            source = sample.get("source")
            if not isinstance(source, str) or not resolve(root, Path(source)).exists():
                errors.append(f"{path}: small_network_client source must exist")
            elif "SYS_socket" not in resolve(root, Path(source)).read_text(encoding="utf-8"):
                errors.append(f"{source}: small network client must use explicit socket syscall")
    return errors


def parse_table_rows(text: str) -> list[list[str]]:
    rows: list[list[str]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line.startswith("|"):
            continue
        cells = [cell.strip().strip("`") for cell in line.strip("|").split("|")]
        if cells and all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells):
            continue
        if cells and cells[0] == "Order":
            continue
        rows.append(cells)
    return rows


def check_doc(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    normalized = normalized_text(text)
    errors: list[str] = []
    for required in REQUIRED_DOC_TEXT:
        if normalized_text(required) not in normalized:
            errors.append(f"{path}: missing required text: {required}")
    for pattern in FORBIDDEN_DOC_PATTERNS:
        if pattern.search(text):
            errors.append(f"{path}: must not claim PASS or permit unsafe benign-dataset behavior")

    rows = parse_table_rows(text)
    by_sample = {row[1]: row for row in rows if len(row) >= 7}
    for sample_id, expected in EXPECTED_SAMPLES.items():
        row = by_sample.get(sample_id)
        if row is None:
            errors.append(f"{path}: missing dataset row for {sample_id}")
            continue
        if row[0] != str(expected["order"]):
            errors.append(f"{path}: {sample_id} order must be {expected['order']}")
        if row[4] == "yes":
            errors.append(f"{path}: {sample_id} must not document network as enabled")
        if row[5] != expected["status"]:
            errors.append(f"{path}: {sample_id} status must be {expected['status']}")
        if row[6] != f"{expected['doc_evidence_dir']}/":
            errors.append(f"{path}: {sample_id} evidence directory mismatch")
    return errors


def check_uv_doc(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    if "tools/check_linux_benign_dataset.py" not in text:
        errors.append(f"{path}: missing Phase 6.2 checker command")
    if "docs/04-runtime-linux/linux_benign_dataset.md" not in text:
        errors.append(f"{path}: missing Phase 6.2 benign dataset doc reference")
    if "experiments/linux_behavior/benign/manifest.json" not in text:
        errors.append(f"{path}: missing Phase 6.2 benign manifest reference")
    return errors


def run_checks(root: Path, manifest: Path, doc: Path, policy: Path, uv_doc: Path) -> list[str]:
    manifest_path = resolve(root, manifest)
    doc_path = resolve(root, doc)
    policy_path = resolve(root, policy)
    uv_path = resolve(root, uv_doc)
    errors: list[str] = []
    for path, label in (
        (manifest_path, "manifest"),
        (doc_path, "doc"),
        (policy_path, "policy"),
        (uv_path, "uv workflow"),
    ):
        if not path.exists():
            errors.append(f"missing {label}: {path}")
    if errors:
        return errors
    errors.extend(check_policy(policy_path))
    errors.extend(check_manifest(root, manifest_path))
    errors.extend(check_doc(doc_path))
    errors.extend(check_uv_doc(uv_path))
    return errors


def write_fixture(root: Path) -> None:
    (root / "experiments/linux_behavior/benign/fixtures").mkdir(parents=True)
    (root / "experiments/linux_behavior/benign/programs").mkdir(parents=True)
    (root / "docs/04-runtime-linux").mkdir(parents=True)
    (root / "docs/10-process").mkdir(parents=True)
    (root / EXPECTED_FIXTURES[0]).write_text("fixture\n", encoding="utf-8")
    (root / EXPECTED_SAMPLES["small_network_client"]["source"]).write_text("SYS_socket\n", encoding="utf-8")
    (root / DEFAULT_POLICY).write_text(
        json.dumps(
            {
                "real_malware_policy": "FORBIDDEN_EARLY",
                "network_policy": "disabled_by_default",
                "allowed_sample_classes": ["benign", "malware_like_synthetic"],
                "blocked_sample_classes": ["real_malware", "unknown_provenance"],
            }
        ),
        encoding="utf-8",
    )
    samples = []
    for sample_id, expected in EXPECTED_SAMPLES.items():
        sample = {"id": sample_id, "class": "benign"}
        for field, value in expected.items():
            if field not in {"order", "doc_evidence_dir"}:
                sample[field] = value
        samples.append(sample)
    (root / DEFAULT_MANIFEST).write_text(
        json.dumps(
            {
                "phase": "6.2",
                "status": "PASS_LOCAL_LINUX_CONTROL",
                "sample_class": "benign",
                "policy_ref": "experiments/linux_behavior/policy.json",
                "evidence_root": "results/linux_behavior/<run-id>/benign",
                "fixtures": EXPECTED_FIXTURES,
                "samples": samples,
            }
        ),
        encoding="utf-8",
    )
    (root / DEFAULT_DOC).write_text(
        """# Linux Benign Dataset

Phase 6.2 defines the benign Linux behavior dataset.
current evidence package includes a local Linux non-network benign-control audit
not Genesys2 board benign-trace evidence and not malware detection accuracy evidence
experiments/linux_behavior/benign/manifest.json
results/evaluation/genesys2-cva6/current/benign_control_summary.json
optional, disabled by default
preserve the Phase 6.1 network policy

| Order | Sample | Command shape | Expected behavior | Network | Status | Evidence directory |
| ---: | --- | --- | --- | --- | --- | --- |
| 1 | hello | echo | stdout write | no | PASS_LOCAL_LINUX_CONTROL | `build/benign_control/hello/` |
| 2 | ls | ls | directory listing | no | PASS_LOCAL_LINUX_CONTROL | `build/benign_control/ls/` |
| 3 | cat | cat | file read | no | PASS_LOCAL_LINUX_CONTROL | `build/benign_control/cat/` |
| 4 | cp | cp | file copy | no | PASS_LOCAL_LINUX_CONTROL | `build/benign_control/cp/` |
| 5 | sha256sum | sha256sum | file hash | no | PASS_LOCAL_LINUX_CONTROL | `build/benign_control/sha256sum/` |
| 6 | small_network_client | client | socket | optional, disabled by default | OPTIONAL_DISABLED_BY_DEFAULT | `06_small_network_client/` |

`trace.jsonl`
`semantic_events.json`
`behavior_graph.json`
`recovery_report.md`
All samples in this dataset are benign.
must not include real malware
uv run python tools/check_benign_control_summary.py --root .
""",
        encoding="utf-8",
    )
    (root / DEFAULT_UV_DOC).write_text(
        "uv run python tools/check_linux_benign_dataset.py\n"
        "docs/04-runtime-linux/linux_benign_dataset.md\n"
        "experiments/linux_behavior/benign/manifest.json\n",
        encoding="utf-8",
    )


def expect_error(root: Path, expected: str) -> bool:
    return any(expected in error for error in run_checks(root, DEFAULT_MANIFEST, DEFAULT_DOC, DEFAULT_POLICY, DEFAULT_UV_DOC))


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        errors = run_checks(root, DEFAULT_MANIFEST, DEFAULT_DOC, DEFAULT_POLICY, DEFAULT_UV_DOC)
        if errors:
            for error in errors:
                print(f"[FAIL] self-test false positive: {error}", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        manifest = load_json(root / DEFAULT_MANIFEST)
        manifest["samples"] = manifest["samples"][:-1]
        (root / DEFAULT_MANIFEST).write_text(json.dumps(manifest), encoding="utf-8")
        if not expect_error(root, "sample ids differ"):
            print("[FAIL] self-test missed missing sample", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        manifest = load_json(root / DEFAULT_MANIFEST)
        manifest["samples"][0]["class"] = "real_malware"
        (root / DEFAULT_MANIFEST).write_text(json.dumps(manifest), encoding="utf-8")
        if not expect_error(root, "class must be benign"):
            print("[FAIL] self-test missed non-benign sample class", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        manifest = load_json(root / DEFAULT_MANIFEST)
        manifest["samples"][1]["provenance"] = "unknown_provenance"
        (root / DEFAULT_MANIFEST).write_text(json.dumps(manifest), encoding="utf-8")
        if not expect_error(root, "provenance"):
            print("[FAIL] self-test missed unknown provenance", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        manifest = load_json(root / DEFAULT_MANIFEST)
        for sample in manifest["samples"]:
            if sample["id"] == "small_network_client":
                sample["default_enabled"] = True
        (root / DEFAULT_MANIFEST).write_text(json.dumps(manifest), encoding="utf-8")
        if not expect_error(root, "default_enabled"):
            print("[FAIL] self-test missed enabled network client", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        doc = root / DEFAULT_DOC
        doc.write_text(doc.read_text(encoding="utf-8") + "\nPASS\n", encoding="utf-8")
        if not expect_error(root, "must not claim PASS"):
            print("[FAIL] self-test missed premature PASS doc", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        doc = root / DEFAULT_DOC
        doc.write_text(doc.read_text(encoding="utf-8") + "\nreal malware is allowed\n", encoding="utf-8")
        if not expect_error(root, "must not claim PASS"):
            print("[FAIL] self-test missed unsafe doc malware allowance", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        doc = root / DEFAULT_DOC
        doc.write_text(doc.read_text(encoding="utf-8") + "\nLinux benign dataset experiments have passed.\n", encoding="utf-8")
        if not expect_error(root, "must not claim PASS"):
            print("[FAIL] self-test missed benign experiment overclaim", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        doc = root / DEFAULT_DOC
        doc.write_text(doc.read_text(encoding="utf-8") + "\nLinux behavior experiments are validated.\n", encoding="utf-8")
        if not expect_error(root, "must not claim PASS"):
            print("[FAIL] self-test missed linux behavior validation overclaim", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        doc = root / DEFAULT_DOC
        doc.write_text(doc.read_text(encoding="utf-8") + "\nReal malware may be run in this benign dataset.\n", encoding="utf-8")
        if not expect_error(root, "must not claim PASS"):
            print("[FAIL] self-test missed malware may-run wording", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        doc = root / DEFAULT_DOC
        doc.write_text(doc.read_text(encoding="utf-8") + "\nUnknown provenance binaries may be included.\n", encoding="utf-8")
        if not expect_error(root, "must not claim PASS"):
            print("[FAIL] self-test missed unknown-provenance may-include wording", file=sys.stderr)
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_fixture(root)
        doc = root / DEFAULT_DOC
        doc.write_text(
            doc.read_text(encoding="utf-8").replace(
                "optional, disabled by default | OPTIONAL_DISABLED_BY_DEFAULT",
                "yes | OPTIONAL_DISABLED_BY_DEFAULT",
            ),
            encoding="utf-8",
        )
        if not expect_error(root, "must not document network as enabled"):
            print("[FAIL] self-test missed network doc regression", file=sys.stderr)
            return 1

    for token, expected in (
        ("uv run python tools/check_linux_benign_dataset.py", "checker command"),
        ("docs/04-runtime-linux/linux_benign_dataset.md", "benign dataset doc reference"),
        ("experiments/linux_behavior/benign/manifest.json", "benign manifest reference"),
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_fixture(root)
            uv_doc = root / DEFAULT_UV_DOC
            uv_doc.write_text(uv_doc.read_text(encoding="utf-8").replace(token, ""), encoding="utf-8")
            if not expect_error(root, expected):
                print(f"[FAIL] self-test missed missing uv reference: {token}", file=sys.stderr)
                return 1

    print("[PASS] linux benign dataset self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Phase 6.2 Linux benign dataset specification.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--doc", type=Path, default=DEFAULT_DOC)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--uv-doc", type=Path, default=DEFAULT_UV_DOC)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    try:
        errors = run_checks(args.root.resolve(), args.manifest, args.doc, args.policy, args.uv_doc)
    except Exception as exc:
        print(f"check_linux_benign_dataset: error: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    print("[PASS] Phase 6.2 Linux benign dataset is specified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
