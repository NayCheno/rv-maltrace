from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    repo_path,
    write_json,
)

from check_genesys2_external_closure_intake import (
    DEFAULT_EXTERNAL_ROOT,
    EXPECTED_EXTERNAL_SUMMARIES,
    fixture_evidence_artifacts,
    good_external_summary,
    load_json,
    validate_external_summary,
)
from package_genesys2_external_closure_plan import (
    board_benign_template,
    pointer_string_template,
    source_line_template,
    streaming_template,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TEMPLATE_ROOT = Path("results/evaluation/genesys2-cva6/current/external_closure_templates")

TEMPLATE_BUILDERS = {
    "board_native_dwarf_source_lines": source_line_template,
    "full_hardware_pointer_strings": pointer_string_template,
    "production_streaming_dma_trace_sink": streaming_template,
    "genesys2_board_benign_control": board_benign_template,
}


def repo_relative(root: Path, value: Path) -> str | None:
    try:
        return value.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return None


def template_filename(record_id: str) -> str:
    source = EXPECTED_EXTERNAL_SUMMARIES[record_id]["path"]
    return f"{source.stem}.template.json"


def template_for(record_id: str) -> dict[str, Any]:
    try:
        return TEMPLATE_BUILDERS[record_id]()
    except KeyError as exc:
        raise ValueError(f"unknown external summary record id: {record_id}") from exc


def validate_candidate(root: Path, record_id: str, summary_path: Path) -> list[str]:
    data = load_json(summary_path)
    errors = validate_candidate_input_path(root, record_id, summary_path)
    errors.extend(validate_external_summary(record_id, data, root))
    if data.get("template_only") is True or data.get("status") == "TEMPLATE_NOT_EVIDENCE":
        errors.append("template summaries are not evidence; provide a board/RTL-derived PASS summary")
    return errors


def validate_candidate_input_path(root: Path, record_id: str, path: Path) -> list[str]:
    errors: list[str] = []
    target = repo_path(root, path)
    target_rel = repo_relative(root, target)
    if target.name.endswith(".template.json"):
        errors.append(f"{record_id}: candidate summary path must not be a .template.json file")
    if target_rel is not None and "external_closure_templates/" in target_rel:
        errors.append(f"{record_id}: candidate summary path must not live under external_closure_templates/")
    return errors


def validate_template_output_path(root: Path, record_id: str, path: Path) -> list[str]:
    errors: list[str] = []
    target = repo_path(root, path)
    target_rel = repo_relative(root, target)
    intake_path = repo_path(root, EXPECTED_EXTERNAL_SUMMARIES[record_id]["path"])
    external_root = repo_path(root, DEFAULT_EXTERNAL_ROOT)
    if target.resolve() == intake_path.resolve():
        errors.append(f"{record_id}: template path must not be the intake evidence path")
    if target_rel is None:
        errors.append(f"{record_id}: template path must stay under the repository root")
    else:
        external_root_rel = DEFAULT_EXTERNAL_ROOT.as_posix().rstrip("/") + "/"
        if target_rel.startswith(external_root_rel):
            errors.append(f"{record_id}: template path must not live under external_closure evidence root")
        if "external_closure_templates/" not in target_rel:
            errors.append(f"{record_id}: template path must live under external_closure_templates/")
    if not target.name.endswith(".template.json"):
        errors.append(f"{record_id}: template filename must end with .template.json")
    if external_root.exists() and target.resolve().is_relative_to(external_root.resolve()):
        errors.append(f"{record_id}: template path must stay outside external_closure evidence root")
    return errors


def write_all_templates(root: Path, template_root: Path) -> list[Path]:
    target_root = repo_path(root, template_root)
    written: list[Path] = []
    for record_id in EXPECTED_EXTERNAL_SUMMARIES:
        path = target_root / template_filename(record_id)
        errors = validate_template_output_path(root, record_id, path)
        if errors:
            raise ValueError("; ".join(errors))
        write_json(path, template_for(record_id))
        written.append(path)
    return written


def check_templates(root: Path, template_root: Path) -> list[str]:
    errors: list[str] = []
    target_root = repo_path(root, template_root)
    for record_id, spec in EXPECTED_EXTERNAL_SUMMARIES.items():
        path = target_root / template_filename(record_id)
        errors.extend(validate_template_output_path(root, record_id, path))
        if not path.is_file():
            errors.append(f"{record_id}: template missing: {path}")
            continue
        try:
            data = load_json(path)
        except Exception as exc:
            errors.append(f"{record_id}: template JSON load failed: {exc}")
            continue
        expected = template_for(record_id)
        if data != expected:
            errors.append(f"{record_id}: template content drifted from generator")
        if data.get("status") != "TEMPLATE_NOT_EVIDENCE" or data.get("template_only") is not True:
            errors.append(f"{record_id}: template must remain TEMPLATE_NOT_EVIDENCE/template_only")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        written = write_all_templates(root, DEFAULT_TEMPLATE_ROOT)
        if len(written) != len(EXPECTED_EXTERNAL_SUMMARIES):
            print("[FAIL] template count mismatch", file=sys.stderr)
            return 1
        errors = check_templates(root, DEFAULT_TEMPLATE_ROOT)
        if errors:
            print("[FAIL] generated templates failed template check", file=sys.stderr)
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        for record_id in EXPECTED_EXTERNAL_SUMMARIES:
            template_path = root / DEFAULT_TEMPLATE_ROOT / template_filename(record_id)
            template_errors = validate_candidate(root, record_id, template_path)
            if not template_errors:
                print("[FAIL] template was accepted as evidence", file=sys.stderr)
                return 1
            candidate_path = root / "candidate" / f"{record_id}.json"
            write_json(candidate_path, good_external_summary(record_id, fixture_evidence_artifacts(root, record_id)))
            errors = validate_candidate(root, record_id, candidate_path)
            if errors:
                print(f"[FAIL] good candidate failed for {record_id}", file=sys.stderr)
                for error in errors:
                    print(error, file=sys.stderr)
                return 1
            template_dir_candidate = root / DEFAULT_TEMPLATE_ROOT / f"{record_id}.candidate.json"
            write_json(template_dir_candidate, good_external_summary(record_id, fixture_evidence_artifacts(root, record_id)))
            errors = validate_candidate(root, record_id, template_dir_candidate)
            if not any("external_closure_templates" in error for error in errors):
                print(f"[FAIL] template-directory candidate was not rejected for {record_id}", file=sys.stderr)
                return 1
            template_named_candidate = root / "candidate" / f"{record_id}.template.json"
            write_json(template_named_candidate, good_external_summary(record_id, fixture_evidence_artifacts(root, record_id)))
            errors = validate_candidate(root, record_id, template_named_candidate)
            if not any(".template.json" in error for error in errors):
                print(f"[FAIL] .template.json candidate was not rejected for {record_id}", file=sys.stderr)
                return 1
        bad_template = root / DEFAULT_TEMPLATE_ROOT / template_filename("full_hardware_pointer_strings")
        data = load_json(bad_template)
        data["status"] = "PASS"
        write_json(bad_template, data)
        if not check_templates(root, DEFAULT_TEMPLATE_ROOT):
            print("[FAIL] evidence-like template drift was not rejected", file=sys.stderr)
            return 1
        intake_errors = validate_template_output_path(
            root,
            "full_hardware_pointer_strings",
            EXPECTED_EXTERNAL_SUMMARIES["full_hardware_pointer_strings"]["path"],
        )
        if not intake_errors:
            print("[FAIL] intake-path template output was not rejected", file=sys.stderr)
            return 1
        evidence_root_errors = validate_template_output_path(
            root,
            "full_hardware_pointer_strings",
            DEFAULT_EXTERNAL_ROOT / "operator_notes.template.json",
        )
        if not evidence_root_errors:
            print("[FAIL] external_closure template output was not rejected", file=sys.stderr)
            return 1
        filename_errors = validate_template_output_path(
            root,
            "full_hardware_pointer_strings",
            DEFAULT_TEMPLATE_ROOT / "hardware_pointer_strings_summary.json",
        )
        if not filename_errors:
            print("[FAIL] non-template filename output was not rejected", file=sys.stderr)
            return 1
    print("[PASS] Genesys2 external summary preparation self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Prepare or pre-validate candidate external summaries for remaining non-real-malware Genesys2/CVA6 blockers."
    )
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--record-id", choices=sorted(EXPECTED_EXTERNAL_SUMMARIES))
    parser.add_argument("--summary", type=Path, help="Candidate external summary JSON to validate without moving it into the intake path.")
    parser.add_argument("--write-template", type=Path, help="Write the selected record's template JSON to this path.")
    parser.add_argument("--write-all-templates", action="store_true", help="Write all external summary templates outside the intake path.")
    parser.add_argument("--check-templates", action="store_true", help="Check that all generated templates are present and still marked as non-evidence.")
    parser.add_argument("--template-root", type=Path, default=DEFAULT_TEMPLATE_ROOT)
    parser.add_argument("--list", action="store_true", help="List accepted external summary record ids and intake paths.")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()

    root = args.root.resolve()
    if args.list:
        for record_id, spec in EXPECTED_EXTERNAL_SUMMARIES.items():
            print(f"{record_id}: schema={spec['schema']} intake_path={spec['path'].as_posix()}")
        return 0

    did_work = False
    if args.write_all_templates:
        written = write_all_templates(root, args.template_root)
        for path in written:
            print(f"[WRITE] template {path}")
        did_work = True

    if args.check_templates:
        errors = check_templates(root, args.template_root)
        if errors:
            print(f"[FAIL] external summary templates rejected under {repo_path(root, args.template_root)}")
            for error in errors:
                print(f"- {error}")
            return 1
        print(f"[PASS] external summary templates accepted under {repo_path(root, args.template_root)}")
        did_work = True

    if args.write_template:
        if not args.record_id:
            print("prepare_genesys2_external_summary: error: --write-template requires --record-id", file=sys.stderr)
            return 2
        path = repo_path(root, args.write_template)
        errors = validate_template_output_path(root, args.record_id, path)
        if errors:
            print(f"[FAIL] template output path rejected for {args.record_id}: {path}")
            for error in errors:
                print(f"- {error}")
            return 1
        write_json(path, template_for(args.record_id))
        print(f"[WRITE] template {path}")
        did_work = True

    if args.summary:
        if not args.record_id:
            print("prepare_genesys2_external_summary: error: --summary requires --record-id", file=sys.stderr)
            return 2
        path = repo_path(root, args.summary)
        if not path.is_file():
            print(f"[FAIL] candidate summary missing: {path}", file=sys.stderr)
            return 1
        try:
            errors = validate_candidate(root, args.record_id, path)
        except Exception as exc:
            print(f"[FAIL] candidate summary validation error: {exc}", file=sys.stderr)
            return 2
        if errors:
            print(f"[FAIL] candidate external summary rejected for {args.record_id}: {path}")
            for error in errors:
                print(f"- {error}")
            return 1
        print(f"[PASS] candidate external summary accepted for {args.record_id}: {path}")
        did_work = True

    if not did_work:
        parser.print_help()
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
