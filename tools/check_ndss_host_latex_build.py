from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from experiment_common import (
    as_dict,
    as_list,
    load_json,
    repo_path,
    require,
    sha256_file,
)


DEFAULT_MANIFEST = Path("results/evaluation/genesys2-cva6/current/host_latex_build_summary.json")
SCHEMA = "rvmt.ndss.host_latex_build.v1"


def check_manifest(data: dict[str, Any], root: Path) -> list[str]:
    errors: list[str] = []
    require(errors, data.get("schema") == SCHEMA, f"schema must be {SCHEMA}")
    require(errors, data.get("status") == "PASS", "status must be PASS for an executed host LaTeX build")
    require(errors, data.get("command") == "uv run rvmt ndss:host-latex", "command must record the rvmt host LaTeX entrypoint")

    paper_value = data.get("paper_tex")
    pdf_value = data.get("pdf")
    log_value = data.get("log")
    require(errors, isinstance(paper_value, str) and bool(paper_value), "paper_tex missing")
    require(errors, isinstance(pdf_value, str) and bool(pdf_value), "pdf missing")
    if not isinstance(paper_value, str) or not isinstance(pdf_value, str):
        return errors

    paper = repo_path(root, paper_value)
    pdf = repo_path(root, pdf_value)
    require(errors, paper.is_file(), f"paper source missing: {paper_value}")
    require(errors, pdf.is_file(), f"PDF missing: {pdf_value}")
    if paper.is_file():
        require(errors, data.get("paper_tex_sha256") == sha256_file(paper), "paper_tex_sha256 mismatch")
    if pdf.is_file():
        require(errors, data.get("pdf_sha256") == sha256_file(pdf), "pdf_sha256 mismatch")
        require(errors, int(data.get("pdf_size_bytes") or -1) == pdf.stat().st_size, "pdf_size_bytes mismatch")
        with pdf.open("rb") as handle:
            require(errors, handle.read(5) == b"%PDF-", "pdf does not start with a PDF header")

    if log_value is not None:
        require(errors, isinstance(log_value, str) and bool(log_value), "log must be null or a non-empty path")
        if isinstance(log_value, str) and log_value:
            log = repo_path(root, log_value)
            require(errors, log.is_file(), f"LaTeX log missing: {log_value}")
            if log.is_file():
                require(errors, data.get("log_sha256") == sha256_file(log), "log_sha256 mismatch")

    boundary = as_dict(data.get("claim_boundary"))
    require(errors, boundary.get("host_latex_build_executed") is True, "host_latex_build_executed boundary missing")
    require(errors, boundary.get("anonymous_submission_ready_claimed") is False, "must not claim anonymous submission readiness")
    require(errors, boundary.get("paper_content_complete_claimed") is False, "must not claim paper content completeness")

    non_claims = " ".join(str(item).lower() for item in as_list(data.get("non_claims")))
    require(errors, "not a final anonymous submission readiness claim" in non_claims, "non-claim must reject final anonymous submission readiness")
    require(errors, "docker reproduction does not require latex" in non_claims, "non-claim must keep Docker independent from LaTeX")
    return errors


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="rvmt-latex-check-") as tmp:
        root = Path(tmp)
        paper = root / "docs/08-publication/ndss2026/paper.tex"
        pdf = root / "build/latex/ndss2026/paper.pdf"
        log = root / "build/latex/ndss2026/paper.log"
        manifest = root / DEFAULT_MANIFEST
        paper.parent.mkdir(parents=True)
        pdf.parent.mkdir(parents=True)
        manifest.parent.mkdir(parents=True)
        paper.write_text("\\documentclass{article}\\begin{document}fixture\\end{document}\n", encoding="utf-8")
        pdf.write_bytes(b"%PDF-1.5\nfixture\n")
        log.write_text("latex fixture\n", encoding="utf-8")
        row = {
            "schema": SCHEMA,
            "status": "PASS",
            "command": "uv run rvmt ndss:host-latex",
            "paper_tex": "docs/08-publication/ndss2026/paper.tex",
            "paper_tex_sha256": sha256_file(paper),
            "pdf": "build/latex/ndss2026/paper.pdf",
            "pdf_sha256": sha256_file(pdf),
            "pdf_size_bytes": pdf.stat().st_size,
            "log": "build/latex/ndss2026/paper.log",
            "log_sha256": sha256_file(log),
            "claim_boundary": {
                "host_latex_build_executed": True,
                "anonymous_submission_ready_claimed": False,
                "paper_content_complete_claimed": False,
            },
            "non_claims": [
                "This confirms the current NDSS skeleton compiles on the host; it is not a final anonymous submission readiness claim.",
                "Docker reproduction does not require LaTeX.",
            ],
        }
        manifest.write_text(json.dumps(row, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if check_manifest(load_json(manifest), root):
            print("[FAIL] good LaTeX fixture rejected", file=sys.stderr)
            return 1
        row["claim_boundary"]["paper_content_complete_claimed"] = True
        if not check_manifest(row, root):
            print("[FAIL] bad LaTeX fixture accepted", file=sys.stderr)
            return 1
    print("[PASS] NDSS host LaTeX build checker self-test")
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check the host-side NDSS LaTeX build summary.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    manifest = repo_path(root, args.manifest)
    if not manifest.is_file():
        print(f"[FAIL] missing host LaTeX build manifest: {manifest}", file=sys.stderr)
        return 1
    try:
        errors = check_manifest(load_json(manifest), root)
    except Exception as exc:
        print(f"[FAIL] host LaTeX checker error: {exc}", file=sys.stderr)
        return 1
    if errors:
        print("[FAIL] host LaTeX build summary is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] host LaTeX build summary accepted: {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
