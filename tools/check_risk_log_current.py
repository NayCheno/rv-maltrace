from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path


DEFAULT_DOC = Path("docs/10-process/risk_log.md")
REQUIRED_RISKS = {
    "Memory semantics are under-specified": [
        "bounded-prefix hardware `ARG_MEM`",
        "full hardware pointer strings",
        "external_closure_readiness.json",
    ],
    "Running real malware too early": [
        "FORBIDDEN_EARLY",
        "excluded from the current objective",
        "future real-malware validation remains separate",
    ],
    "35T results are overgeneralized to CVA6 or real malware": [
        "Current suites marked `current: true` exclude legacy 35T checks",
        "check_ccfa_claim_boundaries.py",
        "historical reference only",
    ],
    "eBPF contribution dilution": [
        "semantic-enrichment docs and checkers",
        "optional",
        "CVA6 RTL committed behavior trace",
    ],
    "Toolchain is not visible on Windows PATH": [
        "Docker `linux-behavior`",
        "source-line toolchain probe",
        "fresh-clone gate",
    ],
}
FORBIDDEN_STALE_PHRASES = (
    "Memory semantics are under-specified | Load/store behavior cannot be reconstructed from the MVP trace alone | Keep Phase 2.3 default at `TRACE_MEM_MODE_NONE`",
    "Running real malware too early | Safety and provenance risk before the trace-enabled board path and analysis workflow are validated | Phase 6.1 policy keeps `FORBIDDEN_EARLY` real-malware handling, rejects unknown-provenance binaries, and permits only benign plus malware-like synthetic samples | Open",
    "35T results are overgeneralized to CVA6 or real malware | Paper claims could exceed the LiteX/VexRiscv evidence base | Keep `results/experiments/35t/<run-id>/` scoped to 35T/VexRiscv, exclude network and real malware samples, and label reports as malware-like behavior audit accuracy | Open",
    "eBPF contribution dilution | Optional software tracing could obscure the RTL-level contribution | Phase 7.1 keeps eBPF as optional semantic enrichment only; the core contribution remains CVA6 RTL committed behavior trace | Open",
    "Toolchain is not visible on Windows PATH | Bare-metal build cannot run locally | Use Docker `cva6-toolchain` service or point scripts at installed toolchain | Open",
)
FORBIDDEN_OVERCLAIMS = (
    re.compile(r"\breal\s+malware\s+validation\s+(?:is\s+)?(?:complete|validated|passed)\b", re.IGNORECASE),
    re.compile(r"\bfull\s+hardware\s+pointer\s+strings\s+(?:are\s+)?(?:complete|validated|passed)\b", re.IGNORECASE),
    re.compile(r"\bproduction\s+streaming(?:/DMA| DMA)?\s+throughput\s+(?:is\s+)?(?:complete|validated|passed)\b", re.IGNORECASE),
    re.compile(r"\b35T\s+results\s+(?:are\s+)?(?:current\s+)?Genesys2/CVA6\s+evidence\b", re.IGNORECASE),
)


def normalized(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def parse_table(text: str) -> dict[str, list[str]]:
    rows: dict[str, list[str]] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) != 4 or cells[0] in {"Risk", "---"}:
            continue
        if all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells):
            continue
        rows[cells[0]] = cells
    return rows


def check_doc(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    rows = parse_table(text)
    errors: list[str] = []
    for risk, required_tokens in REQUIRED_RISKS.items():
        row = rows.get(risk)
        if row is None:
            errors.append(f"{path}: missing risk row: {risk}")
            continue
        row_text = " | ".join(row)
        for token in required_tokens:
            if token not in row_text:
                errors.append(f"{path}: {risk}: missing current token: {token}")
        status = row[3].lower()
        if status == "open":
            errors.append(f"{path}: {risk}: status is stale bare Open")
    normalized_text = normalized(text)
    for phrase in FORBIDDEN_STALE_PHRASES:
        if normalized(phrase) in normalized_text:
            errors.append(f"{path}: stale early risk-log wording remains: {phrase[:80]}...")
    for pattern in FORBIDDEN_OVERCLAIMS:
        if pattern.search(text):
            errors.append(f"{path}: risk log contains overclaim: {pattern.pattern}")
    return errors


def write_fixture(path: Path, *, stale: bool = False) -> None:
    status = "Open" if stale else "Mitigated for scoped bounded-prefix semantics; open only for full hardware pointer strings"
    memory_mitigation = (
        "Keep Phase 2.3 default at `TRACE_MEM_MODE_NONE`"
        if stale
        else "Current Genesys2/CVA6 evidence closes the scoped semantic route with bounded-prefix hardware `ARG_MEM`, pointer guardrails, hardware byte-prefix audit, and trusted companion alignment; full hardware pointer strings remain an external blocker tracked by `external_closure_readiness.json` and `external_closure_intake.json`"
    )
    path.write_text(
        f"""# Risk Log

| Risk | Impact | Mitigation | Status |
| --- | --- | --- | --- |
| Memory semantics are under-specified | Load/store behavior cannot be reconstructed from the MVP trace alone | {memory_mitigation} | {status} |
| Running real malware too early | Safety and provenance risk before the trace-enabled board path and analysis workflow are validated | Phase 6.1 policy keeps `FORBIDDEN_EARLY` real-malware handling, rejects unknown-provenance binaries, permits only benign plus malware-like synthetic samples, and records real malware as excluded from the current objective while keeping containment and optional future validation gates separate | Contained and excluded from current objective; future real-malware validation remains separate |
| 35T results are overgeneralized to CVA6 or real malware | Paper claims could exceed the LiteX/VexRiscv evidence base | Current suites marked `current: true` exclude legacy 35T checks; `check_ccfa_claim_boundaries.py`, `check_genesys2_cva_evidence_boundary.py`, and `check_suites.py --self-test` keep 35T/VexRiscv artifacts out of current Genesys2/CVA6 completion claims | Mitigated by current-suite boundaries; legacy 35T remains historical reference only |
| eBPF contribution dilution | Optional software tracing could obscure the RTL-level contribution | Phase 7.1/7.2/7.3 semantic-enrichment docs and checkers keep eBPF/kernel-helper metadata optional; current claims remain CVA6 RTL committed behavior trace plus bounded hardware `ARG_MEM` and explicitly scoped companion/sidecar alignment | Mitigated by semantic-enrichment boundaries |
| Toolchain is not visible on Windows PATH | Bare-metal build cannot run locally | Docker `linux-behavior` / `cva6-toolchain` routes and the source-line toolchain probe provide the current reproducible path; host PATH visibility is optional and must not be required for the current quick/fresh-clone gate | Mitigated for current reproducibility path; host PATH remains optional |
""",
        encoding="utf-8",
    )


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        doc = root / "risk_log.md"
        write_fixture(doc)
        errors = check_doc(doc)
        if errors:
            for error in errors:
                print(f"[FAIL] false positive: {error}", file=sys.stderr)
            return 1
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        doc = root / "risk_log.md"
        write_fixture(doc, stale=True)
        errors = check_doc(doc)
        if not any("stale" in error or "bare Open" in error for error in errors):
            print("[FAIL] missed stale risk-log fixture", file=sys.stderr)
            return 1
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        doc = root / "risk_log.md"
        write_fixture(doc)
        doc.write_text(doc.read_text(encoding="utf-8") + "\nreal malware validation is complete\n", encoding="utf-8")
        errors = check_doc(doc)
        if not any("overclaim" in error for error in errors):
            print("[FAIL] missed risk-log overclaim fixture", file=sys.stderr)
            return 1
    print("[PASS] risk log current-boundary checker self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check current Genesys2/CVA6 risk-log boundaries.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--doc", type=Path, default=DEFAULT_DOC)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    root = args.root.resolve()
    path = args.doc if args.doc.is_absolute() else root / args.doc
    if not path.is_file():
        print(f"[FAIL] missing risk log: {path}", file=sys.stderr)
        return 1
    errors = check_doc(path)
    if errors:
        print("[FAIL] risk log current boundaries are stale")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] risk log current boundaries accepted: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
