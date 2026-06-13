from __future__ import annotations

import argparse
import sys
from pathlib import Path

from check_genesys2_external_closure_intake import EXPECTED_EXTERNAL_SUMMARIES, load_json, validate_external_summary
from external_closure_artifacts import ROOT, repo_path


RECORD_ID = "production_streaming_dma_trace_sink"
DEFAULT_SUMMARY = EXPECTED_EXTERNAL_SUMMARIES[RECORD_ID]["path"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the Genesys2 UART streaming/DMA throughput external summary.")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    path = repo_path(root, args.summary)
    if not path.is_file():
        print(f"[FAIL] missing streaming/DMA throughput summary: {path}", file=sys.stderr)
        return 1
    errors = validate_external_summary(RECORD_ID, load_json(path), root)
    if errors:
        print("[FAIL] streaming/DMA throughput summary is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] streaming/DMA throughput summary accepted: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
