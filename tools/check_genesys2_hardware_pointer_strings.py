from __future__ import annotations

import argparse
import sys
from pathlib import Path

from check_genesys2_external_closure_intake import EXPECTED_EXTERNAL_SUMMARIES, load_json, validate_external_summary
from external_closure_artifacts import ROOT, repo_path


RECORD_ID = "full_hardware_pointer_strings"
DEFAULT_SUMMARY = EXPECTED_EXTERNAL_SUMMARIES[RECORD_ID]["path"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the Genesys2 v3 hardware full pointer-string external summary.")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    path = repo_path(root, args.summary)
    if not path.is_file():
        print(f"[FAIL] missing hardware pointer string summary: {path}", file=sys.stderr)
        return 1
    errors = validate_external_summary(RECORD_ID, load_json(path), root)
    if errors:
        print("[FAIL] hardware pointer string summary is not acceptable")
        for error in errors:
            print(f"- {error}")
        return 1
    print(f"[PASS] hardware pointer string summary accepted: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
