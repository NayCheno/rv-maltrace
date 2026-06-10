from __future__ import annotations

import argparse
from pathlib import Path

from run_check_suite import main as run_check_suite_main


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Compatibility wrapper for the current Digilent Genesys2 + CVA6 gate. "
            "The suite definition lives in tools/check_suites.json."
        )
    )
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Repository root. Defaults to current directory.")
    parser.add_argument("--list", action="store_true", help="List the commands without running them.")
    parser.add_argument("--self-test", action="store_true", help="Validate the check suite manifest.")
    parser.add_argument(
        "--skip-safe-surrogate",
        action="store_true",
        help="Run only the board/baseline gates, omitting the safe surrogate evidence boundary gate.",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        return run_check_suite_main(["--root", str(args.root), "--self-test"])

    suite = "genesys2-board" if args.skip_safe_surrogate else "genesys2-current"
    runner_args = ["--root", str(args.root), "--suite", suite]
    if args.list:
        runner_args.append("--list-checks")
    return run_check_suite_main(runner_args)


if __name__ == "__main__":
    raise SystemExit(main())
