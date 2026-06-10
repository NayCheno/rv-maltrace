from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any


ROOT_GENERATED_NAMES = {
    ".Xil",
    "xsim.dir",
    "dfx_runtime.txt",
    "tb_cva6_rvfi_trace_adapter_snap.wdb",
    "tb_trace_top_unit_snap.wdb",
    "vivado.jou",
    "vivado.log",
    "xelab.log",
    "xelab.pb",
    "xsim.jou",
    "xsim.log",
    "xvlog.log",
    "xvlog.pb",
}
ROOT_GENERATED_PREFIXES = (
    "vivado_",
    "xsim_",
)
ROOT_GENERATED_SUFFIXES = (
    ".backup.jou",
    ".backup.log",
)


def run_git(root: Path, args: list[str]) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=root,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f"git {' '.join(args)} failed")
    return result.stdout


def git_files(root: Path) -> list[Path]:
    output = run_git(root, ["ls-files", "-z"])
    return [Path(item) for item in output.split("\0") if item]


def path_text(path: Path) -> str:
    return path.as_posix().lower()


def file_size(root: Path, path: Path) -> int:
    full_path = root / path
    try:
        return full_path.stat().st_size
    except OSError:
        return 0


def top_prefixes(paths: list[Path], depth: int, limit: int) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    for path in paths:
        parts = path.parts[:depth]
        if parts:
            counts["/".join(parts)] += 1
    return [{"path": name, "files": count} for name, count in counts.most_common(limit)]


def top_size_prefixes(root: Path, paths: list[Path], depth: int, limit: int) -> list[dict[str, Any]]:
    sizes: Counter[str] = Counter()
    for path in paths:
        parts = path.parts[:depth]
        if parts:
            sizes["/".join(parts)] += file_size(root, path)
    return [{"path": name, "bytes": size} for name, size in sizes.most_common(limit)]


def is_root_generated(path: Path) -> bool:
    name = path.name
    if name in ROOT_GENERATED_NAMES:
        return True
    return any(name.startswith(prefix) for prefix in ROOT_GENERATED_PREFIXES) and any(
        name.endswith(suffix) for suffix in ROOT_GENERATED_SUFFIXES
    )


def ignored_root_generated(root: Path) -> list[str]:
    items: list[str] = []
    for child in root.iterdir():
        if is_root_generated(child):
            items.append(child.name)
    return sorted(items)


def classify(root: Path, paths: list[Path], max_items: int) -> dict[str, Any]:
    tracked_35t = [path for path in paths if "35t" in path_text(path)]
    tracked_35t_docs = [path for path in tracked_35t if path.parts and path.parts[0] == "docs"]
    tracked_35t_tools = [path for path in tracked_35t if path.parts and path.parts[0] == "tools"]
    tracked_results = [path for path in paths if path.parts and path.parts[0] == "results"]
    tracked_board_results = [path for path in tracked_results if len(path.parts) > 1 and path.parts[1] == "board"]
    tracked_genesys2_results = [path for path in tracked_results if "genesys2" in path_text(path)]
    tracked_docs_evidence = [
        path
        for path in paths
        if len(path.parts) >= 3 and path.parts[0] == "docs" and path.parts[1] == "07-evaluation-evidence"
    ]
    tracked_legacy_real_malware_surrogate = [
        path for path in paths if "real-malware-surrogate-35t" in path_text(path)
    ]

    categories = {
        "tracked_files": paths,
        "tracked_results": tracked_results,
        "tracked_board_results": tracked_board_results,
        "tracked_genesys2_results": tracked_genesys2_results,
        "tracked_docs_evaluation_evidence": tracked_docs_evidence,
        "tracked_legacy_35t": tracked_35t,
        "tracked_legacy_35t_docs": tracked_35t_docs,
        "tracked_legacy_35t_tools": tracked_35t_tools,
        "tracked_legacy_real_malware_surrogate_35t": tracked_legacy_real_malware_surrogate,
    }
    counts = {name: len(items) for name, items in categories.items()}
    sizes = {name: sum(file_size(root, path) for path in items) for name, items in categories.items()}

    return {
        "counts": counts,
        "sizes_bytes": sizes,
        "ignored_root_generated": ignored_root_generated(root),
        "top_tracked_dirs": top_prefixes(paths, depth=2, limit=max_items),
        "top_tracked_size_dirs": top_size_prefixes(root, paths, depth=2, limit=max_items),
        "legacy_35t_dirs": top_prefixes(tracked_35t, depth=4, limit=max_items),
        "tracked_result_dirs": top_prefixes(tracked_results, depth=4, limit=max_items),
        "recommendations": [
            "Keep current Genesys2/CVA6 gates separate from legacy 35T checks.",
            "Do not use 35T evidence as current Genesys2/CVA6 completion evidence.",
            "Review tracked legacy 35T evidence for archive/untrack decisions in a dedicated commit.",
            "Keep generated Vivado/xsim products out of the repository root and under ignored build/result roots.",
        ],
    }


def print_text(report: dict[str, Any]) -> None:
    counts = report["counts"]
    sizes = report["sizes_bytes"]
    print("[repo-hygiene] tracked files:", counts["tracked_files"])
    print("[repo-hygiene] tracked results files:", counts["tracked_results"])
    print("[repo-hygiene] tracked board result files:", counts["tracked_board_results"])
    print("[repo-hygiene] tracked Genesys2 result files:", counts["tracked_genesys2_results"])
    print("[repo-hygiene] tracked docs evaluation evidence files:", counts["tracked_docs_evaluation_evidence"])
    print("[repo-hygiene] tracked legacy 35T files:", counts["tracked_legacy_35t"])
    print("[repo-hygiene] tracked legacy 35T tools:", counts["tracked_legacy_35t_tools"])
    print("[repo-hygiene] tracked legacy real-malware-surrogate-35T files:", counts["tracked_legacy_real_malware_surrogate_35t"])
    print("[repo-hygiene] tracked results bytes:", sizes["tracked_results"])
    generated = report["ignored_root_generated"]
    print("[repo-hygiene] ignored root generated artifacts:", len(generated))
    for item in generated[:20]:
        print(f"  - {item}")
    print("[repo-hygiene] largest tracked directory groups:")
    for item in report["top_tracked_size_dirs"]:
        print(f"  - {item['path']}: {item['bytes']} bytes")
    print("[repo-hygiene] legacy 35T directory groups:")
    for item in report["legacy_35t_dirs"]:
        print(f"  - {item['path']}: {item['files']} files")


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        run_git(root, ["init"])
        files = {
            "tools/check_35t_example.py": "legacy\n",
            "tools/check_board_baseline.py": "current\n",
            "docs/07-evaluation-evidence/evidence/35t-old/report.md": "legacy evidence\n",
            "results/board/genesys2_trace_validation/run/trace.jsonl": "{}\n",
            "src/current.py": "print('ok')\n",
        }
        for name, text in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        (root / "vivado.log").write_text("generated\n", encoding="utf-8")
        run_git(root, ["add", "."])
        report = classify(root, git_files(root), max_items=10)
        counts = report["counts"]
        if counts["tracked_legacy_35t"] != 2:
            print("[FAIL] self-test expected two tracked legacy 35T files", file=sys.stderr)
            return 1
        if counts["tracked_results"] != 1 or counts["tracked_genesys2_results"] != 1:
            print("[FAIL] self-test expected one tracked Genesys2 result", file=sys.stderr)
            return 1
        if "vivado.log" not in report["ignored_root_generated"]:
            print("[FAIL] self-test missed root generated artifact", file=sys.stderr)
            return 1
    print("[PASS] repo hygiene audit self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit repository clutter without deleting or rewriting history.")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Repository root. Defaults to current directory.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    parser.add_argument("--max-items", type=int, default=12, help="Maximum grouped paths to print per section.")
    parser.add_argument("--self-test", action="store_true", help="Run the audit classifier self-test.")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    root = args.root.resolve()
    try:
        report = classify(root, git_files(root), max_items=args.max_items)
    except Exception as exc:
        print(f"audit_repo_hygiene: error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_text(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
