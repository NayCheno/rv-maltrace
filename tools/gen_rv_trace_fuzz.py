from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path


SEEDS: dict[str, str] = {
    "fuzz_cf": r"""
.section .text
.globl main
main:
  mv s0, ra
  li t0, 0
  beq t0, zero, 1f
  addi t0, t0, 1
1:
  la t1, 2f
  jalr ra, 0(t1)
  li a0, 1
  mv ra, s0
  ret
2:
  addi t0, t0, 2
  ret
""",
    "fuzz_trap": r"""
.section .text
.globl main
main:
  .word 0xffffffff
  ebreak
  li a0, 1
  ret
""",
    "fuzz_syscall": r"""
.section .text
.globl main
main:
  li a0, 1
  li a1, 0
  li a2, 0
  li a3, 0
  li a4, 0
  li a5, 0
  li a6, 0
  li a7, 64
  ecall
  li a0, 1
  ret
""",
    "fuzz_context": r"""
.section .text
.globl main
main:
  csrr t0, satp
  csrw satp, t0
  li a0, 1
  ret
""",
    "fuzz_overflow": r"""
.section .text
.globl main
main:
  li t0, 32
1:
  addi t0, t0, -1
  beqz t0, 2f
  jal zero, 1b
2:
  li a0, 1
  ret
""",
}


def write_seeds(out_dir: Path, cases: list[str]) -> dict[str, str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, str] = {}
    for case in cases:
        if case not in SEEDS:
            raise ValueError(f"unknown fuzz seed: {case}")
        case_dir = out_dir / case
        case_dir.mkdir(parents=True, exist_ok=True)
        source = case_dir / "main.S"
        source.write_text(SEEDS[case].strip() + "\n", encoding="utf-8", newline="\n")
        manifest[case] = source.as_posix()
    (out_dir / "manifest.json").write_text(json.dumps({"seeds": manifest}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        manifest = write_seeds(root / "seeds", sorted(SEEDS))
        missing = [case for case, path in manifest.items() if not (root / "seeds" / case / "main.S").exists() or "main.S" not in path]
        if missing:
            print(f"[FAIL] missing generated seeds: {missing}", file=sys.stderr)
            return 1
        text = (root / "seeds" / "fuzz_syscall" / "main.S").read_text(encoding="utf-8")
        if "ecall" not in text or "li a7, 64" not in text:
            print("[FAIL] syscall seed does not exercise a7/ecall shape", file=sys.stderr)
            return 1
        cf_text = (root / "seeds" / "fuzz_cf" / "main.S").read_text(encoding="utf-8")
        if "mv s0, ra" not in cf_text or "mv ra, s0" not in cf_text:
            print("[FAIL] control-flow seed does not preserve caller return address", file=sys.stderr)
            return 1
    print("[PASS] RISC-V trace fuzz seed generator self-test")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate deterministic RISC-V trace fuzz/stress assembly seeds.")
    parser.add_argument("--out-dir", type=Path, default=Path("build/fuzz_trace_seeds"))
    parser.add_argument("--case", choices=sorted(SEEDS), action="append", dest="cases")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    cases = args.cases or sorted(SEEDS)
    try:
        manifest = write_seeds(args.out_dir, cases)
    except Exception as exc:
        print(f"gen_rv_trace_fuzz: error: {exc}", file=sys.stderr)
        return 2
    for case, path in manifest.items():
        print(f"{case}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
