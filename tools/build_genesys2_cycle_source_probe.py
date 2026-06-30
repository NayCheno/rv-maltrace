from __future__ import annotations

import argparse
from pathlib import Path

from genesys2_experiment_common import FREESTANDING_GCC_FLAGS, ProbeBuildSpec, build_probe_elf


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = Path("board/trace_validation/programs/cycle_source_probe.c")
DEFAULT_OUT_ROOT = Path("build/board/genesys2_cycle_source_probe")
DEFAULT_MANIFEST = DEFAULT_OUT_ROOT / "build_manifest.json"
BUILD_SPEC = ProbeBuildSpec(
    schema="rvmt.genesys2.cycle_source_probe_build.v1",
    binary_name="cycle_source_probe.riscv64",
    gcc_flags=FREESTANDING_GCC_FLAGS,
    extra_manifest_fields={"cycle_source": "kernel_perf_hw_cycles"},
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the Genesys2/CVA6 kernel-perf cycle-source probe ELF inside Docker.")
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--out-root", type=Path, default=DEFAULT_OUT_ROOT)
    parser.add_argument("--compose-file", type=Path, default=Path("docker-compose.toolchain.yml"))
    parser.add_argument("--service", default="linux-behavior")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if not args.source.is_file():
        parser.error(f"source missing: {args.source}")
    return build_probe_elf(
        ROOT,
        source=args.source,
        out_root=args.out_root,
        compose_file=args.compose_file,
        service=args.service,
        dry_run=args.dry_run,
        spec=BUILD_SPEC,
    )


if __name__ == "__main__":
    raise SystemExit(main())
