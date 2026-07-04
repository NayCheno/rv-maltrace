from __future__ import annotations

import argparse
from pathlib import Path

from genesys2_experiment_common import HOSTED_DYNAMIC_GCC_FLAGS, ProbeBuildSpec, build_probe_elf


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = Path("board/trace_validation/programs/counter_access_matrix.c")
DEFAULT_OUT_ROOT = Path("build/board/genesys2_counter_access_matrix")
DEFAULT_MANIFEST = DEFAULT_OUT_ROOT / "build_manifest.json"
BUILD_SPEC = ProbeBuildSpec(
    schema="rvmt.genesys2.counter_access_matrix_build.v1",
    binary_name="counter_access_matrix.riscv64",
    gcc_flags=HOSTED_DYNAMIC_GCC_FLAGS,
    extra_manifest_fields={
        "probe_scope": "user-visible RISC-V counter CSRs and Linux clock_gettime sources",
    },
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the Genesys2/CVA6 counter-access matrix ELF inside Docker.")
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
