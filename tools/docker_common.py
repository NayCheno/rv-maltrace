from __future__ import annotations

from pathlib import Path


def docker_compose_base(compose_file: str | Path = "docker-compose.toolchain.yml") -> list[str]:
    return ["docker", "compose", "-f", Path(compose_file).as_posix()]
