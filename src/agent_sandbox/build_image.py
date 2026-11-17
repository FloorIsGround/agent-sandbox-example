# SPDX-License-Identifier: Apache-2.0
"""Build from installed, explicit assets only. No network, mounts or pulls."""

import argparse
import importlib.resources
import re
import subprocess
import tempfile
from pathlib import Path

from .docker import ENV


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, help="Reviewed local Python 3.12+ sha256 image ID")
    args = parser.parse_args()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.base):
        parser.error("Use an immutable local image ID")
    subprocess.run(
        ["/usr/bin/docker", "image", "inspect", "--format", "{{.Id}}", args.base],
        env=ENV,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    assets = importlib.resources.files("agent_sandbox")
    with tempfile.TemporaryDirectory(prefix=".sandbox-build-", dir=Path.cwd()) as directory:
        context = Path(directory) / "context"
        context.mkdir()
        config = Path(directory) / "docker-config"
        config.mkdir(mode=0o700)
        for name in ("Dockerfile", "entrypoint.py", "launch.py", "tt_tools.py", "CONTAINER_ONLY"):
            (context / name).write_bytes((assets / "container" / name).read_bytes())
        (context / "protocol.py").write_bytes((assets / "protocol.py").read_bytes())
        subprocess.run(
            [
                "/usr/bin/docker",
                "build",
                "--pull=false",
                "--network=none",
                "-q",
                "--build-arg",
                "BASE=" + args.base,
                str(context),
            ],
            env={**ENV, "DOCKER_CONFIG": str(config), "DOCKER_BUILDKIT": "0"},
            check=True,
        )


if __name__ == "__main__":
    main()
