# SPDX-License-Identifier: Apache-2.0
# Adapted with changes from Tylenol Taker Python.
"""Fixed container-only child launcher. Untrusted code never runs on the host."""

import pathlib
import runpy
import sys

if not pathlib.Path("/opt/agent/CONTAINER_ONLY").is_file() or pathlib.Path.cwd() != pathlib.Path(
    "/workspace"
):
    raise SystemExit("Container image unavailable")
sys.path.insert(0, "/opt/agent")
runpy.run_path("/workspace/job.py", run_name="__main__")
