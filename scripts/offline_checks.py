# SPDX-License-Identifier: Apache-2.0
"""Check the local install and deny outbound IP sockets in the test process."""

import socket
import sys
import unittest
from pathlib import Path

import agent_sandbox

root = Path.cwd()
assert Path(agent_sandbox.__file__).resolve() == root / "src/agent_sandbox/__init__.py"


def audit(event, args):
    if event in ("socket.connect", "socket.bind") and args[0].family in (
        socket.AF_INET,
        socket.AF_INET6,
    ):
        raise RuntimeError("Offline tests forbid IP sockets")


sys.addaudithook(audit)
suite = unittest.defaultTestLoader.discover("tests")
result = unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(not result.wasSuccessful())
