# SPDX-License-Identifier: Apache-2.0
# Adapted with changes from Tylenol Taker Python.
"""Untrusted job's narrow Unix-socket helper. No authority in job-supplied IDs."""

import json
import socket


def parallel(calls):
    if not isinstance(calls, list) or not 1 <= len(calls) <= 4:
        raise ValueError("1..4 callback reads required")
    raw = json.dumps({"kind": "call", "calls": calls}, allow_nan=False).encode() + b"\n"
    if len(raw) > 50000:
        raise ValueError("Callback request limit")
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(30)
        connection.connect("/workspace/.rpc")
        with connection.makefile("rwb") as stream:
            stream.write(raw)
            stream.flush()
            reply = stream.readline(1048577)
            if len(reply) > 1048576 or not reply.endswith(b"\n"):
                raise ValueError("Callback response limit")
            value = json.loads(reply)
            if value.get("kind") != "result":
                raise ValueError("Callback denied")
            return value["results"]


def public_tool(name, args):
    return parallel([{"name": name, "args": args}])[0]


def inputs():
    with open("/workspace/.inputs.json") as stream:
        return json.load(stream)
