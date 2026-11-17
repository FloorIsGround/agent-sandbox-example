# SPDX-License-Identifier: Apache-2.0
"""Authored fixed IPC peer. It never evaluates bootstrap code on the host."""

import base64
import sys
import time

from agent_sandbox.protocol import Codec, loads

bootstrap = loads(sys.stdin.buffer.readline())
codec = Codec(bytes.fromhex(bootstrap["key"]))
scenario = sys.argv[1]


def emit(frame):
    sys.stdout.buffer.write(codec.encode(frame))
    sys.stdout.buffer.flush()


if scenario == "wait":
    time.sleep(60)
elif scenario == "broker":
    emit({"kind": "call", "calls": [{"name": "catalog", "args": {"item": "apple"}}]})
    reply = codec.decode(sys.stdin.buffer.readline())
    assert reply == {"kind": "result", "results": ["synthetic"]}
elif scenario == "private":
    emit({"kind": "call", "calls": [{"name": "private", "args": {}}]})
    time.sleep(60)
elif scenario == "stderr":
    sys.stderr.buffer.write(b"x" * 20000)
    sys.stderr.buffer.flush()
elif scenario == "overflow":
    sys.stdout.buffer.write(b"x" * 1048578 + b"\n")
    sys.stdout.buffer.flush()
elif scenario == "invalid-mac":
    sys.stdout.buffer.write(Codec(b"z" * 32).encode({"kind": "done", "ok": True}))
    sys.stdout.buffer.flush()

if scenario != "missing":
    for name in bootstrap["outputs"]:
        frame = {
            "kind": "file",
            "name": name,
            "data": base64.b64encode(b"synthetic\n").decode(),
            "regular": True,
            "links": 1,
        }
        if scenario == "unselected":
            frame["name"] = "foreign.txt"
        if scenario == "bytes":
            frame["data"] = base64.b64encode(b"\xff").decode()
        emit(frame)
        if scenario == "duplicate":
            emit(frame)
if scenario == "replay":
    raw = codec.encode({"kind": "stdout", "text": "same"})
    sys.stdout.buffer.write(raw + raw)
    sys.stdout.buffer.flush()
if scenario != "no-done":
    emit({"kind": "done", "ok": True})
if scenario == "after-done":
    emit({"kind": "stdout", "text": "late"})
if scenario == "nonzero":
    raise SystemExit(2)
