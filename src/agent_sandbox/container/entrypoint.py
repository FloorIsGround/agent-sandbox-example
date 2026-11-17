# SPDX-License-Identifier: Apache-2.0
# Adapted with changes from Tylenol Taker Python.
"""Container supervisor owns authenticated stdio; child owns only local RPC."""

import asyncio
import base64
import ctypes
import json
import re
import resource
import sys
from pathlib import Path

sys.path.insert(0, "/opt/agent")
from protocol import MAX_FRAME, Codec, StreamBuffer, loads, selected_bytes, text_bytes  # noqa: E402


async def main():
    if not Path("/opt/agent/CONTAINER_ONLY").is_file() or Path.cwd() != Path("/workspace"):
        raise RuntimeError("Container-only entrypoint")
    # Linux PR_SET_DUMPABLE=0 closes same-uid /proc/1/mem/fd/ptrace access to the key.
    if ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0) != 0:
        raise RuntimeError("Supervisor memory protection unavailable")
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    value = loads(sys.stdin.buffer.readline(MAX_FRAME + 1))
    if set(value) != {"key", "code", "inputs", "outputs"}:
        raise ValueError("Invalid bootstrap")
    codec = Codec(bytes.fromhex(value.pop("key")))
    code = value["code"]
    if not isinstance(code, str) or not 1 <= len(code.encode()) <= 8000:
        raise ValueError("Invalid code")
    if (
        not isinstance(value["inputs"], list)
        or not isinstance(value["outputs"], list)
        or (
            len(value["inputs"]) > 4
            or len(value["outputs"]) > 4
            or len(set(value["outputs"])) != len(value["outputs"])
        )
    ):
        raise ValueError("Invalid file selection")
    Path("inputs").mkdir(mode=0o700)
    Path("out").mkdir(mode=0o700)
    manifest = {}
    for item in value["inputs"]:
        if (
            not isinstance(item, dict)
            or set(item) != {"id", "path", "data"}
            or (
                not re.fullmatch(r"a_[0-9a-f]{32}", item["id"])
                or not re.fullmatch(r"a_[0-9a-f]{32}\.(txt|csv|json)", item["path"])
                or item["id"] in manifest
            )
        ):
            raise ValueError("Unsafe input")
        data = base64.b64decode(item["data"], validate=True)
        text_bytes(data, 131072)
        target = Path("inputs") / item["path"]
        with target.open("xb") as stream:
            stream.write(data)
        target.chmod(0o400)
        manifest[item["id"]] = str(Path("/workspace") / target)
    Path(".inputs.json").write_text(json.dumps(manifest))
    Path("job.py").write_text(code)
    wire, broker = asyncio.Lock(), asyncio.Lock()
    handlers = set()
    failure = asyncio.get_running_loop().create_future()
    active = 0
    requests = 0

    async def emit(frame):
        async with wire:
            sys.stdout.buffer.write(codec.encode(frame))
            sys.stdout.buffer.flush()

    async def rpc(reader, writer):
        nonlocal active, requests
        task = asyncio.current_task()
        handlers.add(task)
        active += 1
        requests += 1
        try:
            if active > 4 or requests > 16:
                raise ValueError("Helper connection limit")
            async with asyncio.timeout(30):
                raw = await reader.readline()
                if len(raw) > 50000 or not raw.endswith(b"\n"):
                    raise ValueError("Helper request limit")
                request = loads(raw)
                if (
                    set(request) != {"kind", "calls"}
                    or request["kind"] != "call"
                    or (
                        not isinstance(request["calls"], list)
                        or not 1 <= len(request["calls"]) <= 4
                    )
                ):
                    raise ValueError("Only callback requests may be signed")
                async with broker:
                    await emit(request)
                    # Dedicated thread owns stdin until reply or container teardown.
                    reply = await asyncio.to_thread(sys.stdin.buffer.readline, MAX_FRAME + 1)
                    response = codec.decode(reply)
                    writer.write(json.dumps(response, ensure_ascii=False).encode() + b"\n")
                    await writer.drain()
        except Exception:
            if not failure.done():
                failure.set_result(True)
        finally:
            active -= 1
            writer.close()
            await writer.wait_closed()
            handlers.discard(task)

    server = await asyncio.start_unix_server(rpc, "/workspace/.rpc", limit=50001, backlog=4)
    process = await asyncio.create_subprocess_exec(
        "/usr/local/bin/python",
        "-I",
        "/opt/agent/launch.py",
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/workspace", "LANG": "C.UTF-8"},
    )
    total = 0

    async def drain(stream, kind):
        nonlocal total
        buffer = StreamBuffer()
        while chunk := await stream.read(4096):
            total += len(chunk)
            if total > 65536:
                raise ValueError("Code stream limit")
            buffer.feed(chunk)
        if buffer.raw:
            await emit({"kind": kind, "text": buffer.text()})

    tasks = [
        asyncio.create_task(drain(process.stdout, "stdout")),
        asyncio.create_task(drain(process.stderr, "stderr")),
        asyncio.create_task(process.wait()),
    ]
    completion = asyncio.gather(*tasks)
    try:
        await asyncio.wait({completion, failure}, return_when=asyncio.FIRST_COMPLETED)
        if failure.done():
            raise ValueError("Helper failed")
        await completion
        server.close()
        await server.wait_closed()
        if handlers or process.returncode != 0:
            raise ValueError("Code failed or pending callbacks")
        for name in value["outputs"]:
            data = selected_bytes(Path("out"), name)
            await emit(
                {
                    "kind": "file",
                    "name": name,
                    "data": base64.b64encode(data).decode(),
                    "regular": True,
                    "links": 1,
                }
            )
        await emit({"kind": "done", "ok": True})
    finally:
        server.close()
        await server.wait_closed()
        for task in list(handlers) + tasks:
            task.cancel()
        if process.returncode is None:
            process.kill()
        await asyncio.gather(*handlers, *tasks, return_exceptions=True)
        await process.wait()
        completion.cancel()
        await asyncio.gather(completion, return_exceptions=True)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except BaseException:
        # Never echo bootstrap, key or raw supervisor errors.
        raise SystemExit(1) from None
