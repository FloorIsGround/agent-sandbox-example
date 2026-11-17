# SPDX-License-Identifier: Apache-2.0
# Adapted with changes from Tylenol Taker Python.
"""Fixed Docker profile and exact, label-checked cleanup. No global sweeps."""

from __future__ import annotations

import asyncio
import json
import re

from .protocol import MAX_FRAME

ENV = {
    "PATH": "/usr/bin:/bin",
    "HOME": "/nonexistent",
    "DOCKER_CONFIG": "/nonexistent",
    "LANG": "C",
}


class CleanupError(RuntimeError):
    """Absence/reaping could not be verified. Outputs are suppressed."""


async def settle[T](task: asyncio.Future[T]) -> tuple[T, bool]:
    """Retain ownership through repeated cancellation; report deferred interruption."""
    interrupted = False
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            interrupted = True
        except Exception:
            break
    return task.result(), interrupted


def owned_name(name: str) -> None:
    if not re.fullmatch(r"agent-example-[0-9a-f]{32}", name):
        raise ValueError("Invalid owned execution name")


def argv(image: str, name: str) -> list[str]:
    owned_name(name)
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise ValueError("An operator-approved local immutable image ID is required")
    return [
        "/usr/bin/docker",
        "create",
        "-i",
        "--rm",
        "--pull=never",
        "--name",
        name,
        "--label=agent-sandbox-example=true",
        f"--label=agent-example-owner={name}",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user=65534:65534",
        "--memory=256m",
        "--memory-swap=256m",
        "--cpus=1",
        "--pids-limit=32",
        "--ulimit=fsize=1048576:1048576",
        "--ulimit=nofile=64:64",
        "--tmpfs=/workspace:rw,nosuid,nodev,noexec,size=16m,nr_inodes=256,mode=0700,uid=65534,gid=65534",
        "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=8m,nr_inodes=128,mode=0700,uid=65534,gid=65534",
        "--workdir=/workspace",
        "--entrypoint=/usr/local/bin/python",
        image,
        "-I",
        "/opt/agent/entrypoint.py",
    ]


async def reap(process: asyncio.subprocess.Process) -> None:
    if process.stdin:
        process.stdin.close()
    if process.returncode is None:
        try:
            process.kill()
        except ProcessLookupError:
            pass

    async def discard(stream: asyncio.StreamReader | None) -> None:
        if stream:
            while await stream.read(8192):
                pass

    async with asyncio.timeout(5):
        await asyncio.gather(discard(process.stdout), discard(process.stderr), process.wait())


async def command(args: list[str]) -> tuple[int, bytes, bytes]:
    """Bounded CLI subprocess with empty environment and cancellation-safe reaping."""
    spawn = asyncio.create_task(
        asyncio.create_subprocess_exec(
            "/usr/bin/docker",
            *args,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=ENV,
        )
    )
    process, interrupted = await settle(spawn)
    total = 0

    async def read(stream: asyncio.StreamReader | None) -> bytes:
        nonlocal total
        assert stream is not None
        output = bytearray()
        while chunk := await stream.read(4096):
            total += len(chunk)
            if total > 65536:
                raise CleanupError("Docker control output limit")
            output.extend(chunk)
        return bytes(output)

    async def collect() -> tuple[bytes, bytes]:
        tasks = [asyncio.create_task(read(s)) for s in (process.stdout, process.stderr)]
        try:
            a, b = await asyncio.gather(*tasks)
            await process.wait()
            return a, b
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    try:
        if interrupted:
            raise asyncio.CancelledError
        async with asyncio.timeout(3):
            out, err = await collect()
        assert process.returncode is not None
        return process.returncode, out, err
    finally:
        _, cancelled = await settle(asyncio.create_task(reap(process)))
        if cancelled:
            raise asyncio.CancelledError


def absent(result: tuple[int, bytes, bytes]) -> bool:
    status, _, err = result
    return status == 1 and (b"no such container" in err.lower() or b"no such object" in err.lower())


class DockerDriver:
    def __init__(self, image: str):
        argv(image, "agent-example-" + "0" * 32)
        self.image = image
        self._owned: set[str] = set()

    async def spawn(self, name: str) -> asyncio.subprocess.Process:
        self._owned.add(name)
        # Complete creation BEFORE starting the attach process. Cancellation of
        # an attached CLI cannot race a not-yet-submitted container creation.
        created = await command(argv(self.image, name)[1:])
        if created[0] != 0:
            raise RuntimeError("Container creation failed")
        return await asyncio.create_subprocess_exec(
            "/usr/bin/docker",
            "start",
            "-ai",
            name,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=MAX_FRAME + 1,
            env=ENV,
        )

    async def cleanup(self, name: str) -> None:
        owned_name(name)
        if name not in self._owned:
            raise CleanupError("Unowned container cleanup denied")
        inspect = ["container", "inspect", "--format", "{{json .Config.Labels}}", name]
        result = await command(inspect)
        if absent(result):
            self._owned.remove(name)
            return
        if result[0] != 0:
            raise CleanupError("Could not inspect owned container")
        labels = json.loads(result[1])
        if (
            labels.get("agent-sandbox-example") != "true"
            or labels.get("agent-example-owner") != name
        ):
            raise CleanupError("Container ownership mismatch")
        # A nonzero rm is acceptable ONLY when subsequent absence is verified.
        await command(["container", "rm", "-f", name])
        # --rm may have started daemon removal before our exact rm. An inspect
        # can briefly still succeed; wait boundedly for confirmed absence.
        async with asyncio.timeout(3):
            while True:
                result = await command(inspect)
                if absent(result):
                    break
                if result[0] != 0 or json.loads(result[1]) != labels:
                    raise CleanupError("Container absence could not be verified")
                await asyncio.sleep(0.05)
        self._owned.remove(name)
