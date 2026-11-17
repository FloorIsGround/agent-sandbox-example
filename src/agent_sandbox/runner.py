# SPDX-License-Identifier: Apache-2.0
# Adapted with changes from Tylenol Taker Python.
"""Reusable request-scoped broker/file lifecycle. Code is only run in Docker."""

from __future__ import annotations

import asyncio
import base64
import secrets
from collections.abc import Mapping
from dataclasses import dataclass

from .artifacts import Artifact, ArtifactStore, Scope
from .broker import Broker, Tool
from .docker import CleanupError, DockerDriver, reap, settle
from .protocol import MAX_FRAME, Codec, ProtocolError, dumps, file_name, text_bytes


@dataclass(frozen=True)
class Job:
    code: str
    inputs: tuple[str, ...] = ()
    outputs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            not isinstance(self.code, str)
            or not self.code.strip()
            or len(self.code.encode()) > 8000
        ):
            raise ValueError("Code must contain 1..8000 UTF-8 bytes")
        for rows in (self.inputs, self.outputs):
            if not isinstance(rows, tuple) or len(rows) > 4 or len(set(rows)) != len(rows):
                raise ValueError("Select at most four distinct files")
        for name in self.outputs:
            file_name(name)


@dataclass(frozen=True)
class Result:
    stdout: str
    stderr: str
    outputs: tuple[Artifact, ...]
    calls_used: int


class Sandbox:
    """Trusted operator binds the image, callbacks and store once.

    Do not expose this constructor or Scope selection as model tool arguments.
    The host application authenticates users and authorizes callbacks separately.
    """

    def __init__(self, image_id: str, *, tools: Mapping[str, Tool], store: ArtifactStore):
        self._driver = DockerDriver(image_id)
        self._tools = dict(tools)
        self.store = store
        Broker(self._tools, Scope("validation", "validation"))
        self._busy = False

    async def run(
        self,
        scope: Scope,
        job: Job,
        *,
        timeout: float = 30,
        calls: int = 8,
        cancel: asyncio.Event | None = None,
    ) -> Result:
        if not 0 < timeout <= 30 or not isinstance(scope, Scope) or not isinstance(job, Job):
            raise ValueError("Invalid request/deadline")
        if self._busy:
            raise ValueError("One execution at a time per Sandbox instance")
        broker = Broker(self._tools, scope, calls)
        inputs = []
        for ident in job.inputs:
            item = self.store.get(scope, ident)
            text_bytes(item.data, 131072)
            inputs.append(
                {
                    "id": ident,
                    "path": ident + "." + item.name.rsplit(".", 1)[1],
                    "data": base64.b64encode(item.data).decode(),
                }
            )
        key = secrets.token_bytes(32)
        bootstrap = (
            dumps(
                {"key": key.hex(), "code": job.code, "inputs": inputs, "outputs": list(job.outputs)}
            )
            + b"\n"
        )
        if len(bootstrap) > MAX_FRAME:
            raise ProtocolError("Bootstrap limit")
        if cancel is not None and cancel.is_set():
            raise asyncio.CancelledError
        name = "agent-example-" + secrets.token_hex(16)
        codec = Codec(key)
        process: asyncio.subprocess.Process | None = None
        attempted = False
        exports: dict[str, bytes] = {}
        streams: dict[str, list[str]] = {"stdout": [], "stderr": []}
        total = 0

        async def execute() -> None:
            nonlocal process, total, attempted
            attempted = True
            spawn = asyncio.create_task(self._driver.spawn(name))
            process, interrupted = await settle(spawn)
            if interrupted:
                raise asyncio.CancelledError
            assert process.stdin and process.stdout and process.stderr
            process.stdin.write(bootstrap)
            await process.stdin.drain()

            async def errors() -> None:
                count = 0
                assert process and process.stderr
                while chunk := await process.stderr.read(4096):
                    count += len(chunk)
                    if count > 16384:
                        raise ProtocolError("Process stderr limit")

            async def frames() -> None:
                nonlocal total
                assert process and process.stdout and process.stdin
                done = False
                while raw := await process.stdout.readline():
                    if done:
                        raise ProtocolError("Frame after completion")
                    frame = codec.decode(raw)
                    kind = frame.get("kind")
                    if kind == "call":
                        process.stdin.write(codec.encode(await broker.call(frame)))
                        await process.stdin.drain()
                    elif kind in ("stdout", "stderr"):
                        if set(frame) != {"kind", "text"} or not isinstance(frame["text"], str):
                            raise ProtocolError("Invalid stream")
                        total += len(frame["text"].encode())
                        if total > 65536:
                            raise ProtocolError("Stream limit")
                        streams[kind].append(frame["text"])
                    elif kind == "file":
                        if set(frame) != {"kind", "name", "data", "regular", "links"}:
                            raise ProtocolError("Invalid file frame")
                        filename = file_name(frame["name"])
                        encoded = frame["data"]
                        if (
                            filename not in job.outputs
                            or filename in exports
                            or (
                                frame["regular"] is not True
                                or type(frame["links"]) is not int
                                or frame["links"] != 1
                                or not isinstance(encoded, str)
                                or len(encoded) > 4 * ((262144 + 2) // 3)
                            )
                        ):
                            raise ProtocolError("Unselected/unsafe file")
                        data = base64.b64decode(encoded, validate=True)
                        text_bytes(data, 262144)
                        exports[filename] = data
                    elif kind == "done":
                        if set(frame) != {"kind", "ok"} or frame["ok"] is not True:
                            raise ProtocolError("Execution failed")
                        done = True
                    else:
                        raise ProtocolError("Unknown frame kind")
                if not done or set(exports) != set(job.outputs) or await process.wait() != 0:
                    raise ProtocolError("Incomplete execution")

            tasks = [asyncio.create_task(errors()), asyncio.create_task(frames())]
            try:
                done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)
                for task in done:
                    task.result()
            finally:
                for task in tasks:
                    if not task.done():
                        task.cancel()
                # This whole execute task is itself retained by the outer owner.
                _, interrupted = await settle(asyncio.gather(*tasks, return_exceptions=True))
                if interrupted:
                    raise asyncio.CancelledError

        async def cleanup() -> None:
            if process and process.stdin:
                process.stdin.close()
            if process and process.returncode is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
            try:
                # Docker daemon owns containers independently of the CLI process.
                if attempted:
                    await self._driver.cleanup(name)
            finally:
                if process:
                    await reap(process)

        self._busy = True
        execution = asyncio.create_task(execute())
        abort = asyncio.create_task(cancel.wait()) if cancel is not None else None
        interrupted = False
        try:
            try:
                async with asyncio.timeout(timeout):
                    wait_for = {execution} | ({abort} if abort else set())
                    await asyncio.wait(wait_for, return_when=asyncio.FIRST_COMPLETED)
                    if abort and abort.done():
                        raise asyncio.CancelledError
                    execution.result()
            finally:
                if abort:
                    abort.cancel()
                execution.cancel()
                # Wait for callbacks and a possibly in-flight spawn to settle first.
                try:
                    _, interrupted = await settle(execution)
                except BaseException:
                    pass  # Original result/error is propagated after owned cleanup.
                if abort:
                    await settle(asyncio.gather(abort, return_exceptions=True))
                try:
                    _, cleanup_cancelled = await settle(asyncio.create_task(cleanup()))
                    interrupted |= cleanup_cancelled
                except Exception:
                    raise CleanupError(
                        "Execution cleanup could not be verified; outputs suppressed"
                    ) from None
                if interrupted:
                    raise asyncio.CancelledError
            if cancel is not None and cancel.is_set():
                raise asyncio.CancelledError
            artifacts = self.store._save(scope, [(n, exports[n]) for n in job.outputs], "output")
            return Result(
                "".join(streams["stdout"]), "".join(streams["stderr"]), artifacts, broker.used
            )
        finally:
            self._busy = False
