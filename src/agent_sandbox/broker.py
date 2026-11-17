# SPDX-License-Identifier: Apache-2.0
# Adapted with changes from Tylenol Taker Python.
"""Explicit async read callbacks, validated as a batch before any side effect."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Awaitable, Callable, Mapping

from .artifacts import Scope
from .docker import settle
from .protocol import ProtocolError, dumps

Tool = Callable[[Scope, dict[str, object]], Awaitable[str]]


class Broker:
    def __init__(self, tools: Mapping[str, Tool], scope: Scope, limit: int = 8):
        self.tools = dict(tools)
        if any(
            not re.fullmatch(r"[a-z][a-z0-9_]{0,39}", n) or not callable(f)
            for n, f in self.tools.items()
        ):
            raise ValueError("Invalid trusted callback registry")
        if type(limit) is not int or not 1 <= limit <= 16:
            raise ValueError("Invalid callback budget")
        self.scope, self.limit, self.used = scope, limit, 0

    async def call(self, frame: dict[str, object]) -> dict[str, object]:
        calls = frame.get("calls")
        if (
            set(frame) != {"kind", "calls"}
            or frame["kind"] != "call"
            or (not isinstance(calls, list) or not 1 <= len(calls) <= 4)
        ):
            raise ProtocolError("Invalid broker batch")
        checked = []
        for call in calls:
            if not isinstance(call, dict) or set(call) != {"name", "args"}:
                raise ProtocolError("Invalid broker call")
            name, args = call["name"], call["args"]
            if not isinstance(name, str) or name not in self.tools:
                raise ProtocolError("Callback denied")
            if not isinstance(args, dict) or len(dumps(args)) > 12000:
                raise ProtocolError("Callback argument limit")
            checked.append((name, args))
        if self.used + len(checked) > self.limit:
            raise ProtocolError("Callback budget exhausted")
        self.used += len(checked)  # No refund, including failures/cancellation.

        async def invoke(name: str, args: dict[str, object]) -> str:
            value = await self.tools[name](self.scope, args)
            if not isinstance(value, str) or len(value.encode()) > 16000:
                raise ProtocolError("Callback result limit")
            return value

        tasks = [asyncio.create_task(invoke(n, a)) for n, a in checked]
        try:
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)
            for task in done:
                task.result()
            results = [task.result() for task in tasks]
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            _, interrupted = await settle(asyncio.gather(*tasks, return_exceptions=True))
            if interrupted:
                raise asyncio.CancelledError
        return {"kind": "result", "results": results}
