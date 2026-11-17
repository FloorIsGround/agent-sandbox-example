# SPDX-License-Identifier: Apache-2.0
# Adapted with changes from Tylenol Taker Python.
"""Bounded immutable in-memory text artifacts; no host filesystem API."""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field

from .protocol import file_name, text_bytes


class ArtifactError(ValueError):
    """Uniform unavailable/quota denial."""


@dataclass(frozen=True)
class Scope:
    """Trusted caller's namespace, NOT authentication or an authorization grant."""

    owner: str
    session: str

    def __post_init__(self) -> None:
        if any(
            not isinstance(v, str) or not 1 <= len(v) <= 128 for v in (self.owner, self.session)
        ):
            raise ArtifactError("Invalid scope")


@dataclass(frozen=True)
class Artifact:
    id: str
    name: str
    data: bytes = field(repr=False)
    kind: str
    expires: float


class ArtifactStore:
    """Single event-loop/thread store with a GLOBAL quota and lazy expiry.

    No persistence, background sweep or disk paths. A fresh store is recommended
    for each trusted application's short-lived session. close() releases bodies.
    """

    def __init__(self, *, ttl: float = 3600, max_bytes: int = 2_000_000, max_files: int = 16):
        if not 0 < ttl <= 86400 or not 1 <= max_bytes <= 16_000_000 or not 1 <= max_files <= 128:
            raise ArtifactError("Invalid quota")
        self.ttl, self.max_bytes, self.max_files = ttl, max_bytes, max_files
        self._items: dict[str, tuple[Scope, Artifact]] = {}
        self._closed = False

    def _prune(self) -> None:
        if self._closed:
            raise ArtifactError("Store closed")
        now = time.monotonic()
        self._items = {k: v for k, v in self._items.items() if v[1].expires > now}

    def _save(self, scope: Scope, rows: list[tuple[str, bytes]], kind: str) -> tuple[Artifact, ...]:
        self._prune()
        if not isinstance(scope, Scope):
            raise ArtifactError("Invalid scope")
        for name, data in rows:
            file_name(name)
            text_bytes(data, 131072 if kind == "input" else 262144)
        if len(self._items) + len(rows) > self.max_files or (
            sum(len(a.data) for _, a in self._items.values()) + sum(len(b) for _, b in rows)
            > self.max_bytes
        ):
            raise ArtifactError("Artifact quota exceeded")
        pending: dict[str, tuple[Scope, Artifact]] = {}
        for name, data in rows:
            ident = "a_" + secrets.token_hex(16)
            if ident in self._items or ident in pending:
                raise ArtifactError("Artifact ID collision")
            pending[ident] = (scope, Artifact(ident, name, data, kind, time.monotonic() + self.ttl))
        self._items.update(pending)  # All outputs become visible together, after cleanup.
        return tuple(a for _, a in pending.values())

    def stage(self, scope: Scope, name: str, data: bytes) -> Artifact:
        """Stage explicitly supplied UTF-8 bytes, never a path/URL."""
        return self._save(scope, [(name, data)], "input")[0]

    def get(self, scope: Scope, ident: str) -> Artifact:
        self._prune()
        row = self._items.get(ident)
        if row is None or row[0] != scope:
            raise ArtifactError("Artifact unavailable")
        return row[1]

    def select(self, scope: Scope, ids: tuple[str, ...]) -> tuple[Artifact, ...]:
        """Explicit outputs for caller-owned delivery; no automatic sending/writing."""
        if not 1 <= len(ids) <= 4 or len(set(ids)) != len(ids):
            raise ArtifactError("Selection denied")
        result = tuple(self.get(scope, ident) for ident in ids)
        if any(a.kind != "output" for a in result) or len({a.name for a in result}) != len(result):
            raise ArtifactError("Selection denied")
        return result

    def close(self) -> None:
        self._items.clear()
        self._closed = True
