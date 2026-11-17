# SPDX-License-Identifier: Apache-2.0
import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_sandbox import ArtifactError, ArtifactStore, CleanupError, Job, Sandbox, Scope
from agent_sandbox.broker import Broker
from agent_sandbox.docker import DockerDriver, argv
from agent_sandbox.protocol import (
    MAX_FRAME,
    MAX_FRAMES,
    Codec,
    ProtocolError,
    StreamBuffer,
    file_name,
    loads,
    selected_bytes,
    text_bytes,
)

SCOPE = Scope("synthetic-owner", "synthetic-session")
IMAGE = "sha256:" + "a" * 64


class ProtocolTests(unittest.TestCase):
    def test_authentication_replay_order_and_envelope(self):
        sender = Codec(b"k" * 32)
        frame = sender.encode({"kind": "stdout", "text": "hello"})
        receiver = Codec(b"k" * 32)
        self.assertEqual(receiver.decode(frame)["text"], "hello")
        for raw, codec in [
            (frame, receiver),
            (frame, Codec(b"z" * 32)),
            (sender.encode({}), Codec(b"k" * 32)),
        ]:
            with self.subTest(raw=raw[:30]), self.assertRaises(ProtocolError):
                codec.decode(raw)
        for update in ({"mac": "é"}, {"seq": True}, {"data": []}, {"extra": True}):
            value = {**json.loads(frame), **update}
            with self.subTest(update=update), self.assertRaises(ProtocolError):
                Codec(b"k" * 32).decode(json.dumps(value).encode() + b"\n")

    def test_strict_json_and_wire_bounds(self):
        for raw in (
            b'{"x":1,"x":2}',
            b'{"x":NaN}',
            b'{"x":Infinity}',
            b"[]",
            b"\xff",
            b"{" + b"x" * MAX_FRAME,
        ):
            with self.subTest(raw=raw[:30]), self.assertRaises(ProtocolError):
                loads(raw)
        sender = Codec(b"x" * 32)
        for _ in range(MAX_FRAMES):
            sender.encode({})
        with self.assertRaises(ProtocolError):
            sender.encode({})
        with self.assertRaises(ProtocolError):
            Codec(b"x" * 32).encode({"x": "y" * MAX_FRAME})
        sender = Codec(b"x" * 32)
        with self.assertRaises(ProtocolError):
            for _ in range(8):
                sender.encode({"x": "y" * 800000})

    def test_fragmented_utf8_and_stream_limit(self):
        buffer = StreamBuffer()
        for byte in "a€".encode():
            buffer.feed(bytes([byte]))
        self.assertEqual(buffer.text(), "a€")
        with self.assertRaises(ProtocolError):
            buffer.feed(b"x" * 65536)
        buffer = StreamBuffer()
        buffer.feed(b"\xff")
        with self.assertRaises(ProtocolError):
            buffer.text()

    def test_selected_names_bytes_and_real_file_types(self):
        for name in ("../x.txt", "/etc/passwd", "a/b.csv", ".x.txt", "x.zip", "x..txt"):
            with self.subTest(name=name), self.assertRaises(ProtocolError):
                file_name(name)
        for data in (
            b"\xff",
            b"\0",
            b"PK\x03\x04z",
            b"\x1f\x8bz",
            b"x" * 257 + b"ustar",
            b"x" * 262145,
        ):
            with self.subTest(size=len(data)), self.assertRaises(ProtocolError):
                text_bytes(data, 262144)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "x.txt").write_bytes(b"safe")
            self.assertEqual(selected_bytes(root, "x.txt"), b"safe")
            (root / "sym.txt").symlink_to(root / "x.txt")
            os.link(root / "x.txt", root / "hard.txt")
            os.mkfifo(root / "pipe.txt")
            (root / "dir.txt").mkdir()
            for name in ("sym.txt", "x.txt", "pipe.txt", "dir.txt", "missing.txt"):
                with self.subTest(name=name), self.assertRaises((ValueError, OSError)):
                    selected_bytes(root, name)


class ArtifactTests(unittest.TestCase):
    def test_scope_expiry_quota_collision_and_selection(self):
        store = ArtifactStore(max_files=3)
        item = store.stage(SCOPE, "x.txt", b"example")
        self.assertIs(store.get(SCOPE, item.id), item)
        with self.assertRaises(ArtifactError):
            store.get(Scope("other", SCOPE.session), item.id)
        with self.assertRaises(ArtifactError):
            store.select(SCOPE, (item.id,))
        with patch("agent_sandbox.artifacts.secrets.token_hex", return_value=item.id[2:]):
            with self.assertRaises(ArtifactError):
                store.stage(SCOPE, "other.txt", b"replace")
        self.assertEqual(store.get(SCOPE, item.id).data, b"example")
        with patch("agent_sandbox.artifacts.time.monotonic", return_value=item.expires + 1):
            with self.assertRaises(ArtifactError):
                store.get(SCOPE, item.id)
        result = store._save(SCOPE, [("out.txt", b"42")], "output")
        self.assertEqual(store.select(SCOPE, (result[0].id,)), result)
        store.close()
        with self.assertRaises(ArtifactError):
            store.get(SCOPE, result[0].id)

    def test_atomic_global_quota_and_input_byte_bounds(self):
        store = ArtifactStore(max_bytes=6, max_files=2)
        item = store.stage(SCOPE, "x.txt", b"abc")
        with self.assertRaises(ArtifactError):
            store._save(SCOPE, [("a.txt", b"ab"), ("b.txt", b"cd")], "output")
        self.assertEqual(len(store._items), 1)
        with self.assertRaises(ArtifactError):
            store.stage(Scope("other", "s"), "x.txt", b"1234")
        self.assertEqual(store.get(SCOPE, item.id).data, b"abc")
        with self.assertRaises(ProtocolError):
            ArtifactStore().stage(SCOPE, "big.csv", b"x" * 131073)


class BrokerTests(unittest.IsolatedAsyncioTestCase):
    async def test_batch_prevalidation_budget_parallel_order_and_scope(self):
        reached, barrier = [], asyncio.Event()

        async def tool(scope, args):
            self.assertEqual(scope, SCOPE)
            reached.append(args["n"])
            if len(reached) == 2:
                barrier.set()
            await barrier.wait()
            return str(args["n"])

        broker = Broker({"catalog": tool}, SCOPE, 2)
        good = {"name": "catalog", "args": {"n": 1}}
        for bad in (
            {"name": "private", "args": {}},
            {"name": "catalog", "args": []},
            {"name": "catalog", "args": {}, "scope": "other"},
        ):
            with self.assertRaises(ProtocolError):
                await broker.call({"kind": "call", "calls": [good, bad]})
        self.assertEqual(reached, [])
        reply = await asyncio.wait_for(
            broker.call({"kind": "call", "calls": [good, {"name": "catalog", "args": {"n": 2}}]}), 1
        )
        self.assertEqual(reply["results"], ["1", "2"])
        with self.assertRaises(ProtocolError):
            await broker.call({"kind": "call", "calls": [good]})

    async def test_cancel_joins_callbacks_and_result_bound(self):
        entered, stopped = asyncio.Event(), asyncio.Event()

        async def tool(scope, args):
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                stopped.set()

        broker = Broker({"catalog": tool}, SCOPE)
        frame = {"kind": "call", "calls": [{"name": "catalog", "args": {}}]}
        task = asyncio.create_task(broker.call(frame))
        await entered.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(stopped.is_set())
        self.assertEqual(broker.used, 1)

        async def too_big(scope, args):
            return "€" * 5334

        with self.assertRaises(ProtocolError):
            await Broker({"catalog": too_big}, SCOPE).call(frame)


class PeerDriver:
    def __init__(self, scenario, *, release=None, failure=False):
        self.scenario, self.release, self.failure = scenario, release, failure
        self.names, self.cleaned, self.processes = [], [], []
        self.started, self.cleaning = asyncio.Event(), asyncio.Event()

    async def spawn(self, name):
        self.names.append(name)
        process = await asyncio.create_subprocess_exec(
            os.sys.executable,
            str(Path(__file__).with_name("fixture_peer.py")),
            self.scenario,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=MAX_FRAME + 1,
            env={"PATH": os.defpath},
        )
        self.processes.append(process)
        self.started.set()
        return process

    async def cleanup(self, name):
        self.cleaning.set()
        if self.release:
            await self.release.wait()
        self.cleaned.append(name)
        if self.failure:
            raise RuntimeError("synthetic cleanup failure")


def sandbox_with_peer(scenario, **kwargs):
    async def catalog(scope, args):
        return "synthetic"

    sandbox = Sandbox(IMAGE, tools={"catalog": catalog}, store=ArtifactStore())
    peer = PeerDriver(scenario, **kwargs)
    sandbox._driver = peer
    return sandbox, peer


class LifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_cancel_during_spawn_retains_returned_process(self):
        sandbox, peer = sandbox_with_peer("wait")
        entered, release = asyncio.Event(), asyncio.Event()
        spawn = peer.spawn

        async def slow_spawn(name):
            entered.set()
            await release.wait()
            return await spawn(name)

        peer.spawn = slow_spawn
        task = asyncio.create_task(sandbox.run(SCOPE, Job("ignored")))
        await entered.wait()
        task.cancel()
        await asyncio.sleep(0.01)
        task.cancel()
        self.assertFalse(task.done())
        release.set()
        with self.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(task, 2)
        self.assertEqual(peer.names, peer.cleaned)
        self.assertIsNotNone(peer.processes[0].returncode)

    async def test_cancellation_joins_broker_child_before_driver_cleanup(self):
        sandbox, peer = sandbox_with_peer("broker")
        entered, stopping, release = asyncio.Event(), asyncio.Event(), asyncio.Event()

        async def slow_callback(scope, args):
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                stopping.set()
                await release.wait()

        sandbox._tools = {"catalog": slow_callback}
        task = asyncio.create_task(sandbox.run(SCOPE, Job("ignored")))
        await entered.wait()
        task.cancel()
        await stopping.wait()
        task.cancel()
        await asyncio.sleep(0.01)
        self.assertFalse(task.done())
        self.assertFalse(peer.cleaning.is_set())
        release.set()
        with self.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(task, 2)
        self.assertEqual(peer.names, peer.cleaned)

    async def test_owned_ipc_broker_and_artifacts_positive(self):
        sandbox, peer = sandbox_with_peer("broker")
        result = await sandbox.run(SCOPE, Job("ignored by fixed peer", outputs=("result.txt",)))
        self.assertEqual(result.outputs[0].data, b"synthetic\n")
        self.assertEqual(result.calls_used, 1)
        self.assertEqual(peer.names, peer.cleaned)
        self.assertIsNotNone(peer.processes[0].returncode)

    async def test_protocol_failures_cleanup_and_publish_nothing(self):
        for scenario in (
            "private",
            "stderr",
            "overflow",
            "invalid-mac",
            "missing",
            "unselected",
            "bytes",
            "duplicate",
            "replay",
            "no-done",
            "after-done",
            "nonzero",
        ):
            with self.subTest(scenario=scenario):
                sandbox, peer = sandbox_with_peer(scenario)
                with self.assertRaises((ValueError, RuntimeError)):
                    await sandbox.run(SCOPE, Job("ignored", outputs=("result.txt",)))
                self.assertEqual(peer.names, peer.cleaned)
                self.assertTrue(all(p.returncode is not None for p in peer.processes))
                self.assertEqual(sandbox.store._items, {})

    async def test_repeated_cancel_event_and_deadline_join_cleanup(self):
        for stop in ("cancel", "event", "deadline"):
            with self.subTest(stop=stop):
                release, event = asyncio.Event(), asyncio.Event()
                sandbox, peer = sandbox_with_peer("wait", release=release)
                task = asyncio.create_task(
                    sandbox.run(
                        SCOPE,
                        Job("ignored"),
                        cancel=event,
                        timeout=0.1 if stop == "deadline" else 5,
                    )
                )
                await peer.started.wait()
                if stop == "event":
                    event.set()
                elif stop == "cancel":
                    task.cancel()
                await asyncio.wait_for(peer.cleaning.wait(), 1)
                task.cancel()
                await asyncio.sleep(0.01)
                task.cancel()
                self.assertFalse(task.done())
                self.assertEqual(sandbox.store._items, {})
                release.set()
                with self.assertRaises((asyncio.CancelledError, TimeoutError)):
                    await asyncio.wait_for(task, 2)
                self.assertEqual(peer.names, peer.cleaned)
                self.assertIsNotNone(peer.processes[0].returncode)

    async def test_cleanup_failure_suppresses_completed_outputs(self):
        sandbox, peer = sandbox_with_peer("success", failure=True)
        with self.assertRaises(CleanupError):
            await sandbox.run(SCOPE, Job("ignored", outputs=("result.txt",)))
        self.assertEqual(sandbox.store._items, {})
        self.assertIsNotNone(peer.processes[0].returncode)

    async def test_preflight_scope_and_cancellation_no_spawn(self):
        sandbox, peer = sandbox_with_peer("success")
        item = sandbox.store.stage(SCOPE, "x.txt", b"abc")
        with self.assertRaises(ArtifactError):
            await sandbox.run(Scope("other", "session"), Job("ignored", inputs=(item.id,)))
        event = asyncio.Event()
        event.set()
        with self.assertRaises(asyncio.CancelledError):
            await sandbox.run(SCOPE, Job("ignored"), cancel=event)
        self.assertEqual(peer.names, [])


class DockerTests(unittest.IsolatedAsyncioTestCase):
    def test_closed_profile(self):
        args = argv(IMAGE, "agent-example-" + "b" * 32)
        for flag in (
            "--network=none",
            "--read-only",
            "--pull=never",
            "--cap-drop=ALL",
            "--memory=256m",
            "--memory-swap=256m",
            "--pids-limit=32",
        ):
            self.assertIn(flag, args)
        self.assertFalse(set(args) & {"-v", "--volume", "--privileged", "--network=host", "--env"})
        for image, name in (("latest", "agent-example-" + "b" * 32), (IMAGE, "unowned")):
            with self.assertRaises(ValueError):
                argv(image, name)

    async def test_cleanup_requires_local_ownership_and_matching_labels(self):
        driver = DockerDriver(IMAGE)
        name = "agent-example-" + "c" * 32
        with self.assertRaises(CleanupError):
            await driver.cleanup(name)
        driver._owned.add(name)
        with patch("agent_sandbox.docker.command", return_value=(0, b"{}", b"")) as command:
            with self.assertRaises(CleanupError):
                await driver.cleanup(name)
            self.assertEqual(command.await_count, 1)
        labels = json.dumps({"agent-sandbox-example": "true", "agent-example-owner": name}).encode()
        with patch(
            "agent_sandbox.docker.command",
            side_effect=[(0, labels, b""), (0, b"", b""), (1, b"", b"daemon unavailable")],
        ):
            with self.assertRaises(CleanupError):
                await driver.cleanup(name)
        with patch(
            "agent_sandbox.docker.command",
            side_effect=[
                (0, labels, b""),
                (1, b"", b"No such container"),
                (0, labels, b""),  # --rm daemon removal is still in progress.
                (1, b"", b"No such container"),
            ],
        ):
            await driver.cleanup(name)
        self.assertNotIn(name, driver._owned)
