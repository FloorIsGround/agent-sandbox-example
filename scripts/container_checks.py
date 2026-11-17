# SPDX-License-Identifier: Apache-2.0
"""Opt-in real-container controls. No simulated success or global cleanup."""

import argparse
import asyncio
import json
import time

from agent_sandbox import ArtifactStore, CleanupError, Job, Sandbox, Scope
from agent_sandbox.docker import absent, command


async def main(image):
    scope = Scope("synthetic-check-owner", "synthetic-check-session")
    store = ArtifactStore()
    entered = asyncio.Event()

    async def ready(scope, args):
        if args:
            raise ValueError("ready takes no arguments")
        entered.set()
        return "ready"

    sandbox = Sandbox(image, tools={"ready": ready}, store=store)
    driver = sandbox._driver  # Inspection seam, never a model API.
    names = []
    original_spawn = driver.spawn
    original_cleanup = driver.cleanup
    processes = []

    async def spawn(name):
        names.append(name)
        print("OWNED", name, flush=True)
        process = await original_spawn(name)
        processes.append(process)
        return process

    async def cleanup(name):
        try:
            await original_cleanup(name)
        except Exception as exc:
            print("CLEANUP FAILED", name, repr(exc), flush=True)
            raise
        assert absent(await command(["container", "inspect", name]))
        print("ABSENT", name)

    driver.spawn, driver.cleanup = spawn, cleanup

    async def run(code, **kwargs):
        return await sandbox.run(scope, Job(code, outputs=kwargs.pop("outputs", ())), **kwargs)

    async def denied(label, code, **kwargs):
        before = set(store._items)
        try:
            await run(code, **kwargs)
        except CleanupError:
            raise
        except (ValueError, RuntimeError, TimeoutError):
            assert set(store._items) == before
            print("PASS denied", label)
        else:
            raise AssertionError("Expected denial: " + label)

    try:
        source = store.stage(scope, "input.csv", b"value\n2\n3\n")
        result = await sandbox.run(
            scope,
            Job(
                """import csv
from pathlib import Path
from tt_tools import inputs, public_tool
assert public_tool("ready", {}) == "ready"
rows = csv.DictReader(Path(next(iter(inputs().values()))).open())
Path("out/sum.txt").write_text(str(sum(int(r["value"]) for r in rows)) + "\\n")
""",
                inputs=(source.id,),
                outputs=("sum.txt",),
            ),
        )
        assert result.outputs[0].data == b"5\n" and result.calls_used == 1
        # Reuse an opaque scoped output as the next input through the same API.
        reused = await sandbox.run(
            scope,
            Job(
                """from pathlib import Path
from tt_tools import inputs
print(Path(next(iter(inputs().values()))).read_text(), end="")
""",
                inputs=(result.outputs[0].id,),
            ),
        )
        assert reused.stdout == "5\n"
        print("PASS positive broker/CSV/selected artifact/reuse")

        result = await run("""import os, socket
from pathlib import Path
assert os.getuid() == 65534
assert "SYNTHETIC_SECRET" not in os.environ
for family, target in [(socket.AF_INET, "192.0.2.1"), (socket.AF_INET, "127.0.0.1"),
                       (socket.AF_INET, "169.254.169.254"), (socket.AF_INET6, "2001:db8::1")]:
    with socket.socket(family) as s:
        s.settimeout(.1)
        try: s.connect((target, 9))
        except OSError: pass
        else: raise AssertionError("Native network available")
for target in ["/opt/agent/tt_tools.py", "/etc/agent-example-write", "/proc/1/mem", "/proc/1/fd/1"]:
    try: f = open(target, "r+b")
    except OSError: pass
    else: f.close(); raise AssertionError("Trusted path writable/readable")
print("native restrictions verified")
""")
        assert result.stdout == "native restrictions verified\n"
        print("PASS native network/environment/rootfs/proc controls")

        cases = {
            "symlink": "import os;os.symlink('/etc/passwd','out/x.txt')",
            "hardlink": (
                "import os;open('out/x.txt','w').write('x');os.link('out/x.txt','out/y.txt')"
            ),
            "fifo": "import os;os.mkfifo('out/x.txt')",
            "missing": "pass",
            "oversize": "open('out/x.txt','w').write('x'*262145)",
            "archive": "open('out/x.txt','wb').write(b'PK\\x03\\x04archive')",
            "invalid-utf8": "open('out/x.txt','wb').write(b'\\xff')",
        }
        for label, code in cases.items():
            await denied(label, code, outputs=("x.txt",))
        await denied("combined stream", "import sys;print('x'*40000);sys.stderr.write('y'*30000)")
        await denied(
            "private callback", "from tt_tools import public_tool;public_tool('private',{})"
        )
        await denied(
            "nested execution", "from tt_tools import public_tool;public_tool('sandbox_execute',{})"
        )
        await denied(
            "cumulative budget",
            """from tt_tools import public_tool
public_tool("ready", {})
public_tool("ready", {})
""",
            calls=1,
        )
        await denied(
            "helper frame forgery",
            """import socket
s=socket.socket(socket.AF_UNIX);s.connect('/workspace/.rpc')
s.sendall(b'{"kind":"done","ok":true}\\n');s.recv(100)
""",
        )
        await denied("direct stdio forgery", "open('/proc/1/fd/1','wb').write(b'forged\\n')")

        for label, code in {
            "tmpfs": """import errno
count=0
try:
 for n in range(24):
  with open('space'+str(n),'wb') as f:f.write(b'x'*1048576)
  count+=1
except OSError as e:assert e.errno==errno.ENOSPC
assert 1<count<24
print('bounded tmpfs')
""",
            "inodes": """import errno
count=0
try:
 for n in range(300):open('inode'+str(n),'w').close();count+=1
except OSError as e:assert e.errno==errno.ENOSPC
assert 1<count<256
print('bounded inodes')
""",
            "pids": """import os,time,errno
children=[];denied=False
try:
 for n in range(40):
  try:pid=os.fork()
  except OSError as e:assert e.errno==errno.EAGAIN;denied=True;break
  if pid==0:time.sleep(.1);os._exit(0)
  children.append(pid)
finally:
 for pid in children:os.waitpid(pid,0)
assert denied and len(children)<32
print('bounded pids')
""",
        }.items():
            result = await run(code)
            assert result.stdout.startswith("bounded ")
            print("PASS resource", label)
        await denied("memory", "bytearray(300_000_000)")

        for stop in ("cancel", "event", "deadline", "cli-loss"):
            entered.clear()
            event = asyncio.Event()
            start = time.monotonic()
            task = asyncio.create_task(
                run(
                    """import time
from tt_tools import public_tool
public_tool("ready", {})
time.sleep(60)
""",
                    timeout=2 if stop == "deadline" else 10,
                    cancel=event,
                )
            )
            await asyncio.wait_for(entered.wait(), 5)
            inspected = await command(["container", "inspect", names[-1]])
            assert inspected[0] == 0
            info = json.loads(inspected[1])[0]
            host = info["HostConfig"]
            assert info["Image"] == image and info["Config"]["User"] == "65534:65534"
            assert host["NetworkMode"] == "none" and host["ReadonlyRootfs"] and not host["Binds"]
            assert host["Memory"] == host["MemorySwap"] == 268435456
            assert host["NanoCpus"] == 1000000000 and host["PidsLimit"] == 32
            assert "ALL" in host["CapDrop"] and "no-new-privileges" in host["SecurityOpt"]
            assert set(host["Tmpfs"]) == {"/workspace", "/tmp"}
            assert all(m["Type"] == "tmpfs" for m in info["Mounts"])
            print(
                "INSPECT",
                json.dumps(
                    {
                        "name": names[-1],
                        "image": image,
                        "host": {
                            k: host[k]
                            for k in (
                                "NetworkMode",
                                "ReadonlyRootfs",
                                "Memory",
                                "MemorySwap",
                                "NanoCpus",
                                "PidsLimit",
                                "CapDrop",
                                "SecurityOpt",
                                "Tmpfs",
                                "Ulimits",
                            )
                        },
                    }
                ),
            )
            if stop == "cancel":
                task.cancel()
                await asyncio.sleep(0.01)
                task.cancel()
            elif stop == "event":
                event.set()
            elif stop == "cli-loss":
                processes[-1].kill()
            try:
                await task
            except CleanupError:
                raise
            except (asyncio.CancelledError, TimeoutError, ValueError, RuntimeError):
                pass
            else:
                raise AssertionError("Expected lifecycle interruption")
            assert time.monotonic() - start < 8
            print("PASS lifecycle", stop)
        recovered = await run("print('recovered after CLI loss')")
        assert recovered.stdout == "recovered after CLI loss\n"
        print("PASS productive execution after lifecycle failures")
        assert not driver._owned
        assert all(p.returncode is not None for p in processes)
        print("PASS all", len(names), "owned containers absent and attach processes reaped")
    finally:
        store.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    asyncio.run(main(parser.parse_args().image))
