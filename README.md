# Programmatic agent sandbox example

A small async Python API for Python jobs in an operator-approved Docker image.
Jobs can call explicitly registered host read callbacks and return selected
UTF-8 text, CSV or JSON artifacts. The host never evaluates job code. Two
synthetic tasks use the same API; no model account or external service is needed.

Requires Linux, Python 3.12+, Docker Engine with cgroup memory/CPU/PID limits,
default seccomp, and access to the local Unix Docker socket. Docker access is
powerful host authority: keep it with the trusted application. See [SECURITY.md](SECURITY.md).

## Install and verify

```sh
uv sync --offline
uv run scripts/check.sh
```

The package has no runtime dependencies. Offline setup requires the build
dependency `setuptools==80.10.2` already cached. For ordinary installation in a
fresh environment use `python -m pip install .` (which may obtain build tools).
The checks use disposable memory stores and fixed IPC fixture programs. They
never evaluate a supplied job on the host and do not require Docker.

## Build the container and run both tasks

Review an existing local Python 3.12+ slim image (including its environment,
volumes and entrypoint). Set `BASE_ID` to its immutable `sha256:...` ID. The
builder copies only six named package assets into a temporary context; it
performs no image pull, downloads, network access in build steps, or host mounts.
It requires Docker's legacy builder, selected only for that subprocess; no daemon
configuration changes are made. Hosts without it need a reviewed offline recipe.
The base must have `/usr/local/bin/python`, stdlib ctypes/resource/asyncio, a
working nobody user, no declared volumes, and no embedded secrets.

```sh
BASE_ID=sha256:REPLACE_WITH_REVIEWED_LOCAL_BASE_IMAGE_ID
uv run python -m agent_sandbox.build_image --base "$BASE_ID"
# The builder prints the new immutable image ID. Review it, then set:
IMAGE_ID=sha256:REPLACE_WITH_BUILT_IMAGE_ID
uv run python examples/two_tasks.py --image "$IMAGE_ID"
uv run python scripts/container_checks.py --image "$IMAGE_ID"
```

Expected example outputs: `total.txt` contains `26\n`; `counts.json` contains
`{"blue": 2, "green": 1, "red": 3}`. The first job calls a synthetic catalog
twice; the second counts words in a supplied text artifact. This is actual
container execution with native networking disabled. Container checks exercise
positive execution, broker/path/byte denials, inspected restrictions, cancellation,
deadline, CLI loss and exact owned absence. An unavailable Docker engine or image
is a failed prerequisite, never a simulated pass.

## API

```python
import asyncio
from agent_sandbox import ArtifactStore, Job, Sandbox, Scope

async def catalog(scope, args):
    if args != {"item": "apple"}:
        raise ValueError("item denied")
    return '{"price":3}'

async def transform(image_id):
    store = ArtifactStore()
    scope = Scope("synthetic-owner", "synthetic-session")
    runner = Sandbox(image_id, tools={"catalog": catalog}, store=store)
    try:
        source = store.stage(scope, "input.txt", b"hello\n")
        result = await runner.run(scope, Job('''from pathlib import Path
from tt_tools import inputs, public_tool
text = Path(next(iter(inputs().values()))).read_text()
price = public_tool("catalog", {"item":"apple"})
Path("out/result.txt").write_text(text + price + "\\n")
''', inputs=(source.id,), outputs=("result.txt",)), timeout=10, calls=2)
        return store.select(scope, tuple(a.id for a in result.outputs))[0].data
    finally:
        store.close()

# asyncio.run(transform(OPERATOR_APPROVED_IMAGE_ID))
```

`Scope` is a caller-supplied namespace, **not authentication**. The host must
authenticate users and construct it from trusted identity/session state. The
constructor, image, callbacks and store are operator authority; expose only
validated `Job` data to an untrusted caller. Callback arguments remain untrusted:
each registered async callback must validate its own schema and access policy.
Use read-only, local bounded callbacks; do not register general file, shell,
network, provider, nested sandbox or credential APIs.

`tt_tools.parallel` accepts up to four calls in input order; the per-run budget
is cumulative across batches. `cancel=asyncio.Event()` or task cancellation
interrupts the job. Cleanup waits through repeated cancellation and verifies
container absence before returning outputs. `CleanupError` means verification
failed; no result artifacts are committed. Callback coroutines must cooperate
with cancellation. One run per `Sandbox` instance is allowed at a time.

The in-memory store has a global file/byte quota, lazy expiry using a monotonic
clock, atomic output batches and explicit selection. An output artifact can be
selected as a later input when it fits the smaller input limit. No stores,
attachments or automatic exports are written to host disk. `close()` releases
retained bodies. See the precise limits and failure model in SECURITY.md.

## License

[Apache-2.0](LICENSE). See [NOTICE](NOTICE) for attribution.
Container base images are supplied by the operator under their own licenses.
