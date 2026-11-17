# SPDX-License-Identifier: Apache-2.0
"""Two synthetic tasks through the same API, without model/provider calls."""

import argparse
import asyncio
import json

from agent_sandbox import ArtifactStore, Job, Sandbox, Scope

CATALOG = {"apple": 3, "pear": 5}


async def catalog(scope, args):
    if set(args) != {"item"} or args["item"] not in CATALOG:
        raise ValueError("Unknown synthetic catalog item")
    return json.dumps({"price": CATALOG[args["item"]]})


async def main(image):
    store = ArtifactStore()
    scope = Scope("synthetic-owner", "synthetic-session")
    sandbox = Sandbox(image, tools={"catalog": catalog}, store=store)
    try:
        csv = store.stage(scope, "orders.csv", b"item,quantity\napple,2\npear,4\n")
        first = await sandbox.run(
            scope,
            Job(
                """import csv, json
from pathlib import Path
from tt_tools import inputs, parallel
rows = list(csv.DictReader(Path(next(iter(inputs().values()))).open()))
prices = parallel([{"name":"catalog", "args":{"item":r["item"]}} for r in rows])
total = sum(int(r["quantity"]) * json.loads(p)["price"] for r, p in zip(rows, prices))
Path("out/total.txt").write_text(str(total) + "\\n")
print("Synthetic order total:", total)
""",
                inputs=(csv.id,),
                outputs=("total.txt",),
            ),
        )
        text = store.stage(scope, "words.txt", b"red blue red green blue red\n")
        second = await sandbox.run(
            scope,
            Job(
                """import json
from collections import Counter
from pathlib import Path
from tt_tools import inputs
counts = Counter(Path(next(iter(inputs().values()))).read_text().split())
Path("out/counts.json").write_text(json.dumps(dict(sorted(counts.items()))) + "\\n")
print("Synthetic word count:", sum(counts.values()))
""",
                inputs=(text.id,),
                outputs=("counts.json",),
            ),
        )
        for result in (first, second):
            print(result.stdout, end="")
            for artifact in store.select(scope, tuple(a.id for a in result.outputs)):
                print(artifact.name + ": " + artifact.data.decode().strip())
        assert first.outputs[0].data == b"26\n"
        assert json.loads(second.outputs[0].data) == {"blue": 2, "green": 1, "red": 3}
    finally:
        store.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="Operator-approved built image ID")
    asyncio.run(main(parser.parse_args().image))
