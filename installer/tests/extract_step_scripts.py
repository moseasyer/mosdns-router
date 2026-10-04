"""Extract each step's script from a workflow, for syntax and unbound-variable checks.

Writes one file per step into OUTDIR, with GitHub expressions replaced by a literal
X so bash can parse it, and records the env: keys each step declares into
OUTDIR/env.json. That split is the whole point: `env:` is per-STEP in Actions, and
a script that reads a variable a previous step declared is the bug this exists to
find.
"""

import json
import pathlib
import re
import sys

import yaml

EXPRESSION = re.compile(r"\$\{\{[^}]*\}\}")


def main() -> int:
    workflow, outdir = sys.argv[1], pathlib.Path(sys.argv[2])
    outdir.mkdir(parents=True, exist_ok=True)
    doc = yaml.safe_load(workflow.read_text())
    job = list(doc["jobs"].values())[0]
    manifest = {}
    for index, step in enumerate(job["steps"]):
        body = step.get("run")
        if not body:
            continue
        name = re.sub(r"[^a-z0-9]+", "-", str(step.get("name", index)).lower()).strip("-")
        path = outdir / f"{index:02d}-{name}.sh"
        path.write_text(EXPRESSION.sub("X", body))
        manifest[path.name] = sorted(step.get("env", {}))
    (outdir / "env.json").write_text(json.dumps(manifest, indent=1))
    for name, keys in manifest.items():
        print(f"{name}: {keys}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())