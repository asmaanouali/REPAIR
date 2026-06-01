"""Validate every binder catalog in ``binders/`` against ``schemas/binder.schema.json``.

Exit code 0 when all catalogs validate; 1 otherwise. Prints a per-file verdict.
"""

from __future__ import annotations

import glob
import json
import sys
from pathlib import Path

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = ROOT / "schemas" / "binder.schema.json"


def main() -> int:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    failed = 0
    for path in sorted(glob.glob(str(ROOT / "binders" / "*.yaml"))):
        doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        errors = sorted(validator.iter_errors(doc), key=lambda e: e.path)
        name = Path(path).name
        if not errors:
            print(f"OK    {name}")
            continue
        failed += 1
        print(f"FAIL  {name}")
        for err in errors:
            loc = "/".join(str(p) for p in err.path)
            print(f"        @ {loc or '<root>'}: {err.message}")
    print(f"\n{'-' * 40}\n{failed} catalog(s) failed validation")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
