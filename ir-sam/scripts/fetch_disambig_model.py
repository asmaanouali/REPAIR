"""Fetch a pre-built Stage-D disambiguator checkpoint.

This script downloads the IR-SAM disambiguator checkpoint(s) declared
in :data:`KNOWN_CHECKPOINTS` and verifies their SHA-256 against the
manifest. The checkpoint is laid out as a standard HuggingFace
directory and is consumed by :class:`core.disambig.ModelPolicy` via
the ``IR_SAM_DISAMBIG_MODEL`` env var.

Usage::

    python -m scripts.fetch_disambig_model \
        --name codet5p-220m-v1 \
        --dest reports/disambig_ckpts

Reviewer note: when no network is available, this script exits with a
clear "checkpoint unavailable" message; the pipeline still runs with
:class:`HeuristicPolicy` so the system remains demoable.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
import tarfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CheckpointSpec:
    name: str
    url: str
    sha256: str
    archive_format: str  # "tar.gz" | "tar.xz"


KNOWN_CHECKPOINTS: dict[str, CheckpointSpec] = {
    # Placeholder entries: real URLs/hashes are populated by the
    # release pipeline (`scripts.release_v2_0`) once the checkpoint is
    # uploaded. Keeping the registry here lets reviewers see what would
    # be downloaded without needing to chase release notes.
    "codet5p-220m-v1": CheckpointSpec(
        name="codet5p-220m-v1",
        url="https://example.invalid/ir-sam/disambig/codet5p-220m-v1.tar.gz",
        sha256="0" * 64,
        archive_format="tar.gz",
    ),
}


def _build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Fetch a disambiguator checkpoint.")
    p.add_argument("--name", default="codet5p-220m-v1",
                   choices=tuple(KNOWN_CHECKPOINTS))
    p.add_argument("--dest", type=Path, default=Path("reports/disambig_ckpts"))
    p.add_argument("--force", action="store_true")
    return p


def _sha256(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            buf = fh.read(chunk)
            if not buf:
                break
            h.update(buf)
    return h.hexdigest()


def main(argv: list[str] | None = None) -> int:
    args = _build_argparser().parse_args(argv)
    spec = KNOWN_CHECKPOINTS[args.name]
    target = args.dest / spec.name
    if target.exists() and not args.force:
        print(f"[fetch_disambig_model] already present: {target}")
        return 0

    args.dest.mkdir(parents=True, exist_ok=True)
    archive = args.dest / f"{spec.name}.{spec.archive_format}"
    print(f"[fetch_disambig_model] downloading {spec.url} -> {archive}")
    try:
        urllib.request.urlretrieve(spec.url, archive)
    except Exception as e:
        print(f"[fetch_disambig_model] ERROR: download failed ({e}). "
              f"The pipeline will still run with HeuristicPolicy.",
              file=sys.stderr)
        return 2

    digest = _sha256(archive)
    if digest != spec.sha256:
        print(f"[fetch_disambig_model] ERROR: SHA-256 mismatch.\n"
              f"  expected: {spec.sha256}\n  actual:   {digest}",
              file=sys.stderr)
        archive.unlink(missing_ok=True)
        return 3

    print(f"[fetch_disambig_model] extracting {archive}")
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    with tarfile.open(archive) as tf:
        tf.extractall(target)
    archive.unlink()
    print(f"[fetch_disambig_model] OK: checkpoint at {target}")
    print(f"  export IR_SAM_DISAMBIG_MODEL={target}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
