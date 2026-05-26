"""``python -m irsam_worker`` -> arq."""

from __future__ import annotations

import sys


def main() -> None:
    # Delegate to arq's CLI so we get its full feature set (signal
    # handling, --watch reload, etc.) without re-implementing it.
    from arq.cli import cli  # type: ignore[attr-defined]
    sys.argv = [sys.argv[0], "irsam_worker.tasks.WorkerSettings", *sys.argv[1:]]
    cli()


if __name__ == "__main__":
    main()
