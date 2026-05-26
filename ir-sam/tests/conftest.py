"""Pytest collection root for ir-sam.

Responsibilities:
- Make ``core``, ``bench``, ``eval`` importable when running pytest from the repo root.
- Establish deterministic seeds (``random``, ``PYTHONHASHSEED``) so property
  tests and synthetic corpus generation are reproducible across runs.
- Provide cross-cutting fixtures (tmp project dirs, golden-diff helpers).
- Auto-skip tests marked ``requires_docker`` / ``requires_corpus`` /
  ``requires_llm`` when the corresponding resource is unavailable.
"""

from __future__ import annotations

import os
import random
import shutil
import sys
from pathlib import Path

import pytest

# --- import path ---

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


# --- determinism --------------------------------------------------------------


_SEED = int(os.environ.get("IRSAM_TEST_SEED", "20260524"))


@pytest.fixture(scope="session", autouse=True)
def seed_everything() -> int:
    """Seed every stdlib RNG and PYTHONHASHSEED for cross-run determinism."""
    os.environ.setdefault("PYTHONHASHSEED", str(_SEED))
    random.seed(_SEED)
    try:
        import numpy as np  # type: ignore[import-not-found]
        np.random.seed(_SEED)
    except ImportError:
        pass
    return _SEED


# --- resource-availability gates ---------------------------------------------


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _has_corpus(name: str) -> bool:
    cache = Path(os.environ.get("IRSAM_CORPUS_CACHE", ROOT / "bench" / ".cache"))
    return (cache / name).exists()


def pytest_collection_modifyitems(config: pytest.Config,
                                  items: list[pytest.Item]) -> None:
    skip_docker = pytest.mark.skip(reason="docker not available on this host")
    skip_llm = pytest.mark.skip(
        reason="LLM cassettes missing; set IRSAM_LLM_CASSETTES or skip"
    )
    has_docker = _docker_available()
    has_llm = bool(os.environ.get("IRSAM_LLM_CASSETTES")) or (
        ROOT / "baselines" / "cassettes"
    ).exists()
    # Tier markers we know about; anything else falls through as 'unit'.
    _known = {"unit", "property", "integration", "e2e", "differential",
              "perf", "security", "soundness", "mutation", "fuzz"}
    for item in items:
        # Default tier: 'unit' (so plain test functions are picked up by
        # the 'fast' tier).
        if not (set(item.keywords) & _known):
            item.add_marker(pytest.mark.unit)
        if "requires_docker" in item.keywords and not has_docker:
            item.add_marker(skip_docker)
        if "requires_llm" in item.keywords and not has_llm:
            item.add_marker(skip_llm)
        if "requires_corpus" in item.keywords:
            wanted = item.get_closest_marker("requires_corpus")
            corpus = (wanted.args[0] if wanted and wanted.args else "any")
            if corpus != "any" and not _has_corpus(corpus):
                item.add_marker(
                    pytest.mark.skip(reason=f"corpus {corpus!r} not cached")
                )


# --- shared fixtures ----------------------------------------------------------


@pytest.fixture
def repo_root() -> Path:
    return ROOT


@pytest.fixture
def binder_catalogs(repo_root: Path) -> list[Path]:
    return sorted((repo_root / "binders").glob("*.yaml"))


@pytest.fixture
def assert_golden(tmp_path: Path):
    """Compare a string to a committed golden file under ``tests/golden/``.

    Usage::

        def test_x(assert_golden):
            assert_golden("patches/foo.diff", actual_diff)

    Set ``IRSAM_UPDATE_GOLDEN=1`` to refresh goldens in place.
    """
    update = os.environ.get("IRSAM_UPDATE_GOLDEN") == "1"
    golden_root = ROOT / "tests" / "golden"

    def _cmp(relpath: str, actual: str) -> None:
        target = golden_root / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        if update or not target.exists():
            target.write_text(actual, encoding="utf-8")
            return
        expected = target.read_text(encoding="utf-8")
        assert actual == expected, (
            f"Golden mismatch for {relpath!r}. "
            f"Re-run with IRSAM_UPDATE_GOLDEN=1 to refresh."
        )

    return _cmp
