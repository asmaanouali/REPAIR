"""Shared types for dataset loaders."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator


@dataclass(frozen=True)
class VulnSample:
    """One pre/post fix pair from a vulnerability dataset."""

    sample_id: str           # globally unique within the dataset
    dataset: str             # "cvefixes", "vul4j", "bigvul", ...
    cwe: tuple[str, ...]     # ("CWE-89", ...)
    language: str
    repo: str | None         # github "owner/repo" if known
    commit_fix: str | None   # commit sha of the fix
    file: str                # path to the vulnerable file (relative)
    pre_fix_code: str        # the vulnerable version
    post_fix_code: str       # the human-authored fix
    cve: str | None = None
    extra: dict[str, str] = field(default_factory=dict)


class Dataset(ABC):
    """A normalized vulnerability dataset."""

    name: str

    def __init__(self, cache_dir: Path) -> None:
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    @abstractmethod
    def download(self) -> None:
        """Idempotent download + checksum verification."""

    @abstractmethod
    def iter_samples(self) -> Iterator[VulnSample]:
        """Yield normalized samples from the cached dataset."""

    def __len__(self) -> int:  # default: count by iteration
        return sum(1 for _ in self.iter_samples())
