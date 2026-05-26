"""Dataset acquisition & caching for IR-SAM evaluation.

Each loader exposes the same interface::

    from bench.loaders import cvefixes
    ds = cvefixes.load(cache_dir=Path("datasets/cache"))
    for sample in ds.iter_samples():
        ...

Loaders are responsible for: download (with checksum verification),
unpack, normalize to :class:`bench.loaders.base.VulnSample`, and cache.
They are deliberately tolerant of partial caches so a long-running
download can be resumed.
"""

from .base import Dataset, VulnSample

__all__ = ["Dataset", "VulnSample"]
