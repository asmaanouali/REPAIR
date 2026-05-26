"""Binding-catalog DSL loader (Phase 1 reference implementation)."""

from .loader import BinderCatalog, ClosureViolation, load_catalog

__all__ = ["BinderCatalog", "ClosureViolation", "load_catalog"]
