"""Shared tree-sitter language loaders (Phase 2+).

Centralizes Language object construction so each AST front-end imports a
ready-made parser without repeating the boilerplate. Languages are loaded
lazily on first use; failures (missing wheel, ABI mismatch) raise
:class:`TreeSitterUnavailable` which the dispatcher converts into an
abstention rather than a crash.
"""

from __future__ import annotations

from functools import lru_cache


class TreeSitterUnavailable(Exception):
    """Raised when a tree-sitter wheel is not importable."""


@lru_cache(maxsize=4)
def get_java_parser():
    """Return a ``tree_sitter.Parser`` configured for Java."""
    try:
        from tree_sitter import Language, Parser
        import tree_sitter_java as tsj
    except Exception as exc:  # pragma: no cover - missing optional dep
        raise TreeSitterUnavailable(f"tree-sitter-java not installed: {exc}") from exc
    lang = Language(tsj.language())
    parser = Parser(lang)
    return parser


def parse_java(source: str | bytes):
    """Parse ``source`` and return ``(tree, source_bytes)``."""
    parser = get_java_parser()
    src_bytes = source.encode("utf-8") if isinstance(source, str) else source
    return parser.parse(src_bytes), src_bytes


@lru_cache(maxsize=4)
def get_typescript_parser(flavor: str = "typescript"):
    """Return a ``tree_sitter.Parser`` configured for TS or TSX.

    ``flavor`` is either ``"typescript"`` (``.ts``) or ``"tsx"`` (``.tsx``);
    ``"javascript"`` aliases to the TypeScript grammar (TS is a JS
    superset for the syntactic constructs this slicer cares about).
    """
    try:
        from tree_sitter import Language, Parser
        import tree_sitter_typescript as tst
    except Exception as exc:  # pragma: no cover - missing optional dep
        raise TreeSitterUnavailable(
            f"tree-sitter-typescript not installed: {exc}"
        ) from exc
    if flavor == "tsx":
        lang = Language(tst.language_tsx())
    else:
        lang = Language(tst.language_typescript())
    return Parser(lang)


def parse_typescript(source: str | bytes, flavor: str = "typescript"):
    """Parse a TS/TSX source and return ``(tree, source_bytes)``."""
    parser = get_typescript_parser(flavor)
    src_bytes = source.encode("utf-8") if isinstance(source, str) else source
    return parser.parse(src_bytes), src_bytes


def node_text(node, src_bytes: bytes) -> str:
    """Extract the literal source text covered by ``node``."""
    return src_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
