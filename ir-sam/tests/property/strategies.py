"""Shared Hypothesis strategies for IR-SAM property tests."""

from __future__ import annotations

import hypothesis.strategies as st

from core.iam import Cardinality, Hole, IAM, Literal, SemType, SIGNode, SyntCtx


_IDENT = st.from_regex(r"[a-z][a-z0-9_]{0,7}", fullmatch=True)
_SEM = st.sampled_from(list(SemType))
_CTX = st.sampled_from(list(SyntCtx))
_CARD = st.sampled_from(list(Cardinality))


@st.composite
def holes(draw) -> Hole:
    return Hole(
        name=draw(_IDENT),
        ctx=draw(_CTX),
        sem=draw(_SEM),
        card=draw(_CARD),
        allowlist=None,
    )


@st.composite
def literals(draw) -> Literal:
    return Literal(value=draw(st.text(alphabet="abcdef ", min_size=0, max_size=8)))


def sig_nodes(max_depth: int = 3) -> st.SearchStrategy[SIGNode]:
    """Generate SIG_0 trees up to ``max_depth``."""
    leaves: st.SearchStrategy = st.one_of(
        holes().map(lambda h: SIGNode(kind="HoleNode", children=(h,))),
        literals().map(lambda l: SIGNode(kind="LitNode", children=(l,))),
    )
    return st.recursive(
        leaves,
        lambda children: st.builds(
            SIGNode,
            kind=st.sampled_from(["Select", "Comparison", "AndExpr", "OrExpr"]),
            children=st.lists(children, min_size=1, max_size=3).map(tuple),
        ),
        max_leaves=10,
    )


def _collect_holes(node: SIGNode | Hole | Literal) -> tuple[Hole, ...]:
    if isinstance(node, Hole):
        return (node,)
    if isinstance(node, Literal):
        return ()
    out: list[Hole] = []
    for c in node.children:
        out.extend(_collect_holes(c))
    return tuple(out)


@st.composite
def iams(draw) -> IAM:
    sig = draw(sig_nodes())
    hs = _collect_holes(sig)
    # Deduplicate hole names: structurally_sound is keyed by hole name, so
    # repeated names would mean a single realization satisfies multiple
    # logical holes, breaking monotonicity assumptions. We rebuild the SIG
    # with renamed holes.
    seen: dict[str, int] = {}
    renamed_holes: list[Hole] = []
    rename_map: dict[int, str] = {}
    for h in hs:
        n = seen.get(h.name, 0)
        seen[h.name] = n + 1
        new_name = h.name if n == 0 else f"{h.name}_{n}"
        rename_map[id(h)] = new_name
        renamed_holes.append(Hole(name=new_name, ctx=h.ctx, sem=h.sem,
                                  card=h.card, allowlist=h.allowlist))

    def _rebuild(node):
        if isinstance(node, Hole):
            return Hole(name=rename_map[id(node)], ctx=node.ctx, sem=node.sem,
                        card=node.card, allowlist=node.allowlist)
        if isinstance(node, Literal):
            return node
        return SIGNode(kind=node.kind,
                       children=tuple(_rebuild(c) for c in node.children))

    new_sig = _rebuild(sig)
    return IAM(sig=new_sig, holes=tuple(renamed_holes))
