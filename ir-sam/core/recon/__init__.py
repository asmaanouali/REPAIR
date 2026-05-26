"""Stage C --- symbolic string reconstructor.

Takes the :class:`~core.slicer.SliceResult` produced by stage B and
produces a :class:`ParameterizedTemplate`: a SQL string in which every
host-language interpolation point has been replaced by a typed
``<<H{n}>>`` marker. The markers are consumed by stage D (the SQL_0
parser) to lift the template into a SIG with typed holes.

Design notes
~~~~~~~~~~~~

* The reconstructor is *not* a SQL parser. It only sees host-language
  parts and produces a flat marker-augmented string.
* If a variable part appears *inside a SQL string literal* (e.g.
  ``"... LIKE '" + pattern + "%'"``), we expand the surrounding
  literal into the pattern (``'% + ? + %'`` cases are normalized into
  a single hole bound via :class:`~core.parsers.sql.sig.LikeExpr`).
* If the slice produced *no* literal SQL skeleton (pure variable),
  stage C abstains via :class:`ReconAbstention`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from core.slicer import SliceResult, StringPart, infer_sem_type


_MARKER = "<<H{idx}>>"  # rendered into the template string


@dataclass(frozen=True)
class TemplateHole:
    """One interpolation point in the parameterized template."""

    idx: int
    host_expr: str
    sem: str = "string"  # one of: string|integer|decimal|boolean|date|blob
    in_string_literal: bool = False  # True if surrounded by SQL quotes


@dataclass(frozen=True)
class ParameterizedTemplate:
    text: str
    holes: tuple[TemplateHole, ...] = field(default_factory=tuple)

    def render_for_parser(self) -> str:
        """Return the template with markers preserved for stage D."""
        return self.text


@dataclass(frozen=True)
class ReconAbstention:
    reason: str
    details: str = ""


def reconstruct(slice_: SliceResult) -> ParameterizedTemplate | ReconAbstention:
    """Lift a slice into a parameterized template.

    The reconstruction is deterministic: holes are numbered in textual
    order; literals are concatenated verbatim. After concatenation, any
    SQL single-quoted literal that contains exactly one hole marker is
    normalized by stripping the surrounding quotes and absorbing any
    constant prefix/suffix into the hole's host expression (so a
    quoted hole becomes a plain value hole that stage D parses as a
    Comparison/LikeExpr value).
    """
    pieces: list[str] = []
    holes: list[TemplateHole] = []
    next_idx = 0

    in_quote = False
    for p in slice_.parts:
        if p.kind == "literal":
            pieces.append(p.value)
            in_quote = _flip_quotes(p.value, in_quote)
        else:
            h = TemplateHole(
                idx=next_idx,
                host_expr=p.value,
                sem=infer_sem_type(p.java_type),
                in_string_literal=in_quote,
            )
            holes.append(h)
            pieces.append(_MARKER.format(idx=next_idx))
            next_idx += 1
    text = "".join(pieces)
    if not any(p.kind == "literal" for p in slice_.parts):
        return ReconAbstention("opaque_slice",
                               "no literal SQL skeleton survived reconstruction")

    text, holes = _normalize_quoted_holes(text, holes)
    return ParameterizedTemplate(text=text, holes=tuple(holes))


def _flip_quotes(literal: str, in_quote: bool) -> bool:
    """Track whether a single-quoted SQL literal is currently open."""
    i = 0
    while i < len(literal):
        c = literal[i]
        if c == "\\" and i + 1 < len(literal):
            i += 2
            continue
        if c == "'":
            in_quote = not in_quote
        i += 1
    return in_quote


def _merge_quoted_literals(parts: tuple[StringPart, ...]) -> tuple[StringPart, ...]:
    # Deprecated: peephole merge handled post-concatenation in
    # _normalize_quoted_holes; retained for API compatibility.
    return tuple(parts)


def _normalize_quoted_holes(
    text: str, holes: list[TemplateHole]
) -> tuple[str, list[TemplateHole]]:
    """Lift ``'PRE<<Hn>>POST'`` into ``<<Hn>>`` and absorb PRE/POST.

    Scans `text` character-by-character tracking SQL single-quote state
    (with ``''`` SQL escape). For each balanced ``'...'`` region that
    contains exactly one ``<<Hn>>`` marker, the region is replaced with
    just the marker; PRE and POST are merged into the corresponding
    hole's host_expr as Java string concatenation. The hole's
    `in_string_literal` flag is set True.

    Regions with zero markers are left untouched (constant SQL
    literals). Regions with >=2 markers are also left untouched (stage
    D will likely raise SQL0AmbiguousIntent and we abstain).
    """
    out: list[str] = []
    i = 0
    n = len(text)
    by_idx = {h.idx: h for h in holes}
    while i < n:
        c = text[i]
        if c != "'":
            out.append(c)
            i += 1
            continue
        # find matching close quote (handle '' as escape)
        j = i + 1
        while j < n:
            if text[j] == "'":
                if j + 1 < n and text[j + 1] == "'":
                    j += 2
                    continue
                break
            j += 1
        if j >= n:  # unterminated; emit as-is
            out.append(text[i:])
            i = n
            break
        body = text[i + 1:j]
        # find <<Hn>> markers in body
        import re as _re
        marks = list(_re.finditer(r"<<H(\d+)>>", body))
        if len(marks) == 1:
            m = marks[0]
            pre = body[:m.start()]
            post = body[m.end():]
            idx = int(m.group(1))
            h = by_idx.get(idx)
            if h is not None:
                pieces = []
                if pre:
                    esc = pre.replace("\\", "\\\\").replace('"', '\\"')
                    pieces.append(f'"{esc}"')
                pieces.append(h.host_expr)
                if post:
                    esc = post.replace("\\", "\\\\").replace('"', '\\"')
                    pieces.append(f'"{esc}"')
                new_host = " + ".join(pieces)
                # update hole
                new_h = TemplateHole(
                    idx=h.idx,
                    host_expr=new_host,
                    sem=h.sem,
                    in_string_literal=True,
                )
                by_idx[idx] = new_h
            out.append(f"<<H{idx}>>")
            i = j + 1
            continue
        # no transformation
        out.append(text[i:j + 1])
        i = j + 1
    new_holes = [by_idx[h.idx] for h in holes]
    return "".join(out), new_holes
