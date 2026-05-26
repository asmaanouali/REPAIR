"""Stage D parser for the POSIX-shell argv fragment (CWE-78).

The shell-argv fragment is a deliberately narrow subset of POSIX
shell: a sequence of *positional* argv tokens, each of which is
either a literal (possibly quoted) or a hole. Anything outside this
fragment — pipelines, redirections, command substitution, globs in
unquoted positions, ``&&`` / ``||`` chaining, here-docs — is rejected
with :class:`ShellAmbiguousIntent` and the pipeline abstains.

Grammar::

    argv     := word (WS word)*
    word     := dq | sq | bare | <<H{n}>>
    dq       := '"' ( esc | <<H{n}>> | not_dq )* '"'
    sq       := "'" ( not_sq )* "'"
    bare     := [A-Za-z0-9_./:=+@%-]+
    esc      := '\\' .

Each top-level *word* becomes one argv element. A hole inside a
double-quoted string is allowed (it becomes a single argv token whose
value at runtime is the hole). A hole outside any word context is the
common case — ``cmd arg1 <<H0>> arg2`` → three argv tokens, the
middle one is the hole.

Why this is enough for the binder rewrite: the safe rewrite is

    subprocess.run([prog, "literal", hole_value, "literal"], shell=False)

The binder needs only the *list of argv tokens* and the index of each
hole. Globs, pipes, and redirections in the original have no
correspondent in the safe API and must be rejected upstream.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from core.iam import Hole, Literal, SIGNode, SemType, SyntCtx
from core.recon import ParameterizedTemplate, TemplateHole


class ShellSyntaxError(ValueError):
    pass


class ShellAmbiguousIntent(ValueError):
    pass


@dataclass(frozen=True)
class ShellLift:
    sig: SIGNode
    holes: tuple[Hole, ...]


# Forbidden characters at the *unquoted* top level. Their presence
# means the original is using a shell feature whose safe-API
# replacement is not a single ``subprocess.run([...])`` call.
_FORBIDDEN_TOP = set("|&;<>`$(){}*?[")
# A bare ``[`` is allowed in quoted strings but never at the top.


_HOLE_RE = re.compile(r"<<H(\d+)>>")


def _lex_words(src: str) -> list[str | tuple[str, int]]:
    """Tokenize the shell template into a list of words.

    Each word is either a ``str`` (literal-only) or a tuple
    ``('hole', idx)`` for a hole that occupies the entire word.

    A hole that appears *inside* a quoted string yields a single word
    that is the concatenation of literal fragments and the hole
    marker; for the value-position case (the only one we accept) this
    means a word like ``"prefix<<H0>>suffix"`` which we represent as a
    list of fragments. Such mixed words abstain by raising
    :class:`ShellAmbiguousIntent`; the pipeline asks the disambiguator
    or gives up. (The honest framing in the contribution chapter §4.2:
    the convert ``-resize`` example deliberately uses a structured
    allowlist on the hole rather than mixing it with literal flag
    glue.)
    """
    out: list[str | tuple[str, int]] = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c.isspace():
            i += 1
            continue
        # detect a hole that stands alone as a word
        m = _HOLE_RE.match(src, i)
        if m and (i + len(m.group(0)) == n or src[i + len(m.group(0))].isspace()):
            out.append(("hole", int(m.group(1))))
            i = m.end()
            continue
        # quoted word
        if c == '"' or c == "'":
            j, word = _scan_quoted(src, i)
            out.append(word)
            i = j
            continue
        # otherwise: bare word ending at whitespace or EOF. Reject
        # any forbidden top-level meta-character inside this word.
        j = i
        bare = []
        while j < n and not src[j].isspace():
            ch = src[j]
            if ch in _FORBIDDEN_TOP:
                raise ShellAmbiguousIntent(
                    f"shell metacharacter {ch!r} in unquoted position; "
                    f"the safe rewrite for this construct is undefined"
                )
            # a hole embedded in a bare word is a mixed token: abstain.
            if ch == "<":
                m2 = _HOLE_RE.match(src, j)
                if m2:
                    raise ShellAmbiguousIntent(
                        "hole concatenated with bare literal; either "
                        "quote the entire argv token or split the literals"
                    )
            bare.append(ch)
            j += 1
        if bare:
            out.append("".join(bare))
        i = j
    return out


def _scan_quoted(src: str, start: int) -> tuple[int, str | tuple[str, int]]:
    quote = src[start]
    j = start + 1
    buf: list[str] = []
    has_hole = False
    while j < len(src):
        ch = src[j]
        if ch == "\\" and quote == '"' and j + 1 < len(src):
            buf.append(src[j + 1])
            j += 2
            continue
        if ch == quote:
            text = "".join(buf)
            if has_hole and any(part for part in buf if part):
                # mixed literal+hole inside one quoted word: abstain.
                raise ShellAmbiguousIntent(
                    "hole concatenated with literal inside quoted word"
                )
            return j + 1, text
        # a hole inside a quoted string is fine only if it's the
        # whole word (no other literal bytes between the quotes).
        m = _HOLE_RE.match(src, j)
        if m and quote == '"':
            if buf:
                raise ShellAmbiguousIntent(
                    "hole concatenated with literal inside quoted word"
                )
            # peek: must be immediately followed by the closing quote.
            after = j + len(m.group(0))
            if after >= len(src) or src[after] != quote:
                raise ShellAmbiguousIntent(
                    "hole concatenated with literal inside quoted word"
                )
            return after + 1, ("hole", int(m.group(1)))
        buf.append(ch)
        j += 1
    raise ShellSyntaxError(f"unterminated {quote} string at {start}")


def parse_shell_argv(template: ParameterizedTemplate) -> ShellLift:
    """Parse a shell-argv template into a SIG.

    The resulting SIG root is ``Argv(items=...)`` where each item is
    either a :class:`Literal` (a constant argv token) or a
    :class:`Hole` with ``ctx = SyntCtx.VALUE`` and
    ``card = Cardinality.ONE`` (one argv slot per hole).
    """
    from core.iam import Cardinality  # local: avoid cycle at import time

    hole_idx_to_th: dict[int, TemplateHole] = {h.idx: h for h in template.holes}
    words = _lex_words(template.text)
    items: list[SIGNode | Literal | Hole] = []
    holes: list[Hole] = []
    for w in words:
        if isinstance(w, tuple) and w[0] == "hole":
            idx = w[1]
            th = hole_idx_to_th.get(idx)
            if th is None:
                raise ShellSyntaxError(
                    f"template references <<H{idx}>> but no matching hole"
                )
            h = Hole(
                name=f"h{idx}",
                ctx=SyntCtx.VALUE,
                sem=SemType.STRING,
                card=Cardinality.ONE,
                allowlist=None,
            )
            holes.append(h)
            items.append(h)
        else:
            items.append(Literal(str(w)))
    if not items:
        raise ShellSyntaxError("empty argv template")
    sig = SIGNode("Argv", tuple(items))
    return ShellLift(sig=sig, holes=tuple(holes))
