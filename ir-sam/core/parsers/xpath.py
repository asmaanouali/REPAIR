"""Stage D parser for XPath 1.0 predicate subset.

Supported shapes (intentionally narrow --- the MVP target is
authentication / lookup queries):

    expr   := step ('/' step)*
    step   := name ('[' pred ']')?
    pred   := pcomp | fn
    pcomp  := '@' name op value
    fn     := 'contains' '(' '@' name ',' value ')'
            | 'starts-with' '(' '@' name ',' value ')'
    op     := '=' | '!='
    value  := str | num | <<H{n}>>

Holes are required to occupy *value* positions only. A hole in any
other slot (attribute name, function name, axis) raises
:class:`XPathAmbiguousIntent` --- the upstream pipeline turns this
into a stage-D abstention.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from core.iam import Hole, Literal, SIGNode, SemType, SyntCtx
from core.recon import ParameterizedTemplate, TemplateHole


class XPathSyntaxError(ValueError):
    pass


class XPathAmbiguousIntent(ValueError):
    pass


@dataclass(frozen=True)
class XPathLift:
    sig: SIGNode
    holes: tuple[Hole, ...]


_T_RE = re.compile(
    r"""
    (?P<HOLE>   <<H\d+>> )
  | (?P<STR>    ' [^']* ' | " [^"]* " )
  | (?P<NUM>    \d+(?:\.\d+)? )
  | (?P<NAME>   [A-Za-z_][\w-]* )
  | (?P<OP>     != | = | @ | \( | \) | \[ | \] | , | / )
  | (?P<WS>     \s+ )
    """,
    re.VERBOSE,
)


@dataclass(frozen=True)
class _T:
    kind: str
    text: str


def _lex(src: str) -> list[_T]:
    out: list[_T] = []
    i = 0
    while i < len(src):
        m = _T_RE.match(src, i)
        if not m:
            raise XPathSyntaxError(f"bad char {src[i]!r} @ {i}")
        if m.lastgroup != "WS":
            out.append(_T(m.lastgroup or "?", m.group()))
        i = m.end()
    return out


@dataclass
class _P:
    toks: list[_T]
    pos: int = 0

    def peek(self, k=0):
        return self.toks[self.pos + k] if self.pos + k < len(self.toks) else None

    def eat(self, text):
        t = self.peek()
        if t is None or t.text != text:
            raise XPathSyntaxError(f"expected {text!r}, got {t}")
        self.pos += 1
        return t

    def parse_expr(self) -> SIGNode:
        steps = []
        # absolute path: leading '/' or '//'
        while self.peek() and self.peek().text == "/":
            self.pos += 1
        steps.append(self.parse_step())
        while self.peek() and self.peek().text == "/":
            self.pos += 1
            # support '//' between steps
            while self.peek() and self.peek().text == "/":
                self.pos += 1
            steps.append(self.parse_step())
        return SIGNode("XPathPath", tuple(steps))

    def parse_step(self) -> SIGNode:
        t = self.peek()
        if t is None or t.kind != "NAME":
            raise XPathSyntaxError(f"expected step name, got {t}")
        name = t.text
        self.pos += 1
        children: list = [Literal(name)]
        if self.peek() and self.peek().text == "[":
            self.pos += 1
            children.append(self.parse_pred())
            self.eat("]")
        return SIGNode("XPathStep", tuple(children))

    def parse_pred(self) -> SIGNode:
        t = self.peek()
        if t and t.kind == "NAME" and t.text in ("contains", "starts-with"):
            fn = t.text
            self.pos += 1
            self.eat("(")
            self.eat("@")
            attr_tok = self.peek()
            if attr_tok is None or attr_tok.kind == "HOLE":
                raise XPathAmbiguousIntent(
                    "hole in attribute name position not supported")
            self.pos += 1
            self.eat(",")
            val = self._parse_value()
            self.eat(")")
            kind = "XPathFnContains" if fn == "contains" else "XPathFnStartsWith"
            return SIGNode(kind, (SIGNode("Attr", (Literal(attr_tok.text),)), val))
        # else: '@' name op value
        self.eat("@")
        attr_tok = self.peek()
        if attr_tok is None or attr_tok.kind == "HOLE":
            raise XPathAmbiguousIntent("hole in attribute name position not supported")
        self.pos += 1
        op_tok = self.peek()
        if op_tok is None or op_tok.text not in ("=", "!="):
            raise XPathSyntaxError(f"expected op, got {op_tok}")
        self.pos += 1
        val = self._parse_value()
        return SIGNode("XPathPredicateEq",
                       (SIGNode("Attr", (Literal(attr_tok.text),)), val))

    def _parse_value(self):
        t = self.peek()
        if t is None:
            raise XPathSyntaxError("expected value")
        if t.kind == "HOLE":
            idx = int(t.text[3:-2])
            self.pos += 1
            return Hole(name=f"h{idx}", ctx=SyntCtx.VALUE, sem=SemType.STRING)
        if t.kind == "STR":
            self.pos += 1
            return Literal(t.text[1:-1])
        if t.kind == "NUM":
            self.pos += 1
            return Literal(t.text)
        raise XPathSyntaxError(f"bad value {t}")


def parse_template_to_sig(tpl: ParameterizedTemplate) -> XPathLift:
    toks = _lex(tpl.text.strip())
    p = _P(toks)
    sig = p.parse_expr()
    if p.pos != len(toks):
        raise XPathSyntaxError(f"trailing tokens at {p.pos}")

    def collect(n) -> list[Hole]:
        if isinstance(n, Hole):
            return [n]
        if isinstance(n, SIGNode):
            out = []
            for c in n.children:
                out.extend(collect(c))
            return out
        return []
    return XPathLift(sig=sig, holes=tuple(collect(sig)))
