"""Stage D parser for LDAP search filters (RFC 4515 subset).

Grammar (RFC 4515, our supported subset):

    filter      := '(' filtercomp ')'
    filtercomp  := and | or | not | item
    and         := '&' filterlist
    or          := '|' filterlist
    not         := '!' filter
    filterlist  := filter (filter)*
    item        := simple | substring | present | extensible
    simple      := attr filtertype assertionvalue
    filtertype  := '=' | '~=' | '>=' | '<='
    substring   := attr '=' [initial] '*' [any] '*' [final]
    present     := attr '=*'
    assertionvalue := <utf-8 minus reserved>

Holes use the same ``<<H{n}>>`` markers as the SQL_0 parser. A hole in
*value* position becomes ``ctx = SyntCtx.VALUE`` and must be realized
via an escape-helper API from ``binders/ldap.yaml``. A hole in the
*attribute* position becomes ``ctx = SyntCtx.IDENTIFIER`` and requires
an allow-list (Lemma 2).

Out-of-scope (raise :class:`LDAPAmbiguousIntent`): holes spanning
operators, multi-character substring holes without surrounding
literals, holes inside extensible matching rule OIDs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from core.iam import Hole, Literal, SIGNode, SemType, SyntCtx
from core.recon import ParameterizedTemplate, TemplateHole


class LDAPSyntaxError(ValueError):
    pass


class LDAPAmbiguousIntent(ValueError):
    pass


@dataclass(frozen=True)
class LDAPLift:
    sig: SIGNode
    holes: tuple[Hole, ...]


_TOK_RE = re.compile(
    r"""
    (?P<HOLE>  <<H\d+>> )
  | (?P<OP>    [&|!()*] | <= | >= | ~= | = )
  | (?P<TEXT>  [^()&|!*=~<>]+ )
    """,
    re.VERBOSE,
)


@dataclass(frozen=True)
class _Tok:
    kind: str
    text: str
    pos: int


def _lex(src: str) -> list[_Tok]:
    out: list[_Tok] = []
    i = 0
    while i < len(src):
        m = _TOK_RE.match(src, i)
        if not m:
            raise LDAPSyntaxError(f"bad char {src[i]!r} @ {i}")
        out.append(_Tok(m.lastgroup or "?", m.group(), m.start()))
        i = m.end()
    return out


@dataclass
class _P:
    toks: list[_Tok]
    holes: dict[int, TemplateHole]
    pos: int = 0
    next_attr: int = 0

    def peek(self, k=0):
        return self.toks[self.pos + k] if self.pos + k < len(self.toks) else None

    def eat(self, text):
        t = self.peek()
        if t is None or t.text != text:
            raise LDAPSyntaxError(f"expected {text!r}, got {t}")
        self.pos += 1
        return t

    def parse_filter(self) -> SIGNode:
        self.eat("(")
        node = self.parse_comp()
        self.eat(")")
        return node

    def parse_comp(self) -> SIGNode:
        t = self.peek()
        if t is None:
            raise LDAPSyntaxError("empty filter")
        if t.text == "&":
            self.pos += 1
            kids = [self.parse_filter()]
            while self.peek() and self.peek().text == "(":
                kids.append(self.parse_filter())
            return SIGNode("LdapAnd", tuple(kids))
        if t.text == "|":
            self.pos += 1
            kids = [self.parse_filter()]
            while self.peek() and self.peek().text == "(":
                kids.append(self.parse_filter())
            return SIGNode("LdapOr", tuple(kids))
        if t.text == "!":
            self.pos += 1
            return SIGNode("LdapNot", (self.parse_filter(),))
        return self.parse_item()

    def parse_item(self) -> SIGNode:
        # attribute (text or hole) then filter-type then value
        attr_tok = self.peek()
        if attr_tok is None:
            raise LDAPSyntaxError("expected attr")
        if attr_tok.kind == "HOLE":
            idx = int(attr_tok.text[3:-2])
            attr_node: SIGNode | Hole = Hole(
                name=f"h{idx}", ctx=SyntCtx.IDENTIFIER, sem=SemType.STRING,
            )
            self.pos += 1
        elif attr_tok.kind == "TEXT":
            attr_node = SIGNode("Attr", (Literal(attr_tok.text.strip()),))
            self.pos += 1
        else:
            raise LDAPSyntaxError(f"expected attribute, got {attr_tok}")

        op_tok = self.peek()
        if op_tok is None or op_tok.text not in ("=", "~=", ">=", "<="):
            raise LDAPSyntaxError(f"expected filtertype, got {op_tok}")
        op = op_tok.text
        self.pos += 1

        # present filter: ``=*)``
        if op == "=" and self.peek() and self.peek().text == "*" \
                and self.peek(1) and self.peek(1).text == ")":
            self.pos += 1
            return SIGNode("LdapPresent", (attr_node,))

        # value: TEXT? (* TEXT?)* HOLE? combinations.
        # MVP rule: support either (a) single value (HOLE or TEXT)
        # or (b) substring with exactly one HOLE between '*'s.
        v = self.peek()
        if v is None:
            raise LDAPSyntaxError("expected value")
        if v.kind == "HOLE":
            idx = int(v.text[3:-2])
            hole = Hole(name=f"h{idx}", ctx=SyntCtx.VALUE, sem=SemType.STRING)
            self.pos += 1
            return SIGNode("LdapEquality", (attr_node, hole))
        if v.kind == "OP" and v.text == "*":
            # substring: '*' HOLE '*'
            self.pos += 1
            mid = self.peek()
            if mid is None or mid.kind != "HOLE":
                raise LDAPAmbiguousIntent(
                    "LDAP substring without exactly one attacker-controlled "
                    "segment is out of MVP scope")
            idx = int(mid.text[3:-2])
            self.pos += 1
            if not self.peek() or self.peek().text != "*":
                raise LDAPSyntaxError("expected '*' after substring hole")
            self.pos += 1
            hole = Hole(name=f"h{idx}", ctx=SyntCtx.VALUE, sem=SemType.STRING)
            return SIGNode("LdapSubstring", (attr_node, hole))
        if v.kind == "TEXT":
            self.pos += 1
            return SIGNode("LdapEquality",
                           (attr_node, Literal(v.text.strip())))
        raise LDAPSyntaxError(f"bad value token {v}")


def parse_template_to_sig(tpl: ParameterizedTemplate) -> LDAPLift:
    toks = _lex(tpl.text.strip())
    p = _P(toks, {th.idx: th for th in tpl.holes})
    node = p.parse_filter()
    if p.pos != len(toks):
        raise LDAPSyntaxError(f"trailing tokens at {p.pos}")

    def collect(n) -> list[Hole]:
        if isinstance(n, Hole):
            return [n]
        if isinstance(n, SIGNode):
            out = []
            for c in n.children:
                out.extend(collect(c))
            return out
        return []

    return LDAPLift(sig=node, holes=tuple(collect(node)))
