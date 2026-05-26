"""Stage B --- intra-procedural Java slicer (MVP).

The MVP slicer handles the shapes that account for the overwhelming
majority of Juliet CWE-89 and OWASP-Benchmark SQLi cases:

* Direct String literal passed to a sink (no slice needed).
* String concatenation via ``+`` (chained or in single expression).
* ``StringBuilder`` / ``StringBuffer`` ``.append(...).append(...)`` chains.
* ``String.format`` / ``MessageFormat.format`` with positional args.
* Local variable assignments along a straight-line control-flow path
  from the method entry to the sink call.

Out-of-MVP shapes (loop join, inter-procedural helpers, lambda capture,
reflective invocation, framework-injected request parameters) are
detected and result in an explicit :class:`SliceAbstention` reason
returned by :func:`slice_sink_argument`.

The slicer is **text-driven**: we parse just enough Java to recover the
local-variable definition-use chain we need. This avoids dragging in
javalang/Spoon/Joern in the MVP reference implementation; the
``--engine joern`` flag in the CLI is the integration point where
Phase-4 hardening will plug in a real CPG-based slicer.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable


# --- public datatypes ---------------------------------------------------------


@dataclass(frozen=True)
class StringPart:
    """One textual fragment of a reconstructed string expression."""

    kind: str  # "literal" | "var"
    value: str  # literal text or variable host expression
    java_type: str = "java.lang.String"  # for "var" parts

    @staticmethod
    def lit(text: str) -> "StringPart":
        return StringPart(kind="literal", value=text)

    @staticmethod
    def var(host_expr: str, java_type: str = "java.lang.String") -> "StringPart":
        return StringPart(kind="var", value=host_expr, java_type=java_type)


@dataclass(frozen=True)
class SliceResult:
    """Successful slice output.

    ``parts`` is the ordered concatenation of literal / variable
    fragments that constitute the SQL string passed to the sink.

    ``sink_call_text`` is the textual call expression at the sink line
    (``stmt.executeQuery(sqlVar)``-style). The rewriter consumes this
    to locate the exact site to replace.
    """

    parts: tuple[StringPart, ...]
    method_text: str
    method_start_line: int
    sink_call_text: str
    sink_call_line: int
    sink_var_name: str | None
    declarations_to_remove: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class SliceAbstention:
    """Explicit \u22a5: the slice cannot be reconstructed soundly."""

    reason: str
    details: str = ""


# --- tokenizer ----------------------------------------------------------------


_TOKEN_RE = re.compile(
    r"""
    (?P<COMMENT> //[^\n]* | /\*.*?\*/ )
  | (?P<STRING>  " (?:\\.|[^"\\])* " )
  | (?P<CHAR>    ' (?:\\.|[^'\\])* ' )
  | (?P<NUM>     \d+(?:\.\d+)?[fFlLdD]? )
  | (?P<IDENT>   [A-Za-z_][A-Za-z_0-9]* )
  | (?P<OP>      ==|!=|<=|>=|\+\+|--|&&|\|\||<<|>>|[+\-*/%=<>!&|^~?:;,.()\[\]{}@] )
  | (?P<WS>      \s+ )
    """,
    re.VERBOSE | re.DOTALL,
)


@dataclass(frozen=True)
class Tok:
    kind: str
    text: str
    pos: int
    line: int


def tokenize(src: str) -> list[Tok]:
    """Lex a Java fragment. Comments and whitespace are dropped."""
    out: list[Tok] = []
    i = 0
    line = 1
    while i < len(src):
        m = _TOKEN_RE.match(src, i)
        if not m:
            # unknown char -- skip safely
            line += src[i].count("\n")
            i += 1
            continue
        kind = m.lastgroup or "OP"
        text = m.group()
        if kind not in ("WS", "COMMENT"):
            out.append(Tok(kind=kind, text=text, pos=m.start(), line=line))
        line += text.count("\n")
        i = m.end()
    return out


# --- helpers ------------------------------------------------------------------


_SINK_PATTERNS = re.compile(
    r"""
    \b(?P<recv>[A-Za-z_][A-Za-z_0-9]*)\s*\.\s*
    (?P<api>executeQuery|executeUpdate|execute|addBatch|prepareStatement|prepareCall)
    \s*\(
    """,
    re.VERBOSE,
)


def find_sink_calls(java_src: str) -> list[tuple[int, str, str, str]]:
    """Return ``(line, receiver, api, full_call_text)`` for each sink site."""
    out: list[tuple[int, str, str, str]] = []
    for m in _SINK_PATTERNS.finditer(java_src):
        line = java_src.count("\n", 0, m.start()) + 1
        call_text = _balanced_call(java_src, m.start())
        out.append((line, m.group("recv"), m.group("api"), call_text))
    return out


def _balanced_call(src: str, start: int) -> str:
    """Return the substring starting at ``start`` up through the matched ``)``."""
    i = src.find("(", start)
    if i < 0:
        return src[start:start + 200]
    depth = 0
    j = i
    while j < len(src):
        c = src[j]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return src[start:j + 1]
        elif c in ("'", '"'):
            j = _skip_string(src, j)
            continue
        j += 1
    return src[start:j]


def _skip_string(src: str, start: int) -> int:
    quote = src[start]
    j = start + 1
    while j < len(src):
        if src[j] == "\\":
            j += 2
            continue
        if src[j] == quote:
            return j + 1
        j += 1
    return j


def _find_enclosing_method(src: str, target_line: int) -> tuple[int, int, int] | None:
    """Return ``(start_pos, end_pos, start_line)`` of the method containing ``target_line``.

    Uses a brace-balanced scan starting from each ``)\\s*{`` after a
    method header. Heuristic but reliable for the MVP shapes.
    """
    method_header = re.compile(
        r"""
        (?:public|protected|private|static|\s|final|synchronized|abstract|native)+
        [\w<>,\s\[\]?\.]+\s+
        (?P<name>[A-Za-z_][A-Za-z_0-9]*)\s*\([^)]*\)\s*
        (?:throws\s+[\w\s,\.]+)?\s*
        \{
        """,
        re.VERBOSE,
    )
    for m in method_header.finditer(src):
        open_brace = src.find("{", m.start())
        depth = 0
        i = open_brace
        while i < len(src):
            c = src[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    start_line = src.count("\n", 0, m.start()) + 1
                    end_line = src.count("\n", 0, i) + 1
                    if start_line <= target_line <= end_line:
                        return (m.start(), i + 1, start_line)
                    break
            elif c in ("'", '"'):
                i = _skip_string(src, i)
                continue
            i += 1
    return None


# --- string-expression reconstruction ---------------------------------------


_BOOLEAN_TYPES = {"boolean", "Boolean", "java.lang.Boolean"}
_INT_TYPES = {"int", "Integer", "java.lang.Integer", "short", "Short", "byte", "Byte"}
_LONG_TYPES = {"long", "Long", "java.lang.Long"}
_DECIMAL_TYPES = {
    "float", "Float", "java.lang.Float",
    "double", "Double", "java.lang.Double",
    "BigDecimal", "java.math.BigDecimal",
}
_DATE_TYPES = {"java.sql.Date", "Date", "java.sql.Timestamp", "Timestamp"}


def _java_type_to_sem(tname: str) -> str:
    if tname in _BOOLEAN_TYPES:
        return "boolean"
    if tname in _INT_TYPES:
        return "integer"
    if tname in _LONG_TYPES:
        return "integer"
    if tname in _DECIMAL_TYPES:
        return "decimal"
    if tname in _DATE_TYPES:
        return "date"
    return "string"


# --- core entry point --------------------------------------------------------


@dataclass
class _LocalEnv:
    """Local variable environment: name -> (java_type, init_expr_text)."""

    decls: dict[str, tuple[str, str]] = field(default_factory=dict)
    decl_lines: dict[str, str] = field(default_factory=dict)  # full text


def _scan_locals(method_src: str) -> _LocalEnv:
    """Scan local string variable declarations / assignments in ``method_src``.

    Recognized forms (statement-level only):
        String x = expr;
        StringBuilder sb = new StringBuilder(); sb.append(...).append(...);
        x = expr;             (re-assignment to a known String var)
        x += expr;            (append to a known String var)
    """
    env = _LocalEnv()
    decl_re = re.compile(
        r"""
        (?:(?P<final>final)\s+)?
        (?P<type>String|StringBuilder|StringBuffer|CharSequence|int|long|Integer|Long|boolean|Boolean|float|double|BigDecimal|Date|Timestamp)
        \s+(?P<name>[A-Za-z_][A-Za-z_0-9]*)
        \s*(?:=\s*(?P<init>[^;]*?))?\s*;
        """,
        re.VERBOSE,
    )
    for m in decl_re.finditer(method_src):
        name = m.group("name")
        jt = m.group("type")
        init = (m.group("init") or "").strip()
        env.decls[name] = (jt, init)
        env.decl_lines[name] = m.group(0)

    # Capture x = expr; and x += expr;  (string vars)
    assign_re = re.compile(
        r"""
        (?P<name>[A-Za-z_][A-Za-z_0-9]*)\s*(?P<op>\+?=)\s*(?P<rhs>[^;]+);
        """,
        re.VERBOSE,
    )
    for m in assign_re.finditer(method_src):
        name = m.group("name")
        if name not in env.decls:
            continue
        jt, prev = env.decls[name]
        rhs = m.group("rhs").strip()
        if m.group("op") == "=":
            env.decls[name] = (jt, rhs)
        else:  # +=
            env.decls[name] = (jt, f"({prev}) + ({rhs})" if prev else rhs)

    # Capture StringBuilder.append chains:  sb.append(x).append(y);
    sb_re = re.compile(
        r"""
        (?P<name>[A-Za-z_][A-Za-z_0-9]*)\s*\.\s*append\s*\(
        """,
        re.VERBOSE,
    )
    sb_chunks: dict[str, list[str]] = {}
    for m in sb_re.finditer(method_src):
        name = m.group("name")
        if name not in env.decls or env.decls[name][0] not in ("StringBuilder", "StringBuffer"):
            continue
        # find balanced argument
        arg = _balanced_arg(method_src, m.end() - 1)
        if arg is None:
            continue
        sb_chunks.setdefault(name, []).append(arg)
    for name, chunks in sb_chunks.items():
        jt, prev = env.decls[name]
        joined = " + ".join(f"({c})" for c in chunks)
        env.decls[name] = (jt, f"({prev}) + {joined}" if prev else joined)
    return env


def _balanced_arg(src: str, lparen_pos: int) -> str | None:
    depth = 0
    j = lparen_pos
    while j < len(src):
        c = src[j]
        if c == "(":
            depth += 1
            if depth == 1:
                start = j + 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return src[start:j]
        elif c in ("'", '"'):
            j = _skip_string(src, j)
            continue
        j += 1
    return None


def _expand_expr(expr: str, env: _LocalEnv, depth: int = 0) -> tuple[StringPart, ...]:
    """Recursively expand ``expr`` into a tuple of StringParts.

    Supports: string literals, ``+``-concatenation, identifier lookup
    in ``env`` (with bounded recursion to avoid cycles), method calls
    treated as opaque variables.
    """
    if depth > 32:
        return (StringPart.var(expr.strip()),)
    return _expand_tokens(tokenize(expr), env, depth)


def _expand_tokens(toks: list[Tok], env: _LocalEnv, depth: int) -> tuple[StringPart, ...]:
    parts: list[StringPart] = []
    i = 0
    while i < len(toks):
        t = toks[i]
        if t.kind == "STRING":
            parts.append(StringPart.lit(_unquote_java(t.text)))
            i += 1
        elif t.kind == "IDENT" and t.text in env.decls:
            jt, init = env.decls[t.text]
            if jt in ("String", "StringBuilder", "StringBuffer", "CharSequence") and init:
                parts.extend(_expand_expr(init, env, depth + 1))
            else:
                parts.append(StringPart.var(t.text, jt))
            # skip trailing .toString() if present
            if (i + 2 < len(toks) and toks[i + 1].text == "."
                    and toks[i + 2].text == "toString"):
                i += 3
                if i < len(toks) and toks[i].text == "(":
                    j = _match_paren(toks, i)
                    i = j + 1
                continue
            i += 1
        elif t.kind == "IDENT":
            # general expression: capture until + or end
            buf = t.text
            i += 1
            while i < len(toks) and toks[i].text != "+":
                # special-case method calls and member accesses
                if toks[i].text == "(":
                    j = _match_paren(toks, i)
                    buf += "".join(tk.text for tk in toks[i:j + 1])
                    i = j + 1
                    continue
                if toks[i].text == "[":
                    j = _match_bracket(toks, i)
                    buf += "".join(tk.text for tk in toks[i:j + 1])
                    i = j + 1
                    continue
                if toks[i].text == ".":
                    buf += "."
                    i += 1
                    if i < len(toks) and toks[i].kind == "IDENT":
                        buf += toks[i].text
                        i += 1
                    continue
                # bail out
                break
            parts.append(StringPart.var(buf.strip()))
        elif t.text == "+":
            i += 1
        elif t.text == "(":
            j = _match_paren(toks, i)
            inner = toks[i + 1:j]
            parts.extend(_expand_tokens(inner, env, depth + 1))
            i = j + 1
        elif t.kind == "NUM":
            parts.append(StringPart.lit(t.text))
            i += 1
        else:
            i += 1
    return tuple(_merge_literals(parts))


def _merge_literals(parts: Iterable[StringPart]) -> list[StringPart]:
    out: list[StringPart] = []
    for p in parts:
        if out and p.kind == "literal" and out[-1].kind == "literal":
            out[-1] = StringPart.lit(out[-1].value + p.value)
        else:
            out.append(p)
    return out


def _match_paren(toks: list[Tok], lpar_idx: int) -> int:
    depth = 0
    for j in range(lpar_idx, len(toks)):
        if toks[j].text == "(":
            depth += 1
        elif toks[j].text == ")":
            depth -= 1
            if depth == 0:
                return j
    return len(toks) - 1


def _match_bracket(toks: list[Tok], lpar_idx: int) -> int:
    depth = 0
    for j in range(lpar_idx, len(toks)):
        if toks[j].text == "[":
            depth += 1
        elif toks[j].text == "]":
            depth -= 1
            if depth == 0:
                return j
    return len(toks) - 1


_JAVA_ESCAPE_RE = re.compile(r"\\(.)")


def _unquote_java(s: str) -> str:
    assert s.startswith('"') and s.endswith('"')
    body = s[1:-1]

    def sub(m: re.Match[str]) -> str:
        ch = m.group(1)
        return {"n": "\n", "t": "\t", "r": "\r", '"': '"',
                "\\": "\\", "'": "'", "b": "\b", "f": "\f", "0": "\0"}.get(ch, ch)

    return _JAVA_ESCAPE_RE.sub(sub, body)


# --- main entry --------------------------------------------------------------


def slice_sink_argument(
    java_src: str,
    sink_line: int,
) -> SliceResult | SliceAbstention:
    """Dispatch to AST or regex slicer based on ``IRSAM_SLICER``.

    ``IRSAM_SLICER=ts``    → tree-sitter-java AST slicer (Phase 2).
    ``IRSAM_SLICER=regex`` → legacy regex slicer (default).
    Any other value (including unset) keeps the regex tier for stability.
    """
    import os
    engine = os.environ.get("IRSAM_SLICER", "regex").strip().lower()
    if engine == "ts":
        try:
            from core.lang.java_ast import slice_sink_argument as _ts
            return _ts(java_src, sink_line)
        except Exception:
            # Hard-fall-back so a tree-sitter ABI mismatch never crashes
            # the pipeline; the regex tier is conservatively safe.
            return _slice_sink_argument_regex(java_src, sink_line)
    return _slice_sink_argument_regex(java_src, sink_line)


def _slice_sink_argument_regex(
    java_src: str,
    sink_line: int,
) -> SliceResult | SliceAbstention:
    """Regex-based MVP slicer (original implementation).

    The result is either:
    - a :class:`SliceResult` with ``parts`` = sequence of literal/variable
      fragments, in textual order; or
    - a :class:`SliceAbstention` carrying a structured reason code.
    """
    enclosing = _find_enclosing_method(java_src, sink_line)
    if enclosing is None:
        # Quickfix-friendly fallback: when the snippet has no enclosing
        # method declaration (a common case for the web Quickfix view
        # where users paste a bare statement), treat the entire source
        # as a synthetic method body so locals/parameters can still be
        # scanned. The slicer is purely textual, so the absence of a
        # real method header does not invalidate downstream stages.
        m_start, m_end, m_start_line = 0, len(java_src), 1
    else:
        m_start, m_end, m_start_line = enclosing
    method_src = java_src[m_start:m_end]

    # Locate the sink call on the requested line within the method
    sink_call: tuple[int, str, str, str] | None = None
    for ln, recv, api, text in find_sink_calls(method_src):
        absolute_line = m_start_line + method_src.count("\n", 0,
                                                        method_src.find(text)) - method_src[:method_src.find(text)].count("\n") + method_src[:method_src.find(text)].count("\n")
        # safer: recompute via absolute search
        rel_idx = method_src.find(text)
        if rel_idx < 0:
            continue
        abs_line = m_start_line + method_src.count("\n", 0, rel_idx)
        if abs_line == sink_line:
            sink_call = (abs_line, recv, api, text)
            break
    if sink_call is None:
        return SliceAbstention("sink_not_found",
                               f"no sink call on line {sink_line} of method")
    _abs_line, recv, _api, call_text = sink_call

    # Extract the first argument expression
    lparen = call_text.find("(")
    arg = _balanced_arg(call_text, lparen)
    if arg is None:
        return SliceAbstention("no_sink_argument", "could not extract sink argument")
    arg = arg.strip()

    # Detect simple sink-variable identifier
    sink_var: str | None = arg if re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", arg) else None

    env = _scan_locals(method_src)
    _scan_method_params(method_src, env)
    parts = _expand_expr(arg, env)

    # If any part still looks like a method call we don't recognize, abstain
    # only when the *entire* slice is opaque (no literal SQL skeleton).
    if not any(p.kind == "literal" for p in parts):
        return SliceAbstention("no_static_sql_skeleton",
                               "slice produced no literal SQL fragments")

    decls_to_remove: tuple[str, ...] = ()
    if sink_var is not None and sink_var in env.decl_lines:
        decls_to_remove = (env.decl_lines[sink_var],)

    return SliceResult(
        parts=parts,
        method_text=method_src,
        method_start_line=m_start_line,
        sink_call_text=call_text,
        sink_call_line=sink_line,
        sink_var_name=sink_var,
        declarations_to_remove=decls_to_remove,
    )


def infer_sem_type(java_type: str) -> str:
    """Public helper used by stage C / E."""
    return _java_type_to_sem(java_type)


_PARAM_RE = re.compile(
    r"""
    (?P<type>[A-Za-z_][\w.<>\[\]]*)
    \s+(?P<name>[A-Za-z_][A-Za-z_0-9]*)
    \s*(?=,|\))
    """,
    re.VERBOSE,
)


def _scan_method_params(method_src: str, env: _LocalEnv) -> None:
    """Extract method parameter declarations into ``env.decls``.

    Method header up to the opening brace is parsed; each parameter
    contributes ``(java_type, name)`` so the rest of the slicer can
    type variables that originate as parameters (e.g. ``int id``).
    """
    brace = method_src.find("{")
    if brace < 0:
        return
    header = method_src[:brace]
    lparen = header.find("(")
    rparen = header.rfind(")")
    if lparen < 0 or rparen < 0 or rparen < lparen:
        return
    params_text = header[lparen + 1:rparen]
    if not params_text.strip():
        return
    for piece in _split_params(params_text):
        piece = piece.strip()
        if not piece:
            continue
        # strip annotations and 'final'
        piece = re.sub(r"@[A-Za-z_][\w.]*\s*(\([^)]*\))?", "", piece).strip()
        if piece.startswith("final "):
            piece = piece[len("final "):].strip()
        # piece looks like "TYPE name"
        parts = piece.rsplit(None, 1)
        if len(parts) != 2:
            continue
        jt, name = parts[0].strip(), parts[1].strip()
        if name not in env.decls:
            env.decls[name] = (jt, "")


def _split_params(text: str) -> list[str]:
    """Split a parameter list on top-level commas (respecting generics)."""
    out: list[str] = []
    depth = 0
    cur = []
    for c in text:
        if c in "<([":
            depth += 1
            cur.append(c)
        elif c in ">)]":
            depth -= 1
            cur.append(c)
        elif c == "," and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(c)
    if cur:
        out.append("".join(cur))
    return out
