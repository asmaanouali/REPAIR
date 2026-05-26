"""Java sink detection (Phase 9).

Java-side database sinks are already covered by the legacy MVP slicer
(see ``core/lang_java.py``); this module adds the *additional* sinks
introduced by Phase 9:

* CWE-78 — OS command injection:
  - ``Runtime.getRuntime().exec(String)``
  - ``Runtime.getRuntime().exec(String[])`` (already safe but we tag it
    so the differential gate can confirm callers migrated correctly)
  - ``new ProcessBuilder(String...)``
  - ``new ProcessBuilder(List<String>)``
* CWE-1336 — SSTI:
  - ``TemplateEngine.process(String, IContext)`` (Thymeleaf)
  - ``Configuration.getTemplate(String).process(...)`` (FreeMarker)
* CWE-502 — deserialization:
  - ``ObjectInputStream.readObject()``
  - ``XMLDecoder.readObject()``
* CWE-22 — path traversal:
  - ``new File(String)`` (when the string is attacker-influenced)
  - ``Files.readAllBytes(Path)`` / ``Files.write(Path, ...)``

This module only declares the recognition surface; rewriting is handled
by the per-CWE binders in ``binders/java_*.yaml``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


# Method-call sinks (post-dot identifiers).
SINK_APIS = frozenset({
    # CWE-78
    "exec",                        # Runtime.exec
    "start",                       # ProcessBuilder.start
    # CWE-1336
    "process",                     # TemplateEngine.process
    # CWE-502
    "readObject",                  # ObjectInputStream.readObject
    # CWE-22
    "readAllBytes", "readString", "newBufferedReader",
    "write", "writeString",
})


_METHOD_SINK_RE = re.compile(
    r"""
    # Receiver: a name (optionally a ``new X(...)`` constructor) followed
    # by zero or more ``.member(args?)`` segments. Supports chains like
    # ``Runtime.getRuntime().exec`` and ``new ProcessBuilder(cmd).start``.
    (?P<recv>
        (?:new\s+[A-Za-z_$][\w$.]*\s*\([^()]*\))
      | (?:[A-Za-z_$][\w$.]*(?:\s*\([^()]*\))?)
    )
    (?:\s*\.\s*[A-Za-z_$][\w$]*(?:\s*\([^()]*\))?)*
    \s*\.\s*
    (?P<api>exec|start|process|readObject
           |readAllBytes|readString|newBufferedReader
           |write|writeString)
    \s*\(
    """,
    re.VERBOSE,
)


# Constructor sinks (``new X(...)``). Captured separately because the
# receiver is a type name, not a value.
_CTOR_SINK_RE = re.compile(
    r"""
    \bnew\s+
    (?P<cls>ProcessBuilder|File|FileInputStream|FileOutputStream
           |ObjectInputStream|XMLDecoder)
    \s*\(
    """,
    re.VERBOSE,
)


@dataclass(frozen=True)
class JavaSink:
    line: int
    kind: str                      # "method" | "ctor"
    receiver_or_class: str
    api_or_ctor: str
    call_text: str


def find_sink_calls(java_src: str) -> list[JavaSink]:
    out: list[JavaSink] = []
    for m in _METHOD_SINK_RE.finditer(java_src):
        line = java_src.count("\n", 0, m.start()) + 1
        out.append(JavaSink(
            line=line,
            kind="method",
            receiver_or_class=m.group("recv"),
            api_or_ctor=m.group("api"),
            call_text=_balanced_call(java_src, m.start()),
        ))
    for m in _CTOR_SINK_RE.finditer(java_src):
        line = java_src.count("\n", 0, m.start()) + 1
        out.append(JavaSink(
            line=line,
            kind="ctor",
            receiver_or_class=m.group("cls"),
            api_or_ctor=m.group("cls"),
            call_text=_balanced_call(java_src, m.start()),
        ))
    out.sort(key=lambda s: s.line)
    return out


def _balanced_call(src: str, start: int) -> str:
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
