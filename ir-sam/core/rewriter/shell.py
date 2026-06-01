"""Stage F --- OS-command (CWE-78) rewriters.

The shell rewrites turn a *string-concatenated command line* fed to a
shell into an **argv vector** passed directly to ``execve`` (no shell).
This is the structural mitigation proven by ``IRSAM.Soundness.Shell``:
when the program receives a pre-tokenized argument vector, the shell
lexer is never invoked on attacker bytes, so no new tokens (``;``,
``|``, ``$(...)``, ...) can appear in the program's word list.

Two host languages are supported:

* **Python** --- ``subprocess.run(cmd, shell=True)`` /
  ``os.system(cmd)`` lowered to ``subprocess.run([...], shell=False)``
  / ``subprocess.call([...])``.
* **Java** --- ``Runtime.getRuntime().exec(cmd)`` /
  ``new ProcessBuilder(cmd).start()`` lowered to
  ``new ProcessBuilder("p", "a", host).start()``.

The rewriters consume the :class:`~core.slicer.SliceResult` directly
(its ordered literal/variable ``parts``) rather than the
:class:`~core.phi.PatchPlan`, because the argv vector is reconstructed
structurally from the command skeleton. They **abstain**
(:class:`~core.rewriter.RewriteAbstention`) when an attacker-controlled
value is not aligned on an argv word boundary (i.e. it is concatenated
*inside* a token, which would let it inject flags/options), when the
program name (argv[0]) is itself attacker-controlled, or when the sink
shape cannot be losslessly converted (e.g. ``os.popen`` streams).
"""

from __future__ import annotations

import difflib
import re
import shlex

from core.phi import PatchPlan
from core.rewriter import PatchResult, RewriteAbstention
from core.slicer import SliceResult, StringPart


# --- argv reconstruction (shared) --------------------------------------------


def _build_argv_items(parts: tuple[StringPart, ...]) -> list[tuple[str, str]]:
    """Reconstruct an argv vector from the slice's literal/var parts.

    Returns a list of ``("lit", token)`` / ``("expr", host_expr)`` items
    in textual order. Raises :class:`RewriteAbstention` when an
    interpolation does not sit on a clean argv word boundary.
    """
    items: list[tuple[str, str]] = []
    n = len(parts)
    for i, p in enumerate(parts):
        if p.kind == "literal":
            try:
                toks = shlex.split(p.value)
            except ValueError as e:
                raise RewriteAbstention(f"shell: unparseable literal token: {e}")
            items.extend(("lit", t) for t in toks)
        else:  # variable / host expression
            prev_ok = i == 0 or (
                parts[i - 1].kind == "literal"
                and (parts[i - 1].value == "" or parts[i - 1].value[-1].isspace())
            )
            next_ok = i == n - 1 or (
                parts[i + 1].kind == "literal"
                and (parts[i + 1].value == "" or parts[i + 1].value[0].isspace())
            )
            if not (prev_ok and next_ok):
                raise RewriteAbstention(
                    "shell: attacker value is concatenated inside an argv "
                    "token; cannot guarantee word-boundary inertness"
                )
            items.append(("expr", p.value.strip()))
    if not items:
        raise RewriteAbstention("shell: empty argv vector")
    if items[0][0] != "lit":
        raise RewriteAbstention(
            "shell: program name (argv[0]) is attacker-controlled"
        )
    return items


def _split_top_level_args(body: str) -> list[str]:
    """Split a call-argument list on top-level commas."""
    out: list[str] = []
    depth = 0
    start = 0
    i = 0
    while i < len(body):
        c = body[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c in ("'", '"'):
            i = _skip_str(body, i)
            continue
        elif c == "," and depth == 0:
            out.append(body[start:i].strip())
            start = i + 1
        i += 1
    tail = body[start:].strip()
    if tail:
        out.append(tail)
    return out


def _skip_str(s: str, i: int) -> int:
    q = s[i]
    j = i + 1
    while j < len(s):
        if s[j] == "\\":
            j += 2
            continue
        if s[j] == q:
            return j + 1
        j += 1
    return j


def _unified_diff(original: str, patched: str, path: str = "source") -> str:
    return "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            patched.splitlines(keepends=True),
            fromfile=f"a/{path}", tofile=f"b/{path}",
        )
    )


# --- Python ------------------------------------------------------------------


def synthesize_python_shell_patch(
    src: str,
    slice_: SliceResult,
    plan: PatchPlan,
) -> PatchResult:
    """Rewrite a Python shell sink to a ``shell=False`` argv invocation."""
    if slice_.sink_call_text not in src:
        raise RewriteAbstention("python_shell: could not locate sink call text")

    items = _build_argv_items(slice_.parts)
    argv_src = "[" + ", ".join(
        repr(v) if kind == "lit" else v for kind, v in items
    ) + "]"

    call = slice_.sink_call_text
    open_paren = call.find("(")
    funcname = call[:open_paren].strip()
    body = call[open_paren + 1: call.rfind(")")]
    args = _split_top_level_args(body)

    used_imports: tuple[str, ...] = ()
    if funcname.endswith(".popen") or funcname == "popen":
        raise RewriteAbstention(
            "python_shell: os.popen stream semantics not auto-convertible"
        )
    if funcname.endswith(".system") or funcname == "system":
        new_call = f"subprocess.call({argv_src})"
        used_imports = ("import subprocess",)
    else:
        new_args = [argv_src]
        shell_seen = False
        for a in args[1:]:
            if re.match(r"\s*shell\s*=", a):
                new_args.append("shell=False")
                shell_seen = True
            else:
                new_args.append(a)
        if not shell_seen:
            new_args.append("shell=False")
        new_call = f"{funcname}(" + ", ".join(new_args) + ")"

    patched = src.replace(call, new_call, 1)
    if used_imports:
        patched = _ensure_python_import(patched, used_imports[0])

    return PatchResult(
        original_source=src,
        patched_source=patched,
        unified_diff=_unified_diff(src, patched),
        connection_var="",
        used_imports=used_imports,
    )


def _ensure_python_import(src: str, import_line: str) -> str:
    if re.search(rf"(?m)^\s*{re.escape(import_line)}\s*$", src):
        return src
    mod = import_line.split()[1]
    if re.search(rf"(?m)^\s*import\s+{re.escape(mod)}\b", src):
        return src
    return import_line + "\n" + src


# --- Java --------------------------------------------------------------------


def synthesize_java_shell_patch(
    src: str,
    slice_: SliceResult,
    plan: PatchPlan,
) -> PatchResult:
    """Rewrite a Java shell sink to ``new ProcessBuilder(argv).start()``."""
    if slice_.sink_call_text not in src:
        raise RewriteAbstention("java_shell: could not locate sink call text")

    items = _build_argv_items(slice_.parts)
    args_src = ", ".join(
        _java_str_literal(v) if kind == "lit" else v for kind, v in items
    )
    new_call = f"new ProcessBuilder({args_src}).start()"

    patched = src.replace(slice_.sink_call_text, new_call, 1)
    return PatchResult(
        original_source=src,
        patched_source=patched,
        unified_diff=_unified_diff(src, patched),
        connection_var="",
        used_imports=(),
    )


def _java_str_literal(s: str) -> str:
    esc = s.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{esc}"'
