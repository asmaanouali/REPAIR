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
structurally from the command skeleton. They properly handle
intra-token concatenation (e.g., ``--flag=$vN``) and attacker-controlled
program names by cleanly separating arguments in the `argv` list.
"""

from __future__ import annotations

import difflib
import re
import shlex

from core.phi import PatchPlan
from core.rewriter import PatchResult, RewriteAbstention
from core.slicer import SliceResult, StringPart


# --- argv reconstruction (shared) --------------------------------------------


def _build_argv_items(parts: tuple[StringPart, ...]) -> list[list[tuple[str, str]]]:
    """Reconstruct an argv vector from the slice's literal/var parts.

    Returns a list of tokens, where each token is a list of
    ``("lit", string)`` or ``("expr", host_expr)`` pieces.

    Fix #6: When ``shlex.split`` fails (because a variable placeholder
    introduced unmatched quotes), we fall back to splitting only on the
    whitespace of the literal portions via :func:`_fallback_split`.
    A pure-variable token (the entire argv word is attacker-controlled)
    is always kept as a single element — the OS ``execve`` never
    shell-lex-splits individual argv entries, so no further splitting
    of variable values is possible or correct.
    """
    magic = "___IRSAM_VAR_{}___"
    combined = ""
    var_map = {}
    for i, p in enumerate(parts):
        if p.kind == "literal":
            combined += p.value
        else:
            ph = magic.format(i)
            var_map[ph] = p.value.strip()
            combined += ph

    try:
        toks = shlex.split(combined)
    except ValueError:
        # Fix #6: shlex failed; use the literal-whitespace fallback.
        toks = _fallback_split(combined)

    if not toks:
        raise RewriteAbstention("shell: empty argv vector")

    pattern = re.compile(r"(___IRSAM_VAR_\d+___)")
    items: list[list[tuple[str, str]]] = []
    
    for t in toks:
        sub_parts: list[tuple[str, str]] = []
        for piece in pattern.split(t):
            if not piece:
                continue
            if piece in var_map:
                sub_parts.append(("expr", var_map[piece]))
            else:
                sub_parts.append(("lit", piece))
        items.append(sub_parts)
        
    return items


def _fallback_split(combined: str) -> list[str]:
    """Whitespace-split a string that may contain IRSAM var placeholders.

    Fix #6: Used when shlex.split fails.  We split on runs of whitespace
    that appear between non-placeholder characters, so that a placeholder
    is always kept with any surrounding non-space literal text
    (e.g. ``--flag=___IRSAM_VAR_0___`` stays as one token).
    A placeholder surrounded entirely by whitespace becomes its own token.
    """
    segments = re.split(r"(\s+)", combined)
    toks: list[str] = []
    for seg in segments:
        if not seg or seg.isspace():
            continue
        toks.append(seg)
    return toks if toks else [""]


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
    
    arg_srcs = []
    for token_parts in items:
        if not token_parts:
            arg_srcs.append('""')
            continue
            
        if len(token_parts) == 1:
            kind, v = token_parts[0]
            if kind == "lit":
                arg_srcs.append(_java_str_literal(v))
            else:
                arg_srcs.append(f"String.valueOf({v})")
        else:
            concat = []
            for i, (kind, v) in enumerate(token_parts):
                if kind == "lit":
                    concat.append(_java_str_literal(v))
                else:
                    if i == 0:
                        concat.append(f"String.valueOf({v})")
                    else:
                        concat.append(v)
            arg_srcs.append(" + ".join(concat))
            
    args_src = ", ".join(arg_srcs)
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

# --- Python ------------------------------------------------------------------

def synthesize_python_shell_patch(
    src: str,
    slice_: SliceResult,
    plan: PatchPlan,
) -> PatchResult:
    """Rewrite a Python shell sink to ``subprocess.run(argv)`` or ``subprocess.call(argv)``."""
    call = slice_.sink_call_text
    if call not in src:
        raise RewriteAbstention("python_shell: could not locate sink call text")

    open_paren = call.find("(")
    funcname = call[:open_paren].strip()
    
    items = _build_argv_items(slice_.parts)
    
    arg_srcs = []
    for token_parts in items:
        if not token_parts:
            arg_srcs.append('""')
            continue
            
        if len(token_parts) == 1:
            kind, v = token_parts[0]
            if kind == "lit":
                arg_srcs.append(_python_str_literal(v))
            else:
                arg_srcs.append(f"str({v})")
        else:
            concat = []
            for i, (kind, v) in enumerate(token_parts):
                if kind == "lit":
                    concat.append(_python_str_literal(v))
                else:
                    concat.append(f"str({v})")
            arg_srcs.append(" + ".join(concat))
            
    args_src = "[" + ", ".join(arg_srcs) + "]"
    
    body = call[open_paren + 1: call.rfind(")")]
    args = _split_top_level_args(body)
    
    new_kwargs = []
    for a in args[1:]:
        if not a.replace(" ", "").startswith("shell=True"):
            new_kwargs.append(a)
            
    if funcname.endswith("run") or funcname.endswith("call") or funcname.endswith("Popen"):
        pass # args_src is the first arg
    elif funcname.endswith("system"):
        funcname = funcname.replace("system", "call")
        funcname = funcname.replace("os.", "subprocess.")
    elif funcname.endswith("popen"):
        funcname = funcname.replace("popen", "Popen")
        funcname = funcname.replace("os.", "subprocess.")
        new_kwargs.append("stdout=subprocess.PIPE")
        new_kwargs.append("text=True")
        
    final_args = [args_src] + new_kwargs
    new_call = f"{funcname}(" + ", ".join(final_args) + ")"

    patched = src.replace(call, new_call, 1)
    
    used_imports = ("import subprocess",)
    
    return PatchResult(
        original_source=src,
        patched_source=patched,
        unified_diff=_unified_diff(src, patched),
        connection_var="",
        used_imports=used_imports,
    )

def _python_str_literal(s: str) -> str:
    esc = s.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{esc}"'
