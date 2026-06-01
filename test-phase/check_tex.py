"""Lightweight compile-safety checker for the IR-SAM .tex deliverables.

Not a TeX parser: it performs conservative structural checks that catch
the most common compile-breaking mistakes when no LaTeX engine is
available -- unbalanced \\begin/\\end environments, unbalanced math \\$
toggles (outside verbatim/listings), unbalanced braces, and \\cite/\\ref
keys with no matching \\bibitem/\\label.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ENV_BEGIN = re.compile(r"\\begin\{([^}]+)\}")
ENV_END = re.compile(r"\\end\{([^}]+)\}")
CITE = re.compile(r"\\cite\{([^}]+)\}")
BIBITEM = re.compile(r"\\bibitem\{([^}]+)\}")
LABEL = re.compile(r"\\label\{([^}]+)\}")
REF = re.compile(r"\\(?:ref|eqref|autoref)\{([^}]+)\}")


def strip_comments(line: str) -> str:
    out, esc = [], False
    for ch in line:
        if ch == "\\" and not esc:
            esc = True
            out.append(ch)
            continue
        if ch == "%" and not esc:
            break
        out.append(ch)
        esc = False
    return "".join(out)


def check(path: Path) -> list[str]:
    problems: list[str] = []
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()

    env_stack: list[tuple[str, int]] = []
    brace = 0
    dollar_open: int | None = None
    in_verbatim = False
    verbatim_envs = {"lstlisting", "verbatim", "Verbatim"}

    cleaned_chars: list[str] = []
    for i, raw in enumerate(lines, 1):
        line = strip_comments(raw)

        for m in ENV_BEGIN.finditer(line):
            env = m.group(1)
            env_stack.append((env, i))
            if env in verbatim_envs:
                in_verbatim = True
        for m in ENV_END.finditer(line):
            env = m.group(1)
            if not env_stack:
                problems.append(f"{path.name}:{i}: \\end{{{env}}} with empty stack")
            else:
                top, ln = env_stack.pop()
                if top != env:
                    problems.append(
                        f"{path.name}:{i}: \\end{{{env}}} does not match "
                        f"\\begin{{{top}}} (opened line {ln})")
            if env in verbatim_envs:
                in_verbatim = False

        if in_verbatim:
            continue

        # brace + dollar balance on non-verbatim text
        esc = False
        for ch in line:
            if esc:
                esc = False
                cleaned_chars.append(" ")
                continue
            if ch == "\\":
                esc = True
                cleaned_chars.append(" ")
                continue
            if ch == "{":
                brace += 1
            elif ch == "}":
                brace -= 1
                if brace < 0:
                    problems.append(f"{path.name}:{i}: unbalanced '}}'")
                    brace = 0
            elif ch == "$":
                if dollar_open is None:
                    dollar_open = i
                else:
                    dollar_open = None
            cleaned_chars.append(ch)

    if env_stack:
        for env, ln in env_stack:
            problems.append(f"{path.name}: unclosed \\begin{{{env}}} (line {ln})")
    if brace != 0:
        problems.append(f"{path.name}: net brace imbalance = {brace}")
    if dollar_open is not None:
        problems.append(f"{path.name}: unmatched inline $ opened at line {dollar_open}")

    # citation / reference resolution
    defined_cites = set(BIBITEM.findall(text))
    used_cites = set()
    for grp in CITE.findall(text):
        used_cites.update(k.strip() for k in grp.split(","))
    missing_cites = used_cites - defined_cites
    if missing_cites and (defined_cites or "\\bibliography" not in text):
        # only flag when a manual thebibliography is present
        if "\\begin{thebibliography}" in text:
            for k in sorted(missing_cites):
                problems.append(f"{path.name}: \\cite{{{k}}} has no \\bibitem")

    defined_labels = set(LABEL.findall(text))
    used_refs = set()
    for grp in REF.findall(text):
        used_refs.update(k.strip() for k in grp.split(","))
    for k in sorted(used_refs - defined_labels):
        problems.append(f"{path.name}: \\ref{{{k}}} has no \\label")

    return problems


def main(argv: list[str]) -> int:
    files = [Path(a) for a in argv[1:]]
    all_problems: list[str] = []
    for f in files:
        if not f.exists():
            all_problems.append(f"{f}: NOT FOUND")
            continue
        probs = check(f)
        if probs:
            all_problems.extend(probs)
        print(f"[{'FAIL' if probs else 'OK'}] {f.name}: "
              f"{len(probs)} issue(s)")
    if all_problems:
        print("\n--- issues ---")
        for p in all_problems:
            print(p)
        return 1
    print("\nAll files passed structural checks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
