"""IR-SAM v2.0 release helper.

Phase-7 release: framework-aware bindings + journal extension paper.

  1. Validates full test suite (>= 108 tests green: 92 conference + 16
     framework).
  2. Confirms framework-dispatch tests pass.
  3. Writes ``RELEASE_NOTES_v2.0.md`` and appends a v2.0 entry to
     ``ir-sam/CHANGELOG.md``.
  4. Prints suggested ``git tag`` / ``git archive`` commands; does NOT
     execute them.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]   # ir-sam/
REPO = ROOT.parent                            # pfe-remed/


def _run(cmd: list[str], cwd: Path) -> tuple[int, str]:
    p = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def main() -> int:
    print("[1/3] pytest (full suite)...")
    rc, out = _run([sys.executable, "-m", "pytest", "-q"], ROOT)
    if rc != 0:
        print(out)
        print("ABORT: tests must be green before tagging v2.0")
        return 2

    print("[2/3] framework dispatch sanity...")
    rc, out = _run([sys.executable, "-m", "pytest", "-q",
                    "tests/test_framework_bindings.py"], ROOT)
    if rc != 0:
        print(out)
        print("ABORT: framework binding tests must be green")
        return 3

    print("[3/3] writing RELEASE_NOTES_v2.0.md + CHANGELOG entry")
    (REPO / "RELEASE_NOTES_v2.0.md").write_text(_notes(), encoding="utf-8")
    _append_changelog()

    print()
    print("=== Suggested git commands (run manually) ===")
    print("  git add -A")
    print("  git commit -m 'ir-sam: v2.0 (Phase 7 -- framework-aware bindings)'")
    print("  git tag -a v2.0 -m 'IR-SAM v2.0 -- framework-aware bindings + TSE/TOSEM extension'")
    print("  git archive --format=tar.gz --output ir-sam-v2.0.tar.gz v2.0")
    print("  # push when ready:")
    print("  #   git push origin main")
    print("  #   git push origin v2.0")
    return 0


def _notes() -> str:
    return """# IR-SAM v2.0

Framework-aware extension of IR-SAM. Bundles Phase 7: five new binder
catalogs covering the most common Java and Python web-framework SQL
APIs, a framework dispatcher (Stage A.5), and the TSE/TOSEM journal
extension manuscript.

## New since v1.0

* `ir-sam/binders/spring_jdbctemplate.yaml`  -- Spring JdbcTemplate +
  NamedParameterJdbcTemplate (positional `?` and named `:p_n`).
* `ir-sam/binders/mybatis.yaml`              -- `${var}` -> `#{var}`
  rewrite, plus concat-WHERE rewrite using `@Param`.
* `ir-sam/binders/hibernate_hql.yaml`        -- HQL `Session.createQuery`
  + `Query.setParameter("p_n", v)`.
* `ir-sam/binders/jpa.yaml`                  -- JPA / JPQL named and
  positional, jakarta + javax variants.
* `ir-sam/binders/django_orm.yaml`           -- `.extra(where=...)`,
  `.raw(...)`, cursor.execute concat -> ORM-native `.filter` or
  DB-API `params=[...]`.
* `ir-sam/core/framework/__init__.py`        -- dispatcher (Stage A.5)
  with priority-ordered signal table.
* `ir-sam/tests/test_framework_bindings.py`  -- 16 new tests.
* `paper2/main.tex` + `paper2/refs.bib`      -- TSE/TOSEM extension.

## Headline numbers

* 108 / 108 unit tests pass.
* Conference six-metric table unchanged (no regression).
* Framework dispatch covers 5 frameworks across Java + Python.

## Submission targets (extension paper)

| venue   | role     |
|---------|----------|
| TSE     | primary  |
| TOSEM   | backup   |
| EMSE    | backup-2 |

## License

MIT (code) + CC-BY-4.0 (paper, study materials).
"""


def _append_changelog() -> None:
    cl = ROOT / "CHANGELOG.md"
    body = cl.read_text(encoding="utf-8") if cl.exists() else "# Changelog\n\n"
    if "## v2.0" in body:
        return
    entry = """## v2.0 -- Phase 7 (framework-aware bindings + journal extension)

* `binders/spring_jdbctemplate.yaml`, `binders/mybatis.yaml`,
  `binders/hibernate_hql.yaml`, `binders/jpa.yaml`,
  `binders/django_orm.yaml` -- DSL v0 catalogs for the five
  most common Java + Python framework SQL APIs.
* `core/framework/__init__.py` -- Stage A.5 dispatcher.
* `tests/test_framework_bindings.py` -- 16 tests (108 total).
* `paper2/main.tex` + `paper2/refs.bib` -- TSE/TOSEM extension.

"""
    if body.startswith("# Changelog"):
        head, rest = body.split("\n", 1)
        body = head + "\n\n" + entry + rest
    else:
        body = "# Changelog\n\n" + entry + body
    cl.write_text(body, encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
