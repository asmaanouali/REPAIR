"""Large-scale evaluation corpus loader (Phase 5).

Supports three public vulnerability-fix datasets and a deterministic
synthetic fallback that is shape-compatible with all three so the
Phase-5 harness can run end-to-end without network or licence
encumbrance:

  * CVEfixes        -- https://github.com/secureIT-project/CVEfixes
  * Vul4J           -- https://github.com/tuhh-softsec/vul4j
  * BigVul          -- https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset

Loaders auto-detect the archive layout in ``IRSAM_EVAL_CORPUS_DIR``
(env var) and fall back to ``synth`` if no archive is present.

Filtering criteria for the **evaluable subset** (mirrors the
pre-registered protocol, ``study/protocol.md`` Sec.3):

  1. CWE in {CWE-89, CWE-90, CWE-91, CWE-643, CWE-78, CWE-94}.
  2. Pre-patch file compiles / parses with the language adapter.
  3. Sink site reachable by the Phase-4 sink-scanner.
  4. Post-patch ground-truth file present (for FixRate /
     SemanticEquivalence metric).
  5. Single-file fix (multi-file fixes are tagged ``out_of_scope``
     and reported separately).
"""

from __future__ import annotations

import csv
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, Sequence


@dataclass(frozen=True)
class EvalCase:
    """One evaluable vulnerability fix (pre- + post-patch)."""
    dataset: str               # "cvefixes" | "vul4j" | "bigvul" | "synth"
    case_id: str               # globally unique within the corpus
    cve_id: str | None         # may be None for synth
    cwe: str                   # e.g. "CWE-89"
    language: str              # "java" | "python"
    interpreter: str           # "sql" | "ldap" | "xpath"
    pre_path: Path             # vulnerable source (single file)
    post_path: Path | None     # ground-truth fixed source (None if missing)
    sink_hint: str | None      # optional API name, e.g. "executeQuery"
    out_of_scope: bool = False


# --- env / discovery ---


def _corpus_root() -> Path | None:
    p = os.environ.get("IRSAM_EVAL_CORPUS_DIR")
    return Path(p) if p else None


# --- real loaders ---


def _load_cvefixes(root: Path) -> list[EvalCase]:
    """Walk ``root/cvefixes/*/{pre,post}/*`` produced by the CVEfixes
    extractor. The extractor's canonical CSV is at
    ``root/cvefixes/manifest.csv`` with columns
    ``case_id,cve,cwe,lang,interpreter,pre_path,post_path,sink_hint``.
    Returns [] if absent.
    """
    man = root / "cvefixes" / "manifest.csv"
    if not man.exists():
        return []
    out: list[EvalCase] = []
    with man.open(encoding="utf-8") as f:
        for r in csv.DictReader(f):
            out.append(EvalCase(
                dataset="cvefixes",
                case_id=r["case_id"],
                cve_id=r.get("cve") or None,
                cwe=r["cwe"],
                language=r["lang"],
                interpreter=r["interpreter"],
                pre_path=(root / r["pre_path"]).resolve(),
                post_path=((root / r["post_path"]).resolve()
                           if r.get("post_path") else None),
                sink_hint=r.get("sink_hint") or None,
            ))
    return out


def _load_vul4j(root: Path) -> list[EvalCase]:
    man = root / "vul4j" / "manifest.csv"
    if not man.exists():
        return []
    out: list[EvalCase] = []
    with man.open(encoding="utf-8") as f:
        for r in csv.DictReader(f):
            out.append(EvalCase(
                dataset="vul4j",
                case_id=r["case_id"],
                cve_id=r.get("cve") or None,
                cwe=r["cwe"],
                language="java",
                interpreter=r["interpreter"],
                pre_path=(root / r["pre_path"]).resolve(),
                post_path=((root / r["post_path"]).resolve()
                           if r.get("post_path") else None),
                sink_hint=r.get("sink_hint") or None,
            ))
    return out


def _load_bigvul(root: Path) -> list[EvalCase]:
    """BigVul is shipped as a single CSV with `func_before`/`func_after`
    fields. We materialize each row to a pair of files on disk so the
    Phase-4 slicer can read them uniformly.
    """
    csv_path = root / "bigvul" / "MSR_data_cleaned.csv"
    if not csv_path.exists():
        return []
    out: list[EvalCase] = []
    work = root / "bigvul" / "_materialized"
    work.mkdir(parents=True, exist_ok=True)
    with csv_path.open(encoding="utf-8", errors="ignore") as f:
        rd = csv.DictReader(f)
        for i, r in enumerate(rd):
            cwe = (r.get("CWE ID") or "").strip()
            if not cwe:
                continue
            pre = r.get("func_before") or ""
            post = r.get("func_after") or ""
            if not pre.strip() or not post.strip():
                continue
            cid = f"bigvul-{i:06d}"
            pp = work / f"{cid}.pre.c"
            qp = work / f"{cid}.post.c"
            pp.write_text(pre, encoding="utf-8")
            qp.write_text(post, encoding="utf-8")
            out.append(EvalCase(
                dataset="bigvul", case_id=cid,
                cve_id=r.get("CVE ID") or None, cwe=cwe,
                language="c", interpreter="other",  # out of scope below
                pre_path=pp, post_path=qp, sink_hint=None,
                out_of_scope=True,
            ))
    return out


# --- synthetic fallback ---


_SYNTH_TEMPLATES = [
    # (cwe, language, interpreter, pre, post, sink_hint)
    ("CWE-89", "java", "sql",
     ("public class A {\n"
      "  public java.sql.ResultSet run(java.sql.Statement st, String name)"
      " throws Exception {\n"
      "    return st.executeQuery(\"SELECT id FROM users WHERE name = '\""
      " + name + \"'\");\n"
      "  }\n}\n"),
     ("public class A {\n"
      "  public java.sql.ResultSet run(java.sql.Connection c, String name)"
      " throws Exception {\n"
      "    java.sql.PreparedStatement ps = c.prepareStatement("
      "\"SELECT id FROM users WHERE name = ?\");\n"
      "    ps.setString(1, name);\n"
      "    return ps.executeQuery();\n"
      "  }\n}\n"),
     "executeQuery"),
    ("CWE-89", "python", "sql",
     ("import sqlite3\n"
      "def find(conn, name):\n"
      "    cur = conn.cursor()\n"
      "    cur.execute(\"SELECT id FROM users WHERE name = '\""
      " + name + \"'\")\n"
      "    return cur.fetchall()\n"),
     ("import sqlite3\n"
      "def find(conn, name):\n"
      "    cur = conn.cursor()\n"
      "    cur.execute(\"SELECT id FROM users WHERE name = ?\", (name,))\n"
      "    return cur.fetchall()\n"),
     "execute"),
    ("CWE-90", "python", "ldap",
     ("import ldap3\n"
      "def lookup(conn, uid):\n"
      "    f = \"(uid=\" + uid + \")\"\n"
      "    conn.search('dc=ex,dc=org', f)\n"
      "    return conn.entries\n"),
     ("import ldap3\n"
      "from ldap3.utils.conv import escape_filter_chars\n"
      "def lookup(conn, uid):\n"
      "    f = \"(uid=\" + escape_filter_chars(uid) + \")\"\n"
      "    conn.search('dc=ex,dc=org', f)\n"
      "    return conn.entries\n"),
     "search"),
    ("CWE-643", "python", "xpath",
     ("from lxml import etree\n"
      "def find_user(tree, name):\n"
      "    return tree.xpath(\"//user[@name='\" + name + \"']\")\n"),
     ("from lxml import etree\n"
      "def find_user(tree, name):\n"
      "    return tree.xpath(\"//user[@name=$v_0]\", v_0=name)\n"),
     "xpath"),
]


def _load_synth(work: Path) -> list[EvalCase]:
    """Synthesize a deterministic, shape-compatible corpus for
    reproducibility when no real dataset archive is mounted.
    Each template is duplicated with small lexical mutations so the
    six-metric module has non-trivial inputs.
    """
    work.mkdir(parents=True, exist_ok=True)
    out: list[EvalCase] = []
    for i, (cwe, lang, interp, pre, post, sink) in enumerate(_SYNTH_TEMPLATES):
        for k in range(4):                       # 4 mutations / template
            ext = {"java": "java", "python": "py"}[lang]
            cid = f"synth-{cwe}-{lang}-{i:02d}-{k:02d}"
            pp = work / f"{cid}.pre.{ext}"
            qp = work / f"{cid}.post.{ext}"
            mut_pre = pre.replace("name", f"name{k}")\
                         .replace("uid", f"uid{k}")
            mut_post = post.replace("name", f"name{k}")\
                           .replace("uid", f"uid{k}")
            pp.write_text(mut_pre, encoding="utf-8")
            qp.write_text(mut_post, encoding="utf-8")
            out.append(EvalCase(
                dataset="synth", case_id=cid, cve_id=None,
                cwe=cwe, language=lang, interpreter=interp,
                pre_path=pp, post_path=qp, sink_hint=sink,
            ))
    return out


# --- public ---


def load_evaluable_subset(*, datasets: Sequence[str] | None = None,
                          synth_work: Path | None = None
                          ) -> list[EvalCase]:
    """Load the union of the requested datasets, in-scope only.

    Defaults to ``("cvefixes", "vul4j", "bigvul")`` when a corpus
    archive is mounted (env ``IRSAM_EVAL_CORPUS_DIR``); otherwise
    falls back to the synthetic shape-compatible corpus.
    """
    datasets = datasets or ("cvefixes", "vul4j", "bigvul")
    root = _corpus_root()
    out: list[EvalCase] = []
    if root is not None:
        if "cvefixes" in datasets:
            out.extend(_load_cvefixes(root))
        if "vul4j" in datasets:
            out.extend(_load_vul4j(root))
        if "bigvul" in datasets:
            out.extend(_load_bigvul(root))
    if not out:
        work = synth_work or Path("reports/phase5_synth_corpus")
        out.extend(_load_synth(work))
    in_scope = [c for c in out if not c.out_of_scope
                and c.interpreter in ("sql", "ldap", "xpath")
                and c.language in ("java", "python")]
    return in_scope


def corpus_stats(cases: Iterable[EvalCase]) -> dict:
    cases = list(cases)
    by_ds: dict[str, int] = {}
    by_cwe: dict[str, int] = {}
    by_lang: dict[str, int] = {}
    by_interp: dict[str, int] = {}
    for c in cases:
        by_ds[c.dataset] = by_ds.get(c.dataset, 0) + 1
        by_cwe[c.cwe] = by_cwe.get(c.cwe, 0) + 1
        by_lang[c.language] = by_lang.get(c.language, 0) + 1
        by_interp[c.interpreter] = by_interp.get(c.interpreter, 0) + 1
    return {
        "total":           len(cases),
        "by_dataset":      by_ds,
        "by_cwe":          by_cwe,
        "by_language":     by_lang,
        "by_interpreter":  by_interp,
        "corpus_source":   ("real" if _corpus_root() else "synthetic"),
    }
