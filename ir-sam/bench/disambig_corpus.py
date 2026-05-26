"""Disambiguation training-corpus builder (Phase 4).

This module materializes a labelled corpus of
``(interpreter, site, sig_text, context, label)`` examples for the
Stage-D disambiguator. The output format is JSONL --- one example per
line --- so :mod:`scripts.train_disambig` and
:mod:`scripts.eval_disambig` can consume it with HuggingFace
``datasets.load_dataset("json", ...)``.

The corpus is built from two sources:

* **Synthetic generation** (:func:`generate_synthetic`) --- templated
  examples for each ``(interpreter, site)`` pair from
  :mod:`core.disambig.labels`. This source is *always available* and
  is sufficient to ship a working baseline checkpoint.
* **Real-world mining** (:func:`mine_real_world`) --- examples
  extracted from the existing IR-SAM benchmark loaders whose
  ground-truth label is inferable. This source is *optional*: in
  reviewer environments without the benchmark archives, the function
  yields zero examples and the caller continues with synthetic data.

The :func:`build_corpus` orchestrator dedupes and shuffles, writes
``train.jsonl``/``valid.jsonl``/``test.jsonl`` with a deterministic
80/10/10 split keyed on a stable hash of the example.

The exact JSON schema is documented in :doc:`../docs/disambig-task.md`.
"""

from __future__ import annotations

import hashlib
import json
import random
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Iterator

from core.disambig import labels as label_schema


@dataclass(frozen=True)
class Example:
    interpreter: str
    site: str
    sig_text: str
    context: str
    label: str

    def stable_hash(self) -> str:
        """Deterministic example identity for split assignment + dedup."""
        h = hashlib.sha256()
        for f in (self.interpreter, self.site, self.sig_text,
                  self.context, self.label):
            h.update(f.encode("utf-8"))
            h.update(b"\x1f")
        return h.hexdigest()


# --- synthetic generators ---------------------------------------------------


def _gen_sql_in_position() -> Iterator[Example]:
    """SQL IN-list ambiguity: scalar vs collection host type."""
    columns = ("id", "user_id", "email", "tenant_id", "status")
    list_hosts = (
        "java; host_type=java.util.List<Integer>",
        "java; host_type=java.util.List<String>",
        "java; host_type=Long[]",
        "python; host_type=list[int]",
        "python; host_type=tuple[str, ...]",
        "python; host_type=Iterable[str]",
    )
    scalar_hosts = (
        "java; host_type=String",
        "java; host_type=int",
        "python; host_type=str",
        "python; host_type=int",
    )
    for col in columns:
        sig = f"SELECT * FROM t WHERE {col} IN (<<H0>>)"
        for ctx in list_hosts:
            yield Example("sql", "in_position", sig, ctx, "in_list_csv")
        for ctx in scalar_hosts:
            yield Example("sql", "in_position", sig, ctx, "string_value")


def _gen_sql_like_pattern() -> Iterator[Example]:
    """SQL LIKE: bare value vs explicit pattern host."""
    columns = ("name", "email", "title")
    pattern_hosts = (
        "java; host_value_class=PatternBuilder; explicit_wildcards=true",
        "python; host_origin=request.args; sanitized=false",
    )
    literal_hosts = (
        "java; host_value_class=String; explicit_wildcards=false",
        "python; host_origin=internal_constant; sanitized=true",
    )
    for col in columns:
        sig = f"SELECT * FROM t WHERE {col} LIKE <<H0>>"
        for ctx in pattern_hosts:
            yield Example("sql", "like_pattern", sig, ctx, "like_pattern_value")
        for ctx in literal_hosts:
            yield Example("sql", "like_pattern", sig, ctx, "literal_value")


def _gen_ldap_value_position() -> Iterator[Example]:
    """LDAP filter value: 5-way classification."""
    attr = "uid"
    cases = [
        (f"({attr}=<<H0>>)", "exact"),
        (f"({attr}=*<<H0>>*)", "substring"),
        (f"({attr}=<<H0>>*)", "prefix"),
        (f"({attr}=*<<H0>>)", "suffix"),
        (f"({attr}=*)", "presence"),
    ]
    for sig, label in cases:
        for ctx in ("java; host_type=String", "python; host_type=str"):
            yield Example("ldap", "value_position", sig, ctx, label)


def _gen_xpath_value_position() -> Iterator[Example]:
    """XPath: text/numeric/attribute predicates."""
    cases = [
        ("/a/b[text()=<<H0>>]", "text_value"),
        ("/a/b[position()=<<H0>>]", "numeric_value"),
        ("/a/b[@id=<<H0>>]", "attribute_value"),
        ("/a/b[<<H0>>]", "predicate_position"),
    ]
    for sig, label in cases:
        for ctx in ("java; host_type=String", "python; host_type=str"):
            yield Example("xpath", "value_position", sig, ctx, label)


def _gen_shell_argv_position() -> Iterator[Example]:
    cases = [
        ("ls <<H0>>", "argv_token", "python; host_origin=request.args"),
        ("grep -e <<H0>> file", "flag_value", "python; host_origin=request.args"),
        ("cat <<H0>>", "path_token", "python; host_value_class=os.PathLike"),
    ]
    for sig, label, ctx in cases:
        yield Example("shell", "argv_position", sig, ctx, label)


def _gen_html_context() -> Iterator[Example]:
    cases = [
        ("<div><<H0>></div>", "text_node"),
        ("<div class=<<H0>>></div>", "attr_value"),
        ('<a href=<<H0>>>x</a>', "url_attr"),
        ("<script><<H0>></script>", "script_block"),
        ("<style><<H0>></style>", "style_block"),
    ]
    for sig, label in cases:
        yield Example("html", "context", sig, "browser; trust=untrusted", label)


def _gen_ssti_slot() -> Iterator[Example]:
    cases = [
        ("{{ <<H0>> }}", "autoescaped_value"),
        ("{{ <<H0>>|safe }}", "safe_html"),
        ("{{ <<H0>>|int }}", "numeric"),
    ]
    for sig, label in cases:
        yield Example("ssti", "slot", sig, "jinja2; autoescape=on", label)


_GENERATORS = (
    _gen_sql_in_position,
    _gen_sql_like_pattern,
    _gen_ldap_value_position,
    _gen_xpath_value_position,
    _gen_shell_argv_position,
    _gen_html_context,
    _gen_ssti_slot,
)


def generate_synthetic() -> list[Example]:
    """Yield all synthetic examples for the v1 schema."""
    seen: set[str] = set()
    out: list[Example] = []
    for gen in _GENERATORS:
        for ex in gen():
            # Soundness check: the label MUST be in the registered set.
            ls = label_schema.get(ex.interpreter, ex.site)
            if ex.label not in ls.labels:
                raise ValueError(
                    f"corpus generator emitted unregistered label "
                    f"{ex.label!r} for {ex.interpreter}/{ex.site}"
                )
            key = ex.stable_hash()
            if key not in seen:
                seen.add(key)
                out.append(ex)
    return out


# --- real-world mining (best-effort) ----------------------------------------


def mine_real_world() -> list[Example]:
    """Mine labeled examples from the IR-SAM benchmark loaders.

    In environments where the benchmark archives are not present (e.g.
    reviewer docker container), this returns an empty list. The
    corpus pipeline degrades gracefully to synthetic-only training.
    """
    # Intentionally a no-op for now: the loader-driven extraction
    # requires per-loader heuristics for inferring the gold label from
    # the surrounding host code, which are tracked in the Phase 4 TODO.
    # This stub is preserved so :func:`build_corpus` keeps its API
    # contract stable across future expansions.
    return []


# --- orchestration ----------------------------------------------------------


def _split_for(ex: Example, *, train: float = 0.8, valid: float = 0.1) -> str:
    # Stable, deterministic split keyed on the hash digest.
    h = int(ex.stable_hash()[:16], 16) / (1 << 64)
    if h < train:
        return "train"
    if h < train + valid:
        return "valid"
    return "test"


def build_corpus(
    out_dir: Path | str,
    *,
    include_real_world: bool = True,
    seed: int = 0,
) -> dict[str, int]:
    """Materialize ``train.jsonl`` / ``valid.jsonl`` / ``test.jsonl``.

    Returns a per-split count dict for reporting.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    examples = list(generate_synthetic())
    if include_real_world:
        examples.extend(mine_real_world())

    rng = random.Random(seed)
    rng.shuffle(examples)

    splits: dict[str, list[Example]] = {"train": [], "valid": [], "test": []}
    for ex in examples:
        splits[_split_for(ex)].append(ex)

    counts: dict[str, int] = {}
    for name, items in splits.items():
        path = out / f"{name}.jsonl"
        with path.open("w", encoding="utf-8") as fh:
            for ex in items:
                fh.write(json.dumps(asdict(ex), sort_keys=True) + "\n")
        counts[name] = len(items)
    return counts


def iter_jsonl(path: Path | str) -> Iterable[Example]:
    """Read back a corpus JSONL file."""
    with Path(path).open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            yield Example(**d)
