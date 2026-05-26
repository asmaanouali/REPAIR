"""Disambiguation label-set schema (v1, frozen).

Each interpreter exposes a finite, mutually-exclusive set of labels
that a learned :class:`~core.disambig.Policy` may choose between when
the symbolic parser flags an ambiguous-intent point.

The schema is frozen at ``v1``: adding new labels requires bumping
``SCHEMA_VERSION`` and re-curating the training corpus.

Each :class:`LabelSet` records:

* ``interpreter``: the target interpreter (``sql``, ``ldap``,
  ``xpath``, ``shell``, ``html``, ``ssti``).
* ``site``: the ambiguity site within that interpreter (e.g. for SQL,
  ``in_position`` is the only currently-realized site; future sites
  will be added without breaking the schema).
* ``labels``: ordered tuple of labels; index 0 is always the *safest*
  fallback (preserves current parser behavior modulo abstention).
* ``description``: per-label rationale shipped in the training
  prompts and rendered in :class:`~core.disambig.Question.context`.

Stage-D parsers must only call the disambiguator with a label set
declared here; the model is then constrained to return one of these
exact strings (verified by :func:`~core.disambig.Policy.choose`).
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

SCHEMA_VERSION = "1"


@dataclass(frozen=True)
class LabelSet:
    interpreter: str
    site: str
    labels: tuple[str, ...]
    descriptions: tuple[str, ...]  # parallel to ``labels``

    def __post_init__(self) -> None:
        if len(self.labels) != len(self.descriptions):
            raise ValueError(
                f"label/description arity mismatch for {self.interpreter}/{self.site}"
            )
        if len(set(self.labels)) != len(self.labels):
            raise ValueError(
                f"duplicate labels in {self.interpreter}/{self.site}: {self.labels}"
            )
        if not self.labels:
            raise ValueError(
                f"empty label set for {self.interpreter}/{self.site}"
            )

    @property
    def safest_label(self) -> str:
        """Label to return when the policy abstains or is uncertain."""
        return self.labels[0]


# --- SQL ---------------------------------------------------------------------

SQL_IN_POSITION = LabelSet(
    interpreter="sql",
    site="in_position",
    labels=("string_value", "in_list_csv"),
    descriptions=(
        "Single string/numeric value bound by setString/setInt at the IN-slot.",
        "Bag-of-values: emit IN (?, ?, ..., ?) with one placeholder per "
        "element of the host-language collection; bind each by a setX loop.",
    ),
)

SQL_LIKE_PATTERN = LabelSet(
    interpreter="sql",
    site="like_pattern",
    labels=("literal_value", "like_pattern_value"),
    descriptions=(
        "User-supplied value used as a literal string; bind as ?.",
        "User-supplied value is a LIKE-meaningful pattern (contains "
        "%/_); bind as ? without altering metacharacters.",
    ),
)

# --- LDAP --------------------------------------------------------------------

LDAP_VALUE_POSITION = LabelSet(
    interpreter="ldap",
    site="value_position",
    labels=("exact", "substring", "prefix", "suffix", "presence"),
    descriptions=(
        "Exact-match (attr=value).",
        "Substring match (attr=*value*).",
        "Prefix match (attr=value*).",
        "Suffix match (attr=*value).",
        "Presence test (attr=*); value not actually used.",
    ),
)

# --- XPath -------------------------------------------------------------------

XPATH_VALUE_POSITION = LabelSet(
    interpreter="xpath",
    site="value_position",
    labels=("text_value", "numeric_value", "attribute_value", "predicate_position"),
    descriptions=(
        "Hole binds a text node value inside a predicate.",
        "Hole binds a numeric predicate value.",
        "Hole binds an XML attribute value.",
        "Hole stands in the entire predicate; out of MVP scope unless "
        "structurally trivial.",
    ),
)

# --- Shell -------------------------------------------------------------------

SHELL_ARGV_POSITION = LabelSet(
    interpreter="shell",
    site="argv_position",
    labels=("argv_token", "flag_value", "path_token"),
    descriptions=(
        "Hole is one positional argument; bind as-is in argv vector.",
        "Hole is the value of the preceding flag (e.g. '-o ' + path).",
        "Hole is a filesystem path; canonicalize and allow-list against "
        "an inferable base directory if available.",
    ),
)

# --- HTML / DOM --------------------------------------------------------------

HTML_CONTEXT = LabelSet(
    interpreter="html",
    site="context",
    labels=("text_node", "attr_value", "url_attr", "script_block", "style_block"),
    descriptions=(
        "Hole renders as text content; safe via .textContent.",
        "Hole is a non-URL attribute value; safe via setAttribute.",
        "Hole is a URL attribute value (href/src/action); safe via "
        "anchor.href = value (browser does URL parsing).",
        "Hole is inside <script>; abstain unless slice can lift the "
        "hole out of the script tag entirely.",
        "Hole is inside <style>; abstain.",
    ),
)

# --- SSTI --------------------------------------------------------------------

SSTI_SLOT = LabelSet(
    interpreter="ssti",
    site="slot",
    labels=("autoescaped_value", "safe_html", "numeric"),
    descriptions=(
        "Hole goes into a {{ expression }} slot with autoescape on; "
        "rewrite source from string-concat into render_template_string"
        "(FIXED_TPL, var=value).",
        "Hole is HTML that must bypass autoescape (rare); abstain "
        "unless slice proves the source is developer-controlled.",
        "Hole is a numeric coerced via |int filter.",
    ),
)


# --- registry ----------------------------------------------------------------

_REGISTRY: Mapping[tuple[str, str], LabelSet] = MappingProxyType({
    (ls.interpreter, ls.site): ls
    for ls in (
        SQL_IN_POSITION,
        SQL_LIKE_PATTERN,
        LDAP_VALUE_POSITION,
        XPATH_VALUE_POSITION,
        SHELL_ARGV_POSITION,
        HTML_CONTEXT,
        SSTI_SLOT,
    )
})


def get(interpreter: str, site: str) -> LabelSet:
    """Lookup a label set; raises :class:`KeyError` if not registered."""
    try:
        return _REGISTRY[(interpreter, site)]
    except KeyError as e:
        raise KeyError(
            f"no label set for interpreter={interpreter!r} site={site!r}; "
            f"schema v{SCHEMA_VERSION} known sites: "
            f"{sorted(_REGISTRY.keys())}"
        ) from e


def all_label_sets() -> tuple[LabelSet, ...]:
    """All registered label sets in registry order."""
    return tuple(_REGISTRY.values())
