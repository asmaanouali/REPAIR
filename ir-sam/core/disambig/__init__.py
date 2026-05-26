"""SIG disambiguator (Phase 4, neuro-symbolic tie-break).

When stage D's symbolic parser flags an :class:`ambiguous intent` on a
shape that *could* have a sound interpretation but cannot pick one
deterministically (e.g. an IN-list with a single attacker-controlled
hole that may be a CSV bag-of-values or a single string), the
pipeline calls a *constrained* code-LM as a tie-breaker.

The model is **never** asked to generate the patch --- it is only
asked to choose a label from a finite, frozen set declared in
:mod:`core.disambig.labels`. Every label is a strictly syntactic
refinement that stage D would have produced if the input were
unambiguous. The patch itself is still produced by the deterministic
stages E/F. This preserves the soundness contract by construction:
the LM cannot inject syntax.

Constrained decoding
--------------------

:class:`ModelPolicy` uses **per-label sequence scoring with logit
masking**: for each candidate label string, we tokenize the
``prompt + label`` continuation and compute the *teacher-forced* log
probability of the label tokens given the prompt. We then take the
argmax over candidates and return its softmax probability as the
calibrated confidence.

This is mathematically equivalent to constraining the autoregressive
decoder to the union of the labels' token-prefix tries (every
non-candidate continuation has its logit masked to ``-inf``) and then
taking the most likely full sequence among the constrained outputs.

Fallback semantics
------------------

``IR_SAM_DISAMBIG_POLICY`` controls policy selection:

* ``auto`` (default): use :class:`ModelPolicy` when
  ``IR_SAM_DISAMBIG_MODEL`` is set *and* the checkpoint loads; else
  :class:`HeuristicPolicy`.
* ``model``: force :class:`ModelPolicy`. If the checkpoint env var is
  unset or load fails, the policy itself delegates to
  :class:`HeuristicPolicy` at call time, with :attr:`Answer.source`
  annotated as ``model-fallback``.
* ``heuristic``: force :class:`HeuristicPolicy`.

``IR_SAM_DISAMBIG_THRESHOLD`` (default ``0.5``) is the minimum softmax
confidence required to accept a model choice; below that the policy
delegates to :class:`HeuristicPolicy` and records
:attr:`Answer.source` as ``model-low-confidence``.

See :doc:`../../docs/disambig-task.md` for the task spec.
"""

from __future__ import annotations

import os
import logging
import warnings
from dataclasses import dataclass
from typing import Protocol

from core.disambig import labels as _labels

_LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class Question:
    """A constrained multiple-choice question for the disambiguator."""

    sig_text: str                       # marker-augmented template (with <<H{n}>>)
    context: str                        # 1-2 line description (host lang, sink api, host types)
    labels: tuple[str, ...]             # finite, mutually-exclusive label set
    rationale_required: bool = False
    interpreter: str = ""               # optional; used for label-set validation
    site: str = ""                      # optional; used for label-set validation


@dataclass(frozen=True)
class Answer:
    label: str
    confidence: float                   # 0..1 (softmax over candidates for model; rule-confidence for heuristic)
    rationale: str = ""
    source: str = "heuristic"           # "heuristic" | "model" | "model-fallback" | "model-low-confidence"


class Policy(Protocol):
    name: str

    def choose(self, q: Question) -> Answer: ...


# --- heuristic policy -------------------------------------------------------


class HeuristicPolicy:
    """Deterministic, training-free disambiguator.

    Encodes a small set of rules covering the cases the Phase-4
    benchmark exercises:

    * SQL ``IN`` with one hole and surrounding parentheses ->
      ``in_list_csv`` when the hole's host type is a Java
      ``List``/array or Python ``list``/``tuple``; otherwise
      ``string_value``.
    * LDAP substring with one hole between two ``*`` -> ``substring``.
    * Anything else -> the safest label (label-set index 0).
    """

    name = "heuristic"

    def choose(self, q: Question) -> Answer:
        if not q.labels:
            raise ValueError("empty label set in Question")
        s = q.sig_text.lower()
        ctx = q.context.lower()

        # SQL IN-list disambiguation
        if "in_list_csv" in q.labels and "in" in s and "<<h" in s:
            if any(tag in ctx for tag in ("list<", "[]", "tuple", "list[", "iterable")):
                return Answer(
                    "in_list_csv", 0.9, "list/array host type",
                    source=self.name,
                )
            if "string_value" in q.labels:
                return Answer(
                    "string_value", 0.7, "scalar host type",
                    source=self.name,
                )

        # LDAP substring
        if "substring" in q.labels and "*<<h" in s and ">>*" in s:
            return Answer(
                "substring", 0.85, "hole between two wildcards",
                source=self.name,
            )

        # Default: safest label
        return Answer(
            q.labels[0], 0.5, "default to safest label", source=self.name,
        )


# --- model-backed policy ----------------------------------------------------


_DEFAULT_THRESHOLD = 0.5


def _get_threshold() -> float:
    raw = os.environ.get("IR_SAM_DISAMBIG_THRESHOLD")
    if not raw:
        return _DEFAULT_THRESHOLD
    try:
        v = float(raw)
    except ValueError:
        warnings.warn(
            f"IR_SAM_DISAMBIG_THRESHOLD={raw!r} not parseable; "
            f"using default {_DEFAULT_THRESHOLD}"
        )
        return _DEFAULT_THRESHOLD
    if not (0.0 <= v <= 1.0):
        warnings.warn(
            f"IR_SAM_DISAMBIG_THRESHOLD={v} out of [0,1]; using default"
        )
        return _DEFAULT_THRESHOLD
    return v


class ModelPolicy:
    """Constrained-decoding wrapper around a causal-LM checkpoint.

    The checkpoint is loaded lazily on first :meth:`choose` call (or
    immediately when ``eager=True``). On any failure (transformers not
    installed, checkpoint missing, OOM, etc.) the policy logs the
    fallback **once** and silently delegates to :class:`HeuristicPolicy`
    with :attr:`Answer.source` annotated as ``model-fallback``.

    The decoding strategy is *per-label sequence scoring*:

    1. Build the prompt via :meth:`_build_prompt`.
    2. For each candidate label, compute the sequence log-probability
       ``sum_t log P(label_token_t | prompt + label_tokens[:t])``.
    3. Compute ``softmax`` over those log-probabilities.
    4. Return argmax with its softmax probability as confidence.
    """

    name = "model"

    def __init__(self, checkpoint: str, eager: bool = False):
        self.checkpoint = checkpoint
        self.fallback = HeuristicPolicy()
        self.threshold = _get_threshold()
        self._impl: tuple[object, object] | None = None
        self._tried_load = False
        self._warned = False
        self._last_warning: str | None = None
        if eager:
            self._ensure_loaded()

    # ---- loading ----------------------------------------------------------

    def _ensure_loaded(self) -> tuple[object, object] | None:
        if self._tried_load:
            return self._impl
        self._tried_load = True
        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer  # type: ignore
        except Exception as e:                                  # pragma: no cover
            self._warn_once(
                f"transformers unavailable ({e}); ModelPolicy -> heuristic"
            )
            return None
        try:                                                    # pragma: no cover
            tok = AutoTokenizer.from_pretrained(self.checkpoint)
            mdl = AutoModelForCausalLM.from_pretrained(self.checkpoint)
            mdl.eval()
            self._impl = (tok, mdl)
            return self._impl
        except Exception as e:                                  # pragma: no cover
            self._warn_once(
                f"failed to load {self.checkpoint!r}: {e}; ModelPolicy -> heuristic"
            )
            return None

    def _warn_once(self, msg: str) -> None:
        if not self._warned:
            self._last_warning = msg
            _LOG.warning(msg)
            self._warned = True

    # ---- inference --------------------------------------------------------

    def choose(self, q: Question) -> Answer:
        if not q.labels:
            raise ValueError("empty label set in Question")
        loaded = self._ensure_loaded()
        if loaded is None:
            ans = self.fallback.choose(q)
            return Answer(
                ans.label, ans.confidence, ans.rationale,
                source="model-fallback",
            )
        scores = self._score_labels(q, loaded)                  # pragma: no cover
        return self._finalize(q, scores)                        # pragma: no cover

    def _score_labels(self, q: Question, impl) -> list[float]:  # pragma: no cover
        """Compute per-label *sequence* log-probability under teacher forcing."""
        import torch  # type: ignore

        tok, mdl = impl
        prompt = self._build_prompt(q)
        prompt_ids = tok(prompt, return_tensors="pt").input_ids
        prompt_len = int(prompt_ids.shape[1])

        log_probs: list[float] = []
        with torch.no_grad():
            for label in q.labels:
                full = tok(prompt + label, return_tensors="pt").input_ids
                if full.shape[1] <= prompt_len:
                    # Degenerate tokenization (label tokenized away).
                    log_probs.append(float("-inf"))
                    continue
                target_ids = full[0, prompt_len:]
                logits = mdl(input_ids=full).logits
                # logits[t] predicts token at t+1; score positions
                # [prompt_len-1 .. full_len-2] against targets
                # [prompt_len .. full_len-1].
                scoring_logits = logits[0, prompt_len - 1 : full.shape[1] - 1, :]
                lse = torch.log_softmax(scoring_logits, dim=-1)
                token_lp = lse.gather(-1, target_ids.unsqueeze(-1)).squeeze(-1)
                log_probs.append(float(token_lp.sum().item()))
        return log_probs

    def _finalize(self, q: Question, log_probs: list[float]) -> Answer:  # pragma: no cover
        """Pick argmax; softmax-confidence; threshold-gated fallback."""
        import math

        finite = [lp for lp in log_probs if lp != float("-inf")]
        if not finite:
            ans = self.fallback.choose(q)
            return Answer(
                ans.label, ans.confidence, ans.rationale,
                source="model-fallback",
            )
        m = max(finite)
        exps = [math.exp(lp - m) if lp != float("-inf") else 0.0
                for lp in log_probs]
        z = sum(exps) or 1.0
        probs = [e / z for e in exps]
        best = max(range(len(probs)), key=lambda i: probs[i])
        confidence = float(probs[best])
        if confidence < self.threshold:
            ans = self.fallback.choose(q)
            return Answer(
                ans.label, ans.confidence,
                f"model confidence {confidence:.3f} < {self.threshold:.2f}; "
                "fell back to heuristic",
                source="model-low-confidence",
            )
        return Answer(
            q.labels[best], confidence,
            f"constrained argmax over {len(q.labels)} labels",
            source=self.name,
        )

    @staticmethod
    def _build_prompt(q: Question) -> str:
        # Exact prompt template the corpus is generated against;
        # keep in sync with bench/disambig_corpus.py.
        return (
            "# IR-SAM SIG disambiguation\n"
            f"# interpreter: {q.interpreter or 'unknown'}\n"
            f"# site: {q.site or 'unknown'}\n"
            f"# context: {q.context}\n"
            f"# sig: {q.sig_text}\n"
            f"# choose one of: {', '.join(q.labels)}\n"
            "answer: "
        )


# --- factory ---------------------------------------------------------------


def load_default_policy() -> Policy:
    """Build the policy selected by ``IR_SAM_DISAMBIG_POLICY``.

    Selection matrix (``M`` = ``IR_SAM_DISAMBIG_MODEL`` set):

    ============== ===== ============================
    env value      M?    result
    ============== ===== ============================
    ``auto``/``""`` yes  :class:`ModelPolicy`
    ``auto``/``""`` no   :class:`HeuristicPolicy`
    ``model``       yes  :class:`ModelPolicy`
    ``model``       no   :class:`HeuristicPolicy` (warning)
    ``heuristic``   any  :class:`HeuristicPolicy`
    ============== ===== ============================
    """
    selector = (os.environ.get("IR_SAM_DISAMBIG_POLICY") or "auto").lower().strip()
    ckpt = os.environ.get("IR_SAM_DISAMBIG_MODEL")

    if selector == "heuristic":
        return HeuristicPolicy()
    if selector == "model":
        if not ckpt:
            warnings.warn(
                "IR_SAM_DISAMBIG_POLICY=model but IR_SAM_DISAMBIG_MODEL is "
                "unset; falling back to HeuristicPolicy"
            )
            return HeuristicPolicy()
        return ModelPolicy(ckpt)
    # default: auto
    if ckpt:
        return ModelPolicy(ckpt)
    return HeuristicPolicy()


__all__ = [
    "Answer",
    "HeuristicPolicy",
    "ModelPolicy",
    "Policy",
    "Question",
    "load_default_policy",
    "labels",
]

# Convenience alias so external code can write ``from core.disambig import labels``.
labels = _labels
