# Stage-D Disambiguation Task (Phase 4)

**Schema version: v1 (frozen)** — adding new labels requires bumping
`core.disambig.labels.SCHEMA_VERSION` and re-curating the corpus.

## Why a learned policy here?

Stage D (the SQL₀ / LDAP / XPath parsers) is **purely symbolic** and
rejects every input whose intent cannot be decided from the template
alone. A small subset of those rejections are *recoverable*: the input
admits exactly one *sound* refinement among a finite, mutually-exclusive
set of options. The Phase-4 disambiguator turns those rejections into
patches by **choosing a label from that finite set**.

The model never produces syntax. It picks a name. Stage E/F then runs
deterministically on the refined SIG. Soundness (Theorem 1 of the
formal model) is preserved because every candidate label corresponds to
a structural refinement that Stage D would have emitted unambiguously
if the input had the corresponding shape.

## Task format

Each example is a 5-tuple `(interpreter, site, sig_text, context, label)`
where:

* `interpreter ∈ {sql, ldap, xpath, shell, html, ssti}`
* `site` is a constant string for the ambiguity point (e.g.
  `sql/in_position`).
* `sig_text` is the marker-augmented template (`<<H0>>`, `<<H1>>`, …).
* `context` is a single line of host-language type info shipped by the
  upstream slicer (e.g. `java; host_type=java.util.List<Integer>`).
* `label` ∈ the registered label set for `(interpreter, site)`.

The prompt template is canonical (kept in sync with
`core.disambig.ModelPolicy._build_prompt`):

```
# IR-SAM SIG disambiguation
# interpreter: {interpreter}
# site: {site}
# context: {context}
# sig: {sig_text}
# choose one of: {label_1}, {label_2}, ...
answer: {label_k}
```

## Constrained decoding

`ModelPolicy` performs *per-label sequence scoring*. For each candidate
label string `ℓᵢ`, it computes the teacher-forced log-probability
`∑ₜ log P(ℓᵢ,t | prompt + ℓᵢ,<t)`, takes the softmax over candidates,
and returns `argmaxᵢ probᵢ` together with `probᵢ` as a calibrated
confidence.

This is mathematically equivalent to constraining the autoregressive
decoder to the union of the labels' token-prefix tries (every
non-candidate continuation has its logit masked to `-inf`) and then
taking the most likely full sequence among the constrained outputs.

A configurable threshold (`IR_SAM_DISAMBIG_THRESHOLD`, default `0.5`)
gates acceptance: below it, the policy delegates to `HeuristicPolicy`
and marks the answer's `source` as `model-low-confidence`.

## Label sets (v1)

| Interpreter | Site                | Labels                                                                  |
| ----------- | ------------------- | ----------------------------------------------------------------------- |
| sql         | `in_position`       | `string_value`, `in_list_csv`                                           |
| sql         | `like_pattern`      | `literal_value`, `like_pattern_value`                                   |
| ldap        | `value_position`    | `exact`, `substring`, `prefix`, `suffix`, `presence`                    |
| xpath       | `value_position`    | `text_value`, `numeric_value`, `attribute_value`, `predicate_position`  |
| shell       | `argv_position`     | `argv_token`, `flag_value`, `path_token`                                |
| html        | `context`           | `text_node`, `attr_value`, `url_attr`, `script_block`, `style_block`    |
| ssti        | `slot`              | `autoescaped_value`, `safe_html`, `numeric`                             |

**Convention**: the first label in each set is the *safest fallback*,
returned by `HeuristicPolicy` when no specific rule fires and used by
`ModelPolicy` when the threshold is not met.

## Currently wired sites

Only `sql/in_position` is wired into the runtime pipeline in this
release (see `core.pipeline._try_disambiguate_sql_in`). The other label
sets are declared, validated, and shipped with the corpus so the
follow-up phases (LDAP value position, XPath value position, etc.) only
need to add a parser hint path.

## Data sources

The training corpus is built by `bench/disambig_corpus.py` from:

1. **Synthetic generation** — templated examples for each
   `(interpreter, site)` pair driven by a small grammar over host
   types and idiomatic shapes.
2. **Real-world mining** — sink slices from the IR-SAM benchmark
   loaders (`bench/load.py`, `bench/multilang.py`) whose ground-truth
   label is inferable from the original concrete value.
3. **Negative anchors** — examples explicitly *outside* the support
   of each label (e.g. SQL `IN` where the value is provably *not* a
   collection); these train the model to assign low confidence so the
   threshold-gated fallback fires.

## Training & evaluation

* `scripts/train_disambig.py` runs supervised fine-tuning on a code-LM
  backbone (default: `Salesforce/codet5p-220m`; configurable via
  `--base-model`). Outputs a checkpoint directory.
* `scripts/eval_disambig.py` runs A/B evaluation against
  `HeuristicPolicy` on a held-out split: accuracy, calibration (ECE),
  confidence-threshold sweeps, fallback rate.
* `scripts/fetch_disambig_model.py` downloads a pre-built checkpoint
  for reviewers without GPU access.

## Acceptance gates (Phase 4)

A model release is accepted iff:

1. **Accuracy** ≥ 92% macro-averaged across label sets.
2. **Calibration**: ECE ≤ 0.05 (15-bin reliability).
3. **Threshold-fallback rate** on a *clean* (in-distribution) eval set
   ≤ 5%.
4. **No regressions** on the existing Phase 1–3 test corpus when the
   disambiguator is enabled (pipeline outcomes must remain unchanged
   on already-unambiguous inputs).

Gates 1–3 are produced by `scripts/eval_disambig.py`; gate 4 is the
existing pytest suite run with `IR_SAM_DISAMBIG_POLICY=model` and a
loaded checkpoint.
