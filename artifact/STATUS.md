# Artifact badge request and justification

## Badges requested

  - **ACM Artifacts Evaluated -- Functional** (V1.1)
  - **ACM Artifacts Evaluated -- Reusable** (V1.1)
  - **ACM Artifacts Available** (V1.1)
  - **USENIX Available**

## Functional -- justification

The artifact:

  - **executes** end-to-end via a single command
    (`bash artifact/smoke_test.sh`),
  - is **consistent** with the paper: the headline six-metric table
    (paper Table 1) is regenerated bit-identically by the smoke run,
  - is **complete**: every empirical claim in the paper has a
    corresponding artifact entry point (see "What is reproduced"
    table in `README_ARTIFACT.md`),
  - is **exercisable**: the 92 unit tests serve as a fine-grained
    sanity check independent of the eval scripts.

## Reusable -- justification

Beyond Functional, the artifact is reusable because:

  - the **pipeline is modular**: each stage A-G has a clear typed
    interface; new binders and new languages are added by writing a
    YAML file (`ir-sam/binders/`) and a thin adapter
    (`ir-sam/core/lang/`),
  - the **baselines protocol is documented and pluggable**: a new
    baseline subclass implementing `Baseline.run(EvalCase) ->
    BaselineResult` is auto-picked up by the evaluator,
  - the **two-tier policy** is explicit: real-tier hooks exist for
    every external dependency and are activated by single env vars,
  - the **license is permissive** (MIT) and there are no third-party
    redistribution restrictions in the bundled code.

## Available -- justification

  - Source is provided as a self-contained zip (or git tag `v1.0`)
    on a publicly accessible archival service. On acceptance the
    artifact will be deposited on **Zenodo** with a stable DOI; the
    blinded review URL is `[withheld for double-blind review]`.
  - The pre-registered study materials live in `ir-sam/study/` and
    will receive a separate OSF DOI on acceptance.

## Reviewer effort estimate

  - **Kick-the-tires**: 5 minutes (Docker pull + 25-second smoke).
  - **Functional check**: 30 minutes (smoke + spot-check three
    metric numbers against Table 1).
  - **Reusability check**: 2-3 hours (write a new binder, e.g., for
    PostgreSQL-style `$n` placeholders, run the smoke test, observe
    that the new binder is picked up automatically).
