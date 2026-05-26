# IR-SAM Phase 5 -- Pre-Registered Study Protocol

**Status.** Pre-registered prior to data collection.
**Registration channel.** Open Science Framework (OSF), private until
acceptance; reviewers receive a read-only view link.
**Authors.** Anonymized for double-blind submission.
**Date.** mo 20 of the project schedule.
**Revision.** v1.0.

---

## 1. Background and motivation

IR-SAM produces interpreter-aware vulnerability patches and proves their
soundness with a 5-gate validator. Existing benchmarks (CVEfixes,
Vul4J, BigVul) score automatic program repair tools on **token-level
exact match** to the maintainer fix, which is known to under-estimate
semantically equivalent rewrites and over-estimate token-imitating
hallucinations. We therefore complement the automated six-metric
evaluation (M1-M6, §6.2 of the IR-SAM submission) with a **blinded
developer study** that captures expert perception of:

  - patch *correctness* (does this stop the bug?),
  - patch *semantic preservation* (does this change observable behavior?),
  - patch *clarity / merge-ability* (would you accept this in review?),
  - patch *security confidence* (would you ship this on Monday?).

## 2. Hypotheses

We pre-register four hypotheses, each at \u03b1 = 0.05 with Holm-Bonferroni
correction across the family of four:

  - **H1 (Correctness).** Reviewers rate IR-SAM patches higher on
    perceived correctness than the strongest LLM-based baseline
    (CodeQL+GPT-4 *or* ChatRepair, whichever wins in M2).
  - **H2 (Semantic preservation).** Reviewers report fewer
    behavior-altering rewrites in IR-SAM patches than in VulRepair.
  - **H3 (Security confidence).** Reviewers express higher
    "would-ship-it" confidence in IR-SAM patches than in the pure-LLM
    zero-shot baseline.
  - **H4 (Abstention legitimacy).** When IR-SAM abstains, reviewers
    agree (\u2265 70%) that the case is genuinely irreparable by a
    single-file rewrite.

## 3. Evaluable-subset selection criteria

A CVE fix is admissible iff **all** of:

  1. CWE \u2208 {CWE-89, CWE-90, CWE-91, CWE-643, CWE-78, CWE-94}.
  2. Pre-patch source compiles / parses with the language adapter.
  3. The vulnerable sink site is reachable by the Phase-4 sink-scanner.
  4. The maintainer fix is **single-file** (multi-file fixes are
     reported separately and excluded from M2/M3).
  5. The post-patch source is licensed under a permissive licence
     compatible with re-distribution to study participants.

Inadmissible cases are tagged ``out_of_scope`` and used only for the
top-10 failure-mode catalog (§6.4).

## 4. Conditions and blinding

Each reviewer sees a randomized sequence of *patch triplets*: the
original vulnerable function plus three candidate patches labelled
``A``, ``B``, ``C`` with no tool identity. The mapping
(condition \u2194 tool) is randomized per reviewer via a deterministic
Latin-square (``study/randomization.py``, seeded with the reviewer's
hashed ID). Possible tool sets per triplet are drawn from:

  - **T1** = IR-SAM
  - **T2** = CodeQL+GPT-4 (Copilot-Autofix analogue)
  - **T3** = VulRepair
  - **T4** = ChatRepair
  - **T5** = LLM zero-shot

Each reviewer sees **all** of T1 plus two baselines drawn without
replacement; the assignment is balanced so that every (tool, position)
pair is shown an equal number of times.

## 5. Sample size and power

Target *n* = 20 reviewers (acceptable range 15-25). Power analysis for
the primary endpoint (H1) using a Friedman test over three conditions
with effect size *w* = 0.40 and \u03b1 = 0.05 gives power \u2265 0.80 at
*n* = 18. We therefore pre-register **n_min = 18** and **n_max = 25**;
data collection stops at the first of (a) n_max reached, (b) 8 weeks of
recruiting, or (c) n_min reached and budget exhausted.

## 6. Inclusion criteria for reviewers

  - \u2265 3 years professional software engineering experience, OR
  - \u2265 2 years experience in application security / appsec review.
  - Reads Java + (Python or JavaScript) at a working level.
  - Not affiliated with the authors' lab in the prior 24 months.

Recruitment: a stratified sample drawn from (i) OSS maintainer
mailing-lists for known Java/Python projects, (ii) Mastodon / Reddit
``r/AskNetsec`` invitations, (iii) the authors' anonymized institutional
mailing list. The recruitment text is reproduced in
``study/irb_application.md``.

## 7. Primary outcome and analysis plan

Per (reviewer, case, condition) the reviewer answers a 5-point Likert
on each of four items (correctness, preservation, clarity, security
confidence). The primary analysis is a **Friedman** test across the
three conditions for **correctness**, followed by **Nemenyi** post-hoc
if significant. Krippendorff's \u03b1 is reported for inter-rater
reliability with a pre-registered acceptability floor of \u03b1 \u2265 0.55.
Secondary endpoints (preservation, clarity, confidence) are analyzed
with the same procedure and the family is corrected via
Holm-Bonferroni. McNemar's paired \u03c7\u00b2 is reported for the binary
"would you accept this patch in code-review" item.

All analysis code lives in ``study/analysis.py`` and is run via
``python -m study.analysis``; the script is part of the
pre-registration and is *not* modified after data collection begins.

## 8. Data management

  - Responses are collected via a self-hosted LimeSurvey instance
    (Qualtrics-importable JSON schema is shipped at
    ``study/survey.json``); raw exports are stored encrypted at rest
    on the institution's GDPR-compliant storage.
  - PII is limited to (i) reviewer self-reported experience tier and
    (ii) acknowledged time-zone for scheduling. Both are stored in a
    separate, access-controlled table with no link to response IDs
    other than a one-way HMAC under a per-study secret destroyed at
    publication.
  - Retention: raw responses retained for 5 years per institutional
    policy; aggregate, de-identified data deposited with the
    publication on Zenodo under CC-BY-4.0.

## 9. Stopping rules

  - **Safety.** If two consecutive reviewers report distress (free-text
    or check-box) at viewing real CVE source, recruitment pauses and
    the IRB is notified.
  - **Quality.** If Krippendorff's \u03b1 < 0.30 at *n* = 12, we audit
    instructions and may restart with an updated rubric (a single
    restart is permitted and pre-registered here).

## 10. Deviations

Any deviation from this protocol will be reported in §7 of the final
paper with a clear "**deviation from pre-registration**" header.
