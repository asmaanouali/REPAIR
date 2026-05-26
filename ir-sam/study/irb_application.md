# IRB Application -- IR-SAM Blinded Developer Study

> **Template.** This file is the institutional-IRB application skeleton
> the authors submit verbatim with institution-specific blanks (marked
> ``<<...>>``) filled at submission time. It is reproduced in the
> repository so reviewers can audit ethics provisions.

## 1. Study title

*Expert perception of automatically generated security patches: a
within-subjects comparison of static, neural, and hybrid program-repair
tools.*

## 2. Investigators

  - PI: ``<<author_1>>``, ``<<institution>>``
  - Co-I: ``<<author_2>>``, ``<<institution>>``
  - Contact for participants: ``<<irb_contact_email>>``
  - Institutional IRB: ``<<irb_office_email>>``, protocol number
    ``<<IRB-NNNN>>``.

## 3. Purpose

To compare expert reviewers' perception of automatically generated
security patches produced by IR-SAM, two production-grade neural
program-repair tools, and a large-language-model baseline. The study
informs the design of automated triage tools for OSS maintainers and
appsec teams.

## 4. Procedures

  - Eligible participants complete a 35-45 minute web-based session
    on a self-hosted survey instance.
  - Each session shows 6 *patch triplets*: a vulnerable function and
    three blinded candidate patches (``A``, ``B``, ``C``). For each
    triplet the participant answers four 5-point Likert items plus an
    optional free-text comment.
  - Participants may pause and resume; partial responses are retained
    only with explicit consent.

## 5. Risks

  - **Minimal risk.** The source-code excerpts are public OSS files
    already disclosed on the project's bug tracker. No personally
    identifiable information about third parties is shown.
  - **Cognitive fatigue.** A break is enforced after triplet 3; the
    session auto-saves after each triplet.
  - **Discomfort.** Some CVE excerpts describe real-world attacks
    (e.g., SQL exfiltration). A content notice is shown before the
    first triplet, and participants may skip any triplet with no
    penalty.

## 6. Benefits

  - Direct: participants receive a USD <<25-50>> e-gift-card (optional;
    declinable for tax-exempt collaborators) and an early-access copy of
    the published paper.
  - Indirect: the study contributes to safer automated patch tooling
    for OSS maintainers.

## 7. Compensation, withdrawal, and right-to-withdraw

  - Participants are paid pro-rated for partial sessions (>= 50%).
  - Participants may withdraw at any time and have their data deleted
    upon request to ``<<irb_contact_email>>`` within 30 days of session
    completion (after that point only the de-identified aggregate
    survives, which cannot be linked back to a participant).

## 8. Informed consent

The consent form is shown on the first screen of the survey and is
reproduced verbatim below. Participants must check both boxes
(*"I am at least 18 years old"* and *"I consent to participation"*)
before any data is recorded.

> **Consent form.**
> You are invited to participate in a research study about how software
> engineers perceive automatically generated security patches. The
> study takes 35-45 minutes and consists of reading short code
> excerpts and answering Likert-scale questions. Participation is
> voluntary; you may withdraw at any time without consequence. You
> may decline to answer any question. The study collects: your
> self-reported years of experience, your time-zone, and your
> responses; it does **not** collect your name or any other identifier.
> Risks are minimal (cognitive fatigue, viewing public OSS code).
> Compensation is a USD <<25-50>> e-gift-card.
> All responses are stored encrypted on
> ``<<institution>>``-controlled storage and reported only in
> aggregate. Contact ``<<irb_contact_email>>`` for questions or
> withdrawal requests.

## 9. Data management

  - Raw responses are encrypted at rest with AES-256 on
    ``<<institutional_storage>>``.
  - The mapping (reviewer-id \u2194 demographic tier) is stored
    separately, behind two-factor access, and destroyed at publication.
  - Aggregate de-identified data is deposited on Zenodo (CC-BY-4.0)
    alongside the published paper.
  - Retention: 5 years per ``<<institution>>`` records-management
    policy.

## 10. Conflict of interest

None of the investigators have a financial interest in any of the
baseline tools evaluated (Semgrep Inc., GitHub Inc./Microsoft Corp.,
or the academic VulRepair / SeqTrans / ChatRepair groups).

## 11. Appendices

  - Appendix A: full survey JSON (``study/survey.json``).
  - Appendix B: pre-registered protocol (``study/protocol.md``).
  - Appendix C: randomization scheme (``study/randomization.py``).
  - Appendix D: analysis plan + code (``study/analysis.py``).
