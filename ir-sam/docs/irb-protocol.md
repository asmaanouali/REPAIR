# IRB / Ethics Protocol — IR-SAM Developer Acceptance Study

**Document version:** 1.0 (drafted in Phase 0; submitted to the
institutional ethics board before the study runs in Phase 5).

## 1. Study title
*Developer acceptability of automatically generated security patches
for injection vulnerabilities.*

## 2. Principal investigator
PhD candidate, supervised by [Supervisor]. Contact details on file
with the ethics board.

## 3. Research questions addressed by the study

- **RQ-Dev-1.** Do reviewers prefer IR-SAM patches over baseline-tool
  patches on a blinded review task?
- **RQ-Dev-2.** Does IR-SAM's abstention (`⊥` output with an
  explanation) reduce reviewer cognitive load compared with a wrong
  but confident patch?
- **RQ-Dev-3.** What patch-quality dimensions (security correctness,
  semantic equivalence, code-style, idiomaticity) most affect
  acceptance decisions?

## 4. Population & recruitment

- **Target N:** 20 reviewers (minimum 15, maximum 30).
- **Inclusion:** professional software developer or graduate student
  with ≥ 2 years of experience in Java/Python/JS and prior exposure
  to security code review.
- **Exclusion:** authors or close collaborators of any baseline tool;
  reviewers who have seen IR-SAM internals.
- **Recruitment:** university mailing lists, professional Slack/Discord
  groups (security-engineering-focused), and a public call from the
  research group account. **No coercion** — students are not recruited
  from the candidate's own teaching cohort.

## 5. Study design

- **Within-subjects, blinded, randomized order.** Each reviewer sees
  the same set of N patches (10 ≤ N ≤ 15) drawn from CVEfixes
  pre-fix code, where each sample includes one patch per tool
  (IR-SAM + 4 baselines) presented in a random order.
- **Per patch, the reviewer rates** on 5-point Likert scales:
  security correctness, semantic equivalence, idiomaticity, and
  whether they would merge it. A free-text comment box is provided.
- **Duration:** ≤ 60 minutes per session, single sitting, asynchronous.
- **Compensation:** time-equivalent gift voucher (per local ethics
  norms).

## 6. Data handling

- **Identifiers collected:** name and email at consent only;
  stripped on import. Reviewers are referred to by `R01…R30`.
- **Storage:** encrypted at rest (LUKS / BitLocker), university-managed
  storage, 5-year retention then secure deletion.
- **Access:** PhD candidate and supervisor only. Anonymized aggregates
  may be shared with paper reviewers.
- **No code review of proprietary projects** — all samples come from
  open-source CVEfixes / BigVul / Vul4J corpora.

## 7. Risks & mitigations

- **R-IRB-1: psychological burden** (boredom, decision fatigue) —
  short sessions, breaks allowed, withdrawal at any time without
  penalty.
- **R-IRB-2: exposure to malicious code** — pre-fix samples may
  contain exploitable code. Mitigation: samples are presented as
  static text in a sandboxed web form; no execution is required of
  the reviewer.
- **R-IRB-3: re-identification of patch authors** — patch metadata is
  stripped (author, commit hash, repo). Only the code diff and minimal
  context are shown.

## 8. Consent

A written informed-consent form (English + French) is presented
before any data is collected; reviewers confirm understanding that
participation is voluntary and they may withdraw without giving a
reason. Consent forms are stored separately from response data.

## 9. Disclosure & publication

Aggregate results published in the thesis and conference paper.
Raw anonymized response files released alongside the artifact
under a CC-BY-4.0 license, conditional on consent. Reviewers may
opt out of public release of their (anonymized) free-text comments.

## 10. Responsible-disclosure SOP for live CVEs

If during data scraping the candidate discovers a vulnerability in a
project that has **not** yet been publicly disclosed:

1. Halt automated processing of that project.
2. Contact the project maintainers via their security contact
   (security.txt, SECURITY.md, or email).
3. Wait for the disclosure window agreed with maintainers (default 90
   days) before including the finding in any artifact.
4. Document the case in `docs/disclosures/<cve-or-internal-id>.md`.
