# IEEE-Style Testing Protocol

This protocol is written for reporting IR-SAM experiments in an IEEE-style paper. It is not an official IEEE standard; it is a reproducibility and validity checklist aligned with common IEEE empirical-study expectations.

## 1. Research Objective

Evaluate whether IR-SAM can detect and remediate interpreter-bounded injection vulnerabilities with traceable, reviewable, and validator-gated patches.

Primary target families:

- CWE-89 SQL Injection
- CWE-90 LDAP Injection
- CWE-643 XPath Injection

Secondary target families from the thesis scope:

- CWE-78 OS Command Injection
- CWE-79 Cross-site Scripting
- CWE-1336 Server-Side Template Injection
- CWE-22 Path Traversal

## 2. Corpus Inclusion Criteria

A repository is included when it satisfies at least one of these criteria:

1. It is an official or widely used vulnerable-application benchmark.
2. It appears in OWASP VWAD or another public vulnerable-application directory.
3. Its public description explicitly mentions one or more target CWE families.
4. It is useful as an external-validity comparator for scanner or project-level workflow tests.

For scoring IR-SAM patch quality, count only findings whose file, language, and CWE are in scope for the evaluated phase. Broad vulnerable applications must be filtered down to concrete in-scope findings before computing success rates.

## 3. Exclusion Criteria

Exclude a repository, file, or finding from scored remediation metrics when:

- the repository cannot be cloned at the lockfile revision;
- the relevant vulnerable file is generated, minified, vendored, or a dependency copy;
- the vulnerability is outside the declared CWE scope;
- the host language is outside the evaluated phase;
- the project requires network services or credentials that cannot be reproduced locally;
- the vulnerability is only described in documentation and not present in source code;
- a license or terms-of-use issue prevents research reuse.

All exclusions must be reported in the experiment appendix.

## 4. Reproducibility Controls

1. Clone using `scripts/clone-corpus.ps1`.
2. Preserve `metadata/clone-lock.json` with exact commit SHAs.
3. Run `scripts/verify-corpus.ps1` and preserve `metadata/verification-report.csv`.
4. Record the IR-SAM commit, OS, Python version, Node version, Java version, Docker version, and detector versions.
5. Do not update cloned repositories during an experiment batch.
6. Report all failed clones and missing repositories.

## 5. Evaluation Units

Use three levels and keep them separate in reporting:

- Repository-level: project scan completed, files examined, findings discovered.
- Finding-level: vulnerable sink identified and classified.
- Patch-level: remediation generated, applied, compiled/parsed, and passed validator gates.

Do not claim project-level semantic repair unless multiple coordinated files are rewritten and validated as a unit. Current IR-SAM remediation should be described as project-scoped scanning with per-finding or per-file patch generation.

## 6. Metrics

Recommended primary metrics:

- patch applicability: patched findings divided by in-scope findings;
- validator pass rate: patches passing all gates divided by generated patches;
- abstention rate and abstention reason distribution;
- residual target-sink rate after patching;
- parse/build preservation rate;
- median and p95 time per finding and per repository.

Recommended stratifications:

- CWE family;
- host language;
- framework/API family;
- repository source type: official benchmark, OWASP VWAD, external comparator;
- snippet/file/project workflow.

## 7. Safety Controls

The corpus contains intentionally vulnerable code. The default protocol is source-only analysis. If runtime validation is needed:

- run inside isolated containers or VMs;
- bind services only to localhost;
- use synthetic credentials and seeded test data;
- disable outbound network access unless required by the protocol;
- never deploy vulnerable apps to public infrastructure.

## 8. Reporting Checklist

The paper appendix should include:

- `manifest.csv` version;
- `clone-lock.json` hash or full file;
- clone date/time;
- number of repositories successfully cloned;
- number of repositories excluded and reasons;
- per-CWE and per-language sample counts;
- exact commands used to run IR-SAM;
- raw output tables or a link to the artifact archive.
