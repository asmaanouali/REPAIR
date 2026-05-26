# IR-SAM Testing Corpus

This folder is a reproducible evaluation corpus for the IR-SAM remediation work. It is designed for an IEEE-style empirical software-engineering/security paper: every repository is listed in a manifest, cloned by script, checked locally, and locked to the exact commit used in experiments.

The corpus focuses on vulnerability classes that are in scope for IR-SAM's interpreter-bounded remediation model:

- CWE-89: SQL Injection
- CWE-78: OS Command Injection
- CWE-79: Cross-site Scripting
- CWE-90: LDAP Injection
- CWE-643: XPath Injection
- CWE-1336: Server-Side Template Injection
- CWE-22: Path Traversal

Some repositories are broad vulnerable applications that include multiple OWASP Top 10 classes. The manifest records the expected target classes and the selection basis. The verification report should be cited together with the manifest so that every inclusion is auditable.

## Layout

| Path | Purpose |
| --- | --- |
| `manifest.csv` | Curated list of 42 public repositories (Java / Python / JavaScript / TypeScript only, restricted to the IR-SAM CWE scope) with target CWE labels and selection rationale. |
| `repos/` | Local shallow clones. This directory is ignored by Git to avoid redistributing third-party source. |
| `metadata/clone-lock.json` | Generated lockfile with exact commit SHA, branch, clone status, and timestamp. |
| `metadata/clone-report.csv` | Generated per-repository clone status. |
| `metadata/verification-report.csv` | Generated local structural verification summary. |
| `protocol/ieee-style-testing-protocol.md` | Testing protocol, validity controls, and reporting checklist. |
| `scripts/clone-corpus.ps1` | Clones the repositories from the manifest and records commit SHAs. |
| `scripts/verify-corpus.ps1` | Verifies local clones and summarizes source files and target-pattern evidence. |
| `scripts/run-irsam-scan.ps1` | Optional helper to run IR-SAM project scans over cloned repositories. |

## Quick Start

From the repository root on Windows PowerShell:

```powershell
Set-Location testing-code
.\scripts\clone-corpus.ps1
.\scripts\verify-corpus.ps1
```

The clone script does not run the vulnerable applications, install their dependencies, or execute exploit payloads. It only retrieves source code and records provenance.

On Windows, the clone script invokes Git with `core.longpaths=true` because several scanner benchmark repositories contain generated test files with long paths.

## IEEE-Style Controls

This folder does not claim an official IEEE certification. Instead, it implements the testing controls commonly expected for IEEE empirical studies:

- traceable corpus selection through `manifest.csv`;
- reproducible retrieval through `metadata/clone-lock.json` commit pins;
- explicit inclusion and exclusion criteria;
- safe handling of intentionally vulnerable software;
- separation of corpus preparation, verification, and tool execution;
- reporting of all failures, abstentions, and excluded repositories;
- metrics grouped by repository, language, and CWE family.

For the paper, cite both the manifest and the generated lockfile date. Do not report results from moving default branches without the lockfile.

## Safety Boundary

These repositories are intentionally vulnerable. Use them only in isolated local containers or offline test environments. Do not expose cloned applications to public networks, do not add real credentials, and do not run third-party setup scripts unless the experiment protocol explicitly requires it.
