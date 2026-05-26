# Citation Verification Protocol (Phase 0)

## 1. Goal

Every citation in the thesis must be **independently verifiable**
against an authoritative source: DBLP, ACM DL, IEEE Xplore, USENIX,
arXiv (with version pin), or the publisher's official page.
Web-only blog citations are permitted **only** for tool documentation
(e.g., CodeQL docs) and must be archived to the Internet Archive.

## 2. Procedure

For each citation `c` in the thesis bibliography:

1. **Resolve canonical key.** Look up by DOI first; fall back to
   DBLP key; fall back to arXiv id with version (`vN`).
2. **Cross-check** author list, exact title, venue, year, pages /
   article id against the publisher record.
3. **Snapshot.** Save the publisher landing page to
   `docs/refs/snapshots/<bibkey>.html` and the PDF (if open access)
   to `docs/refs/pdfs/<bibkey>.pdf`. For paywalled content, store
   only the metadata snapshot.
4. **Record status** in the table below: `verified`, `pending`,
   `replaced`, or `withdrawn`.

## 3. Verification status of contribution-chapter §5 (SOTA)

| BibKey                  | Topic                              | Source                          | Status   |
|-------------------------|------------------------------------|---------------------------------|----------|
| chen2023neural-apr      | LLM-based program repair survey    | DBLP / arXiv                    | pending  |
| fu2022vulrepair         | VulRepair (T5-based vuln repair)   | ESEC/FSE 2022 (verify pages)    | pending  |
| chi2023seqtrans         | SeqTrans (NMT-based vuln repair)   | TSE (verify volume/issue)       | pending  |
| pearce2023examining     | LLM zero-shot security repair      | IEEE S&P 2023                   | pending  |
| xia2023chatrepair       | ChatRepair (conversational APR)    | ICSE 2024                       | pending  |
| jin2023inferfix         | InferFix (retrieval+LLM)           | FSE 2023                        | pending  |
| ribeiro2025owaspbench   | OWASP Benchmark eval of autofix    | confirm venue                   | pending  |
| anand2025codeqlautofix  | Copilot Autofix (CodeQL+LLM)       | GitHub blog + arXiv companion   | pending  |
| zhao2024neurosymbolic   | Neuro-symbolic program synthesis   | survey, verify venue            | pending  |

Every row marked `pending` will be re-verified during Phase 5 paper
writing; the bibliography file `docs/bibliography.bib` is the single
source of truth.

## 4. Tooling

`docs/refs/verify.py` (planned) — given a `.bib` file, queries DBLP
and crossref APIs, diffs entries, writes a JSON report. Runs in CI
weekly; non-`verified` entries on `main` produce a CI warning,
non-`verified` entries on a release tag produce a CI failure.

## 5. Anti-fabrication policy

Citations may **not** be inserted by language models without a human
verification pass against an authoritative source. Any reviewer of
the thesis can re-run `docs/refs/verify.py` and the result must be
clean.
