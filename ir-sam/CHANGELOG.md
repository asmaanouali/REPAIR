# Changelog

## v2.0 -- Phase 7 (framework-aware bindings + journal extension)

* `binders/spring_jdbctemplate.yaml`, `binders/mybatis.yaml`,
  `binders/hibernate_hql.yaml`, `binders/jpa.yaml`,
  `binders/django_orm.yaml` -- DSL v0 catalogs for the five
  most common Java + Python framework SQL APIs.
* `core/framework/__init__.py` -- Stage A.5 dispatcher.
* `tests/test_framework_bindings.py` -- 16 tests (108 total).
* `paper2/main.tex` + `paper2/refs.bib` -- TSE/TOSEM extension.


## v1.0 -- Phase 6 (paper + artifact)

* `paper/main.tex` -- ICSE/FSE submission (acmart sigconf, anonymous).
* `paper/refs.bib` -- references.
* `artifact/Dockerfile`, `artifact/smoke_test.{sh,ps1}`,
  `artifact/full_run.sh` -- ACM Reusable / USENIX Available bundle.
* `artifact/{README_ARTIFACT,INSTALL,STATUS}.md` -- reviewer guide.
* Phase-5 verdict PASS reconfirmed: M2=?,
  M4=?, M6=?.

# IR-SAM Changelog

All notable changes to the IR-SAM project are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.1.0-mvp] — Phase 3 close-out tag (`ir-sam-mvp/v0.1`)

This is the first publishable artifact of the IR-SAM PhD research
programme. It packages the deliverables of Phases 0–2: foundations,
formalism, and the working MVP pipeline (CWE-089, Java + JDBC) with the
acceptance evaluation reproducibly attached.

### Added — Phase 0 (foundations)

- Repository scaffold, `requirements.txt`, pinned `python==3.10.14`.
- Cross-tool SARIF-unified finding schema (`core.ingest.unified`).
- Binder catalog DSL (`binders/sql_jdbc.yaml`) and a Pydantic-backed
  loader/validator with placeholder-style and parameterizing-API maps.
- Reproducibility harness: `docker-compose.yml`, `Dockerfile`,
  `scripts/build_juliet_mini.py`.

### Added — Phase 1 (formalism)

- Intent-Augmented Model (IAM): syntactic context (VALUE / IDENTIFIER /
  FRAGMENT / STRUCTURAL), semantic types, cardinality, host realizations.
- Semantic-Intent Graph (SIG) with the closed grammar of Lemma 1
  (parameter inertness) and Lemma 2 (allow-list closure).
- φ-binder algebra mapping SIG nodes to setter calls and allow-list
  guards.

### Added — Phase 2 (MVP pipeline)

- Stage A: SARIF-unified detector ingestion.
- Stage B: intra-procedural Java slicer (`core.slicer`) with typed
  abstentions (`no_static_sql_skeleton`, `escapes_method`, …).
- Stage C: symbolic string reconstructor with `<<H{idx}>>` markers
  (`core.recon`).
- Stage D: SQL₀ grammar and SIG lifter (`core.parsers`).
- Stage E: φ-binder application producing a `PatchPlan` (prepared
  template, setter calls, allow-list guards, proof obligations).
- Stage F: Spoon-style Java AST rewriter producing a unified diff.
- Stage G: five validator gates — compile, regression, structural,
  re-SAST, differential — `core.validator.GateReport`.
- Pipeline orchestrator `core.pipeline.run_file`.
- Synthetic Juliet-mini benchmark (`bench/juliet_mini`) covering eq /
  in-list / order-by-ident / like-pattern shapes.
- Acceptance evaluation `scripts/eval_phase2.py`: **87.50 % patch
  gate-pass, 0 residual CWE-089** on 50 cases.

### Reproducibility

- 44 unit + integration tests (`pytest`, all green).
- `build_phase0_phase1_pdf.py` (Phase 0–1 deliverable).
- `build_phase2_pdf.py` (Phase 2 deliverable, embeds live numbers).

### Known limitations (driving Phase 4)

- Single language (Java) and single interpreter (SQL/JDBC).
- Slicer is intra-procedural only.
- Disambiguation is rule-based; no LM-assisted SIG label resolution.
- Differential oracle uses in-process SQLite only.

---

## [v0.2.0-multilang] — Phase 4 close-out (engineering preview)

Multi-language generalization. Not yet a public release; documented for
completeness because it ships in the same workspace as v0.1.

- Python (`core.lang.python`) and JS/TS (`core.lang.jsts`) slicers.
- LDAP RFC 4515 parser (`core.parsers.ldap`) with Lemma 1′ (RFC-4515
  value-escape closure).
- XPath 1.0 predicate-subset parser (`core.parsers.xpath`).
- One-hop inter-procedural slicing (`core.slicer.interproc`).
- Constrained-decoding SIG disambiguator (`core.disambig`,
  `HeuristicPolicy` + `ModelPolicy`); LM is **never** used for patch
  synthesis.
- Grammar-driven attack-payload generator (`bench.attack_gen`).
- Per-interpreter differential oracle (`scripts/oracle_harness.py`)
  with in-process and Dockerized backends.
- Multi-language acceptance: **100.00 % patch pass-rate, 0 residual**
  on the 21-case synthetic benchmark (`scripts/eval_phase4.py`).
