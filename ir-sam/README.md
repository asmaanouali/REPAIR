# IR-SAM — Intent-Reconstructive Secure API Migration

Reference implementation, evaluation harness, and formal-model artifacts
for the PhD thesis *"Intent-Reconstructive Secure API Migration:
A Soundness-Oriented Approach to the Remediation of Injection
Vulnerabilities."*

This repository contains the **Phase 0 (Foundations)** and **Phase 1
(Formal Model & MVP Spec)** deliverables described in
[plan.md](../IR-SAM_Phase0_Phase1.pdf). Implementation of stages A–G
(Phase 2) lives on a feature branch and is intentionally not merged
to `main` yet.

## Repository layout

```
ir-sam/
├── core/
│   ├── iam/          # IAM, SIG, soundness predicates (Phase 1)
│   ├── ingest/       # CodeQL / Semgrep / SonarQube → unified schema
│   └── binder/       # Binding-catalog DSL v0 (Phase 1)
├── binders/          # Declarative binder rules (YAML)
├── schemas/          # JSON Schema for the unified finding format
├── bench/            # Dataset loaders (Phase 0)
├── docs/             # Formal model, soundness proof, MVP spec, IRB...
├── tests/            # Pytest suite
├── .github/workflows # CI
├── Dockerfile        # Reproducible build environment
├── docker-compose.yml
├── pyproject.toml
└── .pre-commit-config.yaml
```

## Quick start

```
git clone <repo> && cd ir-sam
docker compose build
docker compose run --rm dev pytest -q
```

## License
Apache-2.0. See [LICENSE](LICENSE).
