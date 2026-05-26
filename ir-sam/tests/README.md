# IR-SAM Test Suite

This directory contains the production-grade test phase for IR-SAM. Tests are
organized into tiers via pytest markers (declared in
[../pyproject.toml](../pyproject.toml)) and selected via
[`scripts/run_tests.py`](../scripts/run_tests.py).

## Tiers

| Tier     | Marker selector                                        | Budget   | When                          |
|----------|--------------------------------------------------------|----------|-------------------------------|
| `fast`   | `unit or property`                                     | <=10 min | every push, pre-commit pre-push |
| `full`   | `unit or property or integration or e2e`               | <=30 min | every PR                      |
| `eval`   | + `differential`                                       | hours    | weekly / on-demand            |
| `release`| + `perf or soundness or security or mutation or fuzz`  | nightly  | tag push                      |

## Markers

- `unit`       -- fast, hermetic (default if no other tier marker is present).
- `property`   -- Hypothesis property-based tests.
- `integration`-- cross-module / CLI / SARIF-adapter integration.
- `e2e`        -- A..G pipeline against synthetic Juliet-mini corpus.
- `differential` -- requires the `oracle` docker-compose profile (DB sandboxes).
- `perf`       -- enforces MVP §7 budgets; uses pytest-benchmark.
- `security`   -- adversarial inputs, supply-chain, prompt injection.
- `soundness`  -- mechanized soundness-audit predicates (P1..P4).
- `mutation`   -- mutmut-driven mutation testing (nightly).
- `fuzz`       -- atheris/Hypothesis fuzzers (nightly).
- `slow`       -- excluded from `fast` even within other tiers.
- `requires_docker`, `requires_corpus`, `requires_llm` -- auto-skipped when the
  corresponding resource is unavailable (see `conftest.py`).

## Determinism

- `IRSAM_TEST_SEED` (default `20260524`) seeds `random`, `PYTHONHASHSEED`, and
  numpy. Use a different value to reproduce a flake.
- `IRSAM_UPDATE_GOLDEN=1` re-writes golden files under `tests/golden/`. Never
  set this in CI.

## Layout

```
tests/
  conftest.py                  # seed fixture, markers, skip gates
  property/                    # Hypothesis property tier
  integration/                 # CLI, SARIF-adapter, cross-stage integration
  security/                    # adversarial / robustness
  differential/                # deep differential oracle (DB containers)
  perf/                        # pytest-benchmark perf-budget tests
  fuzz/                        # atheris fuzz harnesses
  golden/                      # checked-in expected outputs
    patches/                   # one diff per binder rule
  fixtures/                    # tiny corpus samples, SARIF goldens, ...
  test_*.py                    # legacy / cross-cutting unit tests
```

## CI

- [.github/workflows/fast.yml](../.github/workflows/fast.yml) -- every push.
- [.github/workflows/full.yml](../.github/workflows/full.yml) -- every PR.
- [.github/workflows/nightly.yml](../.github/workflows/nightly.yml) -- 03:17 UTC.
- [.github/workflows/release.yml](../.github/workflows/release.yml) -- on tag.
