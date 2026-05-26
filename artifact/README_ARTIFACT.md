# IR-SAM Reproducibility Artifact

This bundle accompanies the paper *"IR-SAM: Interpreter-aware,
Soundness-Anchored Repair of Injection Vulnerabilities Across
Languages and Frameworks"*. It is submitted for:

  - **ACM Artifacts Evaluated -- Reusable** (and *Functional*),
  - **ACM Artifacts Available**,
  - **USENIX Available**.

## TL;DR (3 commands, < 30 min wall-clock)

```bash
docker build -t irsam:v1.0 -f artifact/Dockerfile .
docker run --rm irsam:v1.0                            # smoke test
docker run --rm irsam:v1.0 bash /opt/irsam/artifact/full_run.sh
```

## Hardware and software requirements

  - **CPU.** Any x86_64 with 4 cores (artifact tested on Intel
    i5-1135G7 and Apple M2). No GPU is required.
  - **RAM.** 4 GB free.
  - **Disk.** 1.5 GB for the Docker image + 200 MB for reports.
  - **OS.** Linux, macOS, or Windows with Docker Desktop 4.x.
  - **Network.** None at run-time. The build phase downloads
    pinned pip wheels (~150 MB).

## What is reproduced

| Claim in paper                            | Smoke    | Full     |
|-------------------------------------------|---------:|---------:|
| 92/92 unit tests pass                     | yes      | yes      |
| Phase-2 differential oracle PASS          | yes      | yes      |
| Phase-4 multilang fix rate ≥ 0.75         | yes      | yes      |
| Phase-5 six-metric table (Table 1)        | yes      | yes      |
| Phase-5 acceptance verdict PASS           | yes      | yes      |
| Top-10 failure-mode catalog               | yes      | yes      |
| Pre-registered study protocol present     | yes      | yes      |
| Real-tier baselines (VulRepair, GPT-4, ...) | no     | optional |
| Phase 1-6 PDFs rebuilt                    | no       | yes      |

The synthetic-tier baselines are **deterministic and seeded**:
re-running the smoke test on a different machine yields the same
six-metric table to the last decimal. The real-tier path is activated
by exporting the env vars listed at the top of `full_run.sh`.

## Disclosures (ACM Reusable §B.4)

  - **Closed/paid resources we do not bundle.** OpenAI API access
    (GPT-4 baselines), CVEfixes/Vul4J/BigVul archives, VulRepair and
    SeqTrans model weights. Each baseline has a deterministic
    synthetic fallback calibrated to the baseline's published
    per-CWE accuracy. The synthetic tier is clearly disclosed in
    `reports/phase5_metrics.json` (`tier` field).
  - **Stochasticity.** Every random source is seeded with a
    SHA-256-derived integer; re-runs are bit-identical.
  - **Human study.** The blinded developer study is
    pre-registered (`ir-sam/study/protocol.md`) and IRB-applied
    (`ir-sam/study/irb_application.md`). Aggregate responses will
    be deposited on Zenodo on acceptance; raw responses cannot be
    redistributed under the institutional IRB's data-handling clause.

## File map

```
artifact/
  Dockerfile          one-stage build, < 500 MB, no GPU
  requirements.txt    pinned pip deps
  smoke_test.sh       < 30 minute reproducibility path
  full_run.sh         optional full re-run including PDF rebuilds
  README_ARTIFACT.md  this file
  INSTALL.md          host-install path (no Docker)
  STATUS.md           ACM/USENIX badge requests + justification

ir-sam/
  core/         pipeline implementation (~6k LOC)
  bench/        synthetic + real-archive evaluators
  baselines/    7 adapter implementations
  eval/         six metrics, top-10 catalog
  scripts/      eval_phase2.py, eval_phase4.py, eval_phase5.py
  study/        pre-registered protocol, IRB, survey, analysis
  reports/      live output from smoke / full runs
  tests/        92 unit tests
```

## Build and run on the host (no Docker)

See `INSTALL.md` for a host-install fallback (Python 3.10 + pip).

## Reviewer support

For artifact-evaluation questions, reach the authors via the
anonymous-channel provided by the chairs. Please report any deviation
between the headline table in the paper and the table produced on
your machine; the artifact has been pinned for bit-identical output
and any divergence is a bug.
