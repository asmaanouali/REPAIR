# Phase 5 -- Top-10 failure-mode catalog

| Rank | Label | Owner | Count | % obs | Dominant tool | Exemplars | Remediation |
|---:|---|---|---:|---:|---|---|---|
| 1 | `uncategorized` | triage | 46 | 32.86% | Semgrep-autofix | synth-CWE-89-java-00-00, synth-CWE-89-java-00-01 | investigate |
| 2 | `model_gen_failure` | out-of-scope | 40 | 28.57% | VulRepair | synth-CWE-89-java-00-00, synth-CWE-89-java-00-01 | LLM/seq2seq baselines |
| 3 | `llm_hallucinated_api` | out-of-scope | 28 | 20.0% | LLM-zero-shot | synth-CWE-89-java-00-03, synth-CWE-89-python-01-00 | LLM baselines only -- not a defect of IR-SAM |
