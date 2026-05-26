# IR-SAM Worker

Arq worker that drains background jobs queued by the API service:

- `run_scan`         — walk a project root, populate findings + patches.
- `generate_patch`   — synthesize a patch for a single finding.
- `import_sarif_task` — ingest a SARIF blob, create findings.

The worker imports `core.api` (additive facade) and reuses the DB
layer from `irsam_api` so models stay in one place.
