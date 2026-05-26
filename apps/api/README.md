# IR-SAM API

FastAPI service exposing the IR-SAM pipeline behind a REST + websocket
surface. See [docs/operations.md](../../docs/operations.md) for run
instructions. This service is one of three apps in the productionized
monorepo:

- `apps/api`   — this package (HTTP / WS surface, auth, DB).
- `apps/worker` — Arq worker that runs scans and patch generation.
- `apps/web`   — Next.js dashboard.

The Python core (`ir-sam/core`) is reached **only** through
`core.api`, the additive facade introduced in Phase 1.
