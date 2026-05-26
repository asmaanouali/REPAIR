# Contributing

Thanks for your interest in IR-SAM. This is a research-grade artifact being
turned into a production-quality, self-hosted product. Contributions are
welcome — please follow the workflow below.

## Ground rules

- **Soundness first.** The validator pipeline (parametrization → invariants →
  semantic equivalence) is a load-bearing claim of the project. Any change to
  `ir-sam/core/validator/*` or the rewriters must keep the existing tests green
  and add new ones for the behaviour you change.
- **No regressions.** All three test suites must pass locally before opening a
  PR:
  - `cd ir-sam && pytest -q`
  - `cd apps/api && pytest -q`
  - `cd apps/web && npm run typecheck && npm run lint && npm run build`
- **Conventional commits** (`feat:`, `fix:`, `chore:`, `docs:`, `test:`,
  `refactor:`) — they drive the changelog.
- **No secrets in commits.** `.env`, GitHub PATs, Fernet keys, signing secrets
  belong in your local untracked `.env`. CI uses repository secrets only.

## Local setup

```bash
# Backend
python -m venv .venv && source .venv/bin/activate   # (Windows: .venv\Scripts\Activate.ps1)
pip install -e "./ir-sam[dev]"
pip install -e "./apps/api[dev]"
pip install -e "./apps/worker"

# Frontend
cd apps/web && npm install
```

Create `apps/api/.env` from `apps/api/.env.example` and set at minimum
`IRSAM_JWT_SECRET`, `IRSAM_SECRETS_FERNET_KEY`, `IRSAM_OWNER_EMAIL`,
`IRSAM_OWNER_PASSWORD`.

## Running the stack

```bash
# Terminal 1
cd apps/api && uvicorn irsam_api.main:app --reload

# Terminal 2
cd apps/worker && arq irsam_worker.tasks.WorkerSettings

# Terminal 3
cd apps/web && npm run dev
```

Or all-in-one:

```bash
cd infra && docker compose up --build
```

## Style

- Python: `ruff check` (lint), `ruff format` (format). Type hints required on
  public APIs. Use the existing `from __future__ import annotations` pattern.
- TypeScript: `tsc --strict` clean, `eslint` clean. Prefer named exports, no
  default exports outside of Next.js `page.tsx` / `layout.tsx` files.
- Commit messages: 50-char subject, blank line, wrapped body if needed.

## Filing issues

- **Bug:** include OS, Python/Node version, exact commands, full traceback.
- **Security:** open a private GitHub security advisory — do not file a public
  issue.
- **Feature:** sketch the use-case and the soundness implications before
  proposing changes to the validator or rewriter.

## License

By contributing you agree your contributions are licensed under Apache-2.0.
