# Changelog

All notable changes to this project will be documented in this file.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.0] — Productionized IR-SAM

First production release. Turns the research artifact into a self-hosted,
single-user web application with hardened defaults and end-to-end CI.

### Added

- **`apps/api`** — FastAPI service with JWT-cookie auth, Postgres-backed
  persistence (SQLAlchemy 2 async), Alembic migrations, bcrypt password hashing,
  Fernet-encrypted secrets table, and structlog JSON logging.
  - Endpoints: `/auth/{login,logout,me}`, `/projects`, `/projects/{id}/scans`,
    `/scans/{id}` (+ `/findings`, `/events` SSE), `/findings/{id}` (+ patches,
    regenerate-patch), `/patches/{id}` (+ decision, pull-request), SARIF
    import, `/quickfix`, `/health`.
  - Hardening: slowapi rate-limit on `/auth/login` (10/min), Origin-guard
    middleware, security-headers middleware (HSTS / X-Frame / Referrer /
    Permissions), append-only audit log on auth, project, patch and PR events.
- **`apps/worker`** — Arq worker process running scans, patch generation and
  validator gates against the existing `ir-sam` core via a stable `core.api`
  facade. Inline backend supported for tests (`IRSAM_QUEUE_BACKEND=inline`).
- **`apps/web`** — Next.js 14 App Router + TypeScript strict + Tailwind +
  hand-crafted shadcn-style UI. Dark premium glassmorphism dashboard:
  - Login (Suspense-wrapped useSearchParams)
  - Dashboard KPIs
  - Projects (create with git / upload / SARIF tabs)
  - Project detail (trigger scan, scan list)
  - Live scan view (SSE event stream + findings list)
  - Finding view with Monaco side-by-side diff, approve/reject, GitHub PR
    dialog (ephemeral PAT)
  - Quickfix playground (Monaco editor, gates panel)
  - Settings (account, GitHub integration policy, soundness guarantees)
- **`infra/`** — `docker-compose.yml` with Postgres 16 + Redis 7 + api + worker
  + web, separate Dockerfiles per service, healthchecks, named volumes,
  `.env.example`.
- **`.github/workflows/ci.yml`** — single CI pipeline:
  `api-lint-test`, `irsam-core-test`, `web-typecheck-build`,
  `web-e2e` (Playwright chromium smoke), `schema-validation`, `docker-build`.
- **Docs.** `README.md` (architecture diagram, quick start, config matrix),
  `CONTRIBUTING.md`, `SECURITY.md`.
- **Playwright e2e** smoke covering login page render and unauthenticated
  middleware redirect.

### Security

- HttpOnly + SameSite=Lax session cookie (`irsam_session`), 12 h TTL.
- bcrypt 4.x used directly (passlib known-incompatible).
- GitHub PATs accepted per-request, **never persisted**.
- Owner credentials seeded once from `IRSAM_OWNER_EMAIL` /
  `IRSAM_OWNER_PASSWORD` (env-only).

### Tests

- `ir-sam` core: 115 ✓
- `apps/api`: 15 ✓
- `apps/web` typecheck + lint + build: ✓
- `apps/web` Playwright smoke: 3 ✓

## [0.x] — Research artifact

See `ir-sam/CHANGELOG.md` for the history of the underlying detector + IR-SAM
rewriter + validator releases (v0.1, v1.0 ICSE artifact, v2.0).
