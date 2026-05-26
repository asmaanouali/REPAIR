# IR-SAM Web

Next.js 14 (App Router) + TypeScript + Tailwind + shadcn-style components,
Monaco diff editor, TanStack Query, framer-motion. Premium dark theme.

## Run

```bash
cp .env.example .env.local
npm install
npm run dev      # http://localhost:3000  (proxies /api/* → http://localhost:8000)
```

Sign in with the owner credentials defined in `apps/api/.env`
(`IRSAM_OWNER_EMAIL` / `IRSAM_OWNER_PASSWORD`).

## Routes

| Path | Purpose |
| ---- | ------- |
| `/login` | Owner sign-in (HttpOnly cookie via API) |
| `/dashboard` | KPI grid + recent projects + system health |
| `/projects` | Project list + create dialog (git / upload / sarif) |
| `/projects/[id]` | Project detail + trigger scan + scan history |
| `/scans/[id]` | Live SSE event stream + findings table |
| `/findings/[id]` | Monaco side-by-side diff + approve/reject + open GitHub PR |
| `/quickfix` | Paste a snippet, get a provable patch in-browser |
| `/settings` | Account + soundness guarantees |
```
