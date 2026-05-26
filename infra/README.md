# IR-SAM Infrastructure

Single-host Docker Compose deployment.

## Quick start

```bash
cp infra/.env.example infra/.env
# edit secrets in infra/.env (JWT_SECRET, FERNET_KEY, owner password)
docker compose -f infra/docker-compose.yml --env-file infra/.env up --build
```

Services:

| Service  | Port | Purpose                              |
|----------|------|--------------------------------------|
| web      | 3000 | Next.js dashboard                    |
| api      | 8000 | FastAPI (auth, scans, findings, …)   |
| worker   | —    | Arq worker (run_scan, generate_patch)|
| postgres | 5432 | Primary database                     |
| redis    | 6379 | Job queue + scan event pubsub        |

## Migrations

The `api` container runs `alembic upgrade head` on each start. To run
manually:

```bash
docker compose -f infra/docker-compose.yml exec api \
    sh -c "cd /app/apps/api && alembic upgrade head"
```

## Generating secrets

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"            # JWT_SECRET
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"  # FERNET_KEY
```
