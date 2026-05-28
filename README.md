# Attack Surface Monitor — Backend

Python/FastAPI backend for the Attack Surface Monitor SaaS.

## Stack

| Layer | Tech |
|---|---|
| API | FastAPI + Uvicorn |
| DB | PostgreSQL 16 + SQLAlchemy 2 + Alembic |
| Queue | Celery 5 + Redis 7 |
| Auth | JWT (python-jose) + bcrypt |
| Payments | Stripe |

---

## Quickstart (Docker)

```bash
# 1. Clone & configure
cp .env.example .env
# Edit .env — set SECRET_KEY to a random 64-char string

# 2. Start services
docker-compose up --build -d

# 3. Run DB migrations
docker-compose exec api alembic revision --autogenerate -m "initial"
docker-compose exec api alembic upgrade head

# 4. Open API docs
open http://localhost:8000/docs
```

## Run tests locally

```bash
pip install -r requirements.txt
pytest tests/ -v
```

---

## API reference

| Method | Path | Description |
|---|---|---|
| POST | `/api/v1/auth/register` | Register new user |
| POST | `/api/v1/auth/login` | Get JWT token |
| GET  | `/api/v1/auth/me` | Current user info |
| POST | `/api/v1/workspaces` | Create workspace |
| GET  | `/api/v1/workspaces` | List workspaces |
| POST | `/api/v1/workspaces/{id}/domains` | Add domain (triggers scan) |
| GET  | `/api/v1/workspaces/{id}/domains` | List domains |
| POST | `/api/v1/workspaces/{id}/domains/{did}/scan` | Manual scan trigger |
| GET  | `/api/v1/workspaces/{id}/findings` | List findings (filterable) |
| PATCH| `/api/v1/workspaces/{id}/findings/{fid}` | Mark finding resolved |

---

## Plan limits

| Plan | Domains | Scan interval | Price |
|---|---|---|---|
| Free | 1 | Manual only | $0 |
| Starter | 5 | Daily | $49/mo |
| Pro | 25 | Hourly | $199/mo |

---

## Week 3-4 next steps

Replace scanner stubs in `app/tasks/scan_tasks.py`:

- `_run_subdomain_scan()` → wrap `subfinder -d {fqdn} -json`
- `_run_port_scan()` → async nmap wrapper
- `_run_vuln_scan()` → nuclei runner with CVE templates
