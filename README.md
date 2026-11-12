# BalanceVault — Backend

FastAPI API for BalanceVault: authentication, role-based access control, account onboarding and an
append-only audit log. Data is stored in PostgreSQL (SQLAlchemy 2 + Alembic) and rate limits in Redis.

This repository is standalone. The web app lives in its own repository ([valut_frontend](https://github.com/Yashuu582/valut_frontend)) and talks to this API only over HTTP.

| Piece | Technology |
|---|---|
| API | FastAPI, Python 3.12+ |
| Database | PostgreSQL, SQLAlchemy 2 ORM, Alembic migrations, separate DB roles |
| Rate limiting | Redis (optional; falls back to in-memory) |
| Auth | bcrypt passwords, JWT access cookie + rotating refresh token |

## Roles

| Capability | Account holder | Auditor | Admin |
|---|:-:|:-:|:-:|
| Self-register, sign in | ✓ | – | – |
| View own accounts, apply for a new account | ✓ | | |
| Dashboard stats, view all accounts | | ✓ (read-only) | ✓ |
| Approve / reject applications, freeze / unfreeze | | | ✓ |
| Manage users (create staff, change role, suspend) | | | ✓ |
| View own transactions, transfer money from own active accounts | ✓ | | |
| View **all** transactions (with owner and initiator) | | ✓ (read-only) | ✓ |
| Post deposits and withdrawals | | | ✓ |
| View audit log | | ✓ | ✓ |

Staff users (admin, auditor) can only be created by an admin or with `scripts/create_admin.py`.
RBAC is enforced here, in `app/deps.py`.

## Configuration (`.env`)

```bash
copy .env.example .env      # macOS/Linux: cp .env.example .env
```

```env
DB_PORT=5433          # PostgreSQL port on your machine (the Docker container is published here)
DB_USER=postgres
DB_PASSWORD=12345
DB_NAME=balancevault
REDIS_PORT=6379       # leave empty to use in-memory rate limiting
JWT_SECRET=...        # long random value, 32+ characters
```

The same values are used by Docker Compose to create the PostgreSQL container and by the API to connect to it.
The host defaults to `localhost`. `CORS_ORIGINS` must list the frontend's URL (default `http://localhost:5173`).

## Run with Docker (PostgreSQL + Redis + API)

```bash
docker compose up -d --build
docker compose ps             # all three should become "healthy"
docker compose logs -f backend
```

| Container | Image | Port on your machine | Notes |
|---|---|---|---|
| `balancevault-postgres` | `postgres:17-alpine` | `127.0.0.1:${DB_PORT}` (5433) | Created with `DB_USER` / `DB_PASSWORD` / `DB_NAME` |
| `balancevault-redis` | `redis:7.4-alpine` | `127.0.0.1:${REDIS_PORT}` (6379) | AOF persistence |
| `balancevault-backend` | built from `Dockerfile` | `8000` | Runs `alembic upgrade head`, creates `BV_ADMIN_EMAIL` if set, serves the API |

- Data lives in the `pgdata` and `redisdata` volumes. `docker compose down -v` deletes them.
- PostgreSQL stores the user and password when the volume is first created. If you change `DB_USER` or
  `DB_PASSWORD` later, run `docker compose down -v` (this deletes the data) before `up` again.
- To connect with pgAdmin/psql from your machine: host `localhost`, port `5433`, user `postgres`, database `balancevault`.

## Run the API without Docker (database still in Docker)

```bash
docker compose up -d postgres redis
python -m venv .venv
.venv\Scripts\activate            # macOS/Linux: source .venv/bin/activate
pip install -r requirements-dev.txt
alembic upgrade head
python -m scripts.create_admin --email admin@example.com --name "Vault Admin"
uvicorn app.main:app --reload --port 8000
```

API docs: http://localhost:8000/docs · Liveness: `/health` · Readiness: `/ready`

`sql/db_roles.sql` is an optional hardening script for production servers. It creates separate least-privileged
database users and is not needed for local development.

## Deploy (Render + Neon, free)

1. **Neon**: create a project and copy the **direct** connection string (connection pooling off).
2. **Render** → New Web Service → this repository, branch `main`, runtime **Docker**, instance type **Free**,
   health check path `/health`.
3. Environment variables:

   | Key | Value |
   |---|---|
   | `DATABASE_URL` | Neon connection string (`postgresql://…?sslmode=require` is accepted as-is) |
   | `JWT_SECRET` | long random value, 32+ characters |
   | `ENVIRONMENT` | `production` |
   | `COOKIE_SECURE` | `true` |
   | `FORWARDED_ALLOW_IPS` | `*` |
   | `CORS_ORIGINS`, `FRONTEND_URL` | the frontend's public URL, e.g. `https://your-app.vercel.app` |
   | `BV_ADMIN_USERNAME`, `BV_ADMIN_EMAIL`, `BV_ADMIN_PASSWORD` | first admin (strong password) |

The container listens on `$PORT` (Render sets it), runs the migrations on start and creates the admin if missing.
No Redis is needed for a single instance.

## Tests

```bash
pytest -q        # uses a temporary SQLite DB; no Postgres or Redis needed
```

## Sign in, sign up, forgot password

- **Sign up** (`/register`): anyone can create an account-holder account with an email, an optional username
  and a strong password.
- **Sign in** (`/login`): use the email **or** the username, plus the password.
- **Admin**: created on start from `BV_ADMIN_USERNAME` / `BV_ADMIN_PASSWORD` in `.env`
  (default username `admin`). The script only creates it if it doesn't exist yet. It never changes an existing password.
- **Forgot password** (`/forgot-password`): sends a single-use link, valid for 30 minutes, to
  `FRONTEND_URL/reset-password?token=...`. Without `SMTP_HOST` the link is printed in the backend log:
  `docker compose logs backend | findstr "reset link"` (Linux/macOS: `grep "reset link"`).
  Resetting the password signs the user out on every device.

## Transactions ledger

- Every balance change is a row in `transactions`: `DEPOSIT`, `WITHDRAWAL`, `TRANSFER_OUT` and `TRANSFER_IN`.
  A transfer writes two rows that share a `transfer_id`. Each row stores the amount, the balance after it, who
  initiated it, and a unique reference (`TX…`).
- Rules: only `ACTIVE` accounts can move money, balances never go below zero, transfers need the same currency,
  and amounts are positive with at most 2 decimals.
- Account rows are locked during a movement (`SELECT … FOR UPDATE`), so parallel requests can't overspend.
- The table is append-only. A database trigger blocks UPDATE, DELETE and TRUNCATE. Mistakes are corrected
  with a new entry, never by editing an old one.

## API overview

| Method | Path | Access |
|---|---|---|
| POST | `/api/auth/register` · `/login` · `/refresh` · `/logout` | public |
| POST | `/api/auth/forgot-password` · `/reset-password` | public |
| GET | `/api/auth/me` | signed in |
| GET/POST | `/api/accounts` · GET `/api/accounts/{id}` | account holder (own only) |
| GET | `/api/admin/stats`, `/api/admin/accounts` | admin, auditor |
| POST | `/api/admin/accounts/{id}/review` · `/freeze` · `/unfreeze` | admin |
| GET/POST/PATCH | `/api/admin/users` · `/api/admin/users/{id}` | admin |
| GET | `/api/audit-logs` · `/api/audit-logs/actions` | admin, auditor |
| GET | `/api/transactions` · `/api/transactions/{id}` | holder: own only · admin, auditor: all |
| POST | `/api/transactions/transfer` | account holder |
| POST | `/api/admin/accounts/{id}/deposit` · `/withdraw` | admin |

## Project layout

```
app/            FastAPI app: config, models, schemas, auth, RBAC, rate limiting, routers
alembic/        database migrations
sql/            DB role bootstrap (db_roles.sql) and its Docker init wrapper
scripts/        create_admin.py
tests/          pytest suite
Dockerfile, docker-entrypoint.sh, docker-compose.yml
```

## Security notes

- Passwords are hashed with bcrypt (cost 12). The policy is 12+ characters with upper, lower, digit and symbol.
- The access token is a 15-minute JWT in an httpOnly cookie. The refresh token is opaque, lasts 7 days, rotates
  on every use and is stored hashed. If a rotated token is reused, the whole session family is revoked.
- Suspending a user takes effect immediately and revokes all of their sessions.
- Login is rate limited per email and per IP, registration per IP, and the whole API per IP.
- Cross-origin writes are rejected (Origin check), and security headers and `Cache-Control: no-store` are set.
- Security-relevant actions, including failed sign-ins, are written to `audit_logs` in the same transaction.
  A database trigger blocks UPDATE, DELETE and TRUNCATE on that table.
- In production set `ENVIRONMENT=production` (disables `/docs`) and `COOKIE_SECURE=true` (HTTPS).
