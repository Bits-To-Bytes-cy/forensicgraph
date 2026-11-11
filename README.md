# ForensicGraph

ForensicGraph is an evidence-centric Digital Forensics and Incident
Reconstruction platform focused on identity compromise and cloud data
exfiltration investigations.

## Phase 1A: Authentication and Organization Management

Phase 1A adds provider-independent OIDC Authorization Code Flow with PKCE,
validated state/nonce/issuer/audience/signature/expiry, short-lived application
access tokens, rotated and revocable refresh sessions, identity mapping by
issuer and subject, organizations, memberships, roles, and tenant-isolated API
access.

Phase 1B adds organization-scoped investigation cases, generated case numbers,
case roles, transactional assignments, explicit status transitions, immutable
status history, administrative audit events, and a React case dashboard.

Phase 2 adds the Evidence Vault: bounded streamed uploads through quarantine,
immutable original objects, SHA-256/SHA-512 metadata, read-back verification,
append-only hash-chained TrustLedger custody events, integrity history, and
derivative/working-copy registration.

### Phase 2 Evidence API

- `POST /api/v1/cases/{case_id}/evidence/uploads`
- `PUT /api/v1/evidence/uploads/{upload_id}/content`
- `POST /api/v1/evidence/uploads/{upload_id}/complete`
- `GET /api/v1/cases/{case_id}/evidence`
- `GET /api/v1/evidence/{evidence_id}`
- `POST /api/v1/evidence/{evidence_id}/verify`
- `GET /api/v1/evidence/{evidence_id}/custody`
- `GET /api/v1/evidence/{evidence_id}/download`
- `POST|GET /api/v1/evidence/{evidence_id}/derivatives`

### Phase 1B API

- `POST /api/v1/organizations/{organization_id}/cases`
- `GET /api/v1/organizations/{organization_id}/cases`
- `GET /api/v1/organizations/{organization_id}/cases/{case_id}`
- `GET /api/v1/cases/{case_id}`
- `PATCH /api/v1/cases/{case_id}`
- `POST|GET /api/v1/cases/{case_id}/members`
- `DELETE /api/v1/cases/{case_id}/members/{user_id}`
- `POST /api/v1/cases/{case_id}/status`
- `GET /api/v1/cases/{case_id}/history`

Configure an OIDC provider in `.env` before using `/api/v1/auth/login`. There
is intentionally no development login bypass.

### Phase 1A API

- `GET|POST /api/v1/auth/login`
- `GET /api/v1/auth/callback`
- `POST /api/v1/auth/refresh`
- `POST /api/v1/auth/logout`
- `GET /api/v1/auth/me`
- `POST|GET /api/v1/organizations`
- `GET /api/v1/organizations/{organization_id}`
- `POST|GET /api/v1/organizations/{organization_id}/members`

## Phase 0: Engineering Foundation

Log parsing, normalization, timeline reconstruction, chain analysis, AI,
graph analysis, ATT&CK mapping, and provenance remain deferred to later
phases.

### Repository structure

```text
backend/
  forensicgraph/
    api/                 # HTTP boundary
    models/              # SQLAlchemy model boundary
    repositories/        # persistence adapters
    services/            # application use cases
    app.py               # FastAPI entrypoint
    config.py            # environment-backed settings
    db.py                # SQLAlchemy engine/session
    health.py            # PostgreSQL, Redis, MinIO checks
  migrations/            # Alembic environment and revisions
frontend/
  src/                   # React + TypeScript + Vite shell
backend/tests/            # pytest foundation tests
docker-compose.yml       # backend, frontend, PostgreSQL, Redis, MinIO
```

## Local development

Copy `.env.example` to `.env` and replace all `change-me` values:

```bash
cp .env.example .env
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
alembic -c backend/alembic.ini upgrade head
uvicorn forensicgraph.app:app --app-dir backend --reload
```

In another terminal:

```bash
cd frontend
npm install
npm run dev
```

The backend API is available at `http://localhost:8000/health` and the
frontend at `http://localhost:5173`.

## Docker Compose

```bash
cp .env.example .env
docker compose config
docker compose up --build
```

Services:

| Service | Purpose | Port |
| --- | --- | --- |
| `backend` | FastAPI application | 8000 |
| `frontend` | React/Vite production build served by Nginx | 5173 |
| `postgres` | Application database | 5432 |
| `redis` | Cache/task-queue foundation | 6379 |
| `minio` | S3-compatible object-storage foundation | 9000 / 9001 |

## Quality checks

```bash
pytest
ruff check backend
ruff format --check backend
cd frontend
npm run build
npm run lint
npm run test
npm run format
```

## Phase 0 limitations

- Authentication and organization tables are defined by migration
  `0002_auth_organizations`; future migrations must preserve both applied
  revisions.
- Health checks report dependency availability but do not mutate infrastructure.
- Credentials are supplied through `.env`; no credentials are committed.
- The frontend is a navigation-ready shell only.
- OIDC provider discovery and JWKS validation require a reachable configured
  identity provider; tests use isolated SQLite and mocked validation boundaries.
