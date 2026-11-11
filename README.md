# ForensicGraph

ForensicGraph is an evidence-centric Digital Forensics and Incident
Reconstruction platform focused on identity compromise and cloud data
exfiltration investigations.

## Phase 0: Engineering Foundation

This branch intentionally contains infrastructure and application foundations
only. Evidence ingestion, hashing, chain of custody, AI, graph analysis, and
timeline reconstruction are deferred to later phases.

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

- No domain models or migrations exist yet; the Alembic environment is ready
  for the first approved model migration.
- Health checks report dependency availability but do not mutate infrastructure.
- Credentials are supplied through `.env`; no credentials are committed.
- The frontend is a navigation-ready shell only.
