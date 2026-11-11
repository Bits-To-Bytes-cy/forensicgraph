# ForensicGraph

ForensicGraph is a defensive digital-forensics platform for preserving evidence
integrity, reconstructing incident timelines, and explaining attack paths.

## Project status

The initial vertical slice provides:

- A FastAPI service with health and evidence-manifest endpoints
- SHA-256 hashing for evidence files
- A tamper-evident manifest model suitable for later chain-of-custody work
- Deterministic timeline reconstruction across multiple evidence sources
- Hash-chained chain-of-custody entries with integrity verification
- Explainable attack-graph edges and actor risk findings
- SQLite-backed case and event persistence
- Browser investigator workbench for creating cases and generating reports
- Focused tests for hashing and API behavior

This project is intended for authorized investigations and synthetic lab data.

## Local development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
uvicorn forensicgraph.api:app --reload
```

The API is then available at `http://127.0.0.1:8000/docs`.
The investigator dashboard is available at `http://127.0.0.1:8000/`.

To run the service in a container:

```bash
docker build -t forensicgraph .
docker run --rm -p 8000:8000 forensicgraph
```

## Initial API

- `POST /v1/evidence/hash` — hash a local lab evidence file
- `POST /v1/evidence/verify` — detect changes since a recorded hash
- `POST /v1/timeline/reconstruct` — normalize and sort investigation events
- `POST /v1/attack-graph/analyze` — build attack paths and risk findings
- `POST /v1/cases/report` — generate a reproducible incident report
- `POST /v1/cases` / `GET /v1/cases` — create and list persisted cases
- `POST /v1/cases/{case_id}/events` — ingest normalized evidence events

The `examples/synthetic-incident.json` file contains a safe, repeatable attack
scenario for demonstrations and testing.
- `POST /v1/custody` — append a chain-of-custody entry
- `GET /v1/custody/verify` — verify the in-memory custody hash chain

Case metadata, events, generated reports, and the custody ledger are persisted
in SQLite. Set
`FORENSICGRAPH_DB_PATH` to a durable path in production; Docker Compose mounts
`/data` as a named volume.

## CV-ready capabilities demonstrated

This prototype demonstrates evidence integrity engineering, normalized
multi-source event modeling, deterministic forensic timelines, explainable
attack-path analysis, hash-chained custody, persistent case management, REST
API design, browser UX, containerization, and continuous testing. The included
synthetic scenario is safe to reproduce in a lab without using real victim data.
