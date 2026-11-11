# ForensicGraph

ForensicGraph is a defensive digital-forensics platform for preserving evidence
integrity, reconstructing incident timelines, and explaining attack paths.

## Project status

The initial vertical slice provides:

- A FastAPI service with health and evidence-manifest endpoints
- SHA-256 hashing for evidence files
- A tamper-evident manifest model suitable for later chain-of-custody work
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
