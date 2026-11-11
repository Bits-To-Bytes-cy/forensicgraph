# ForensicGraph Architecture Baseline

## Approved architecture

ForensicGraph is a modular monolith:

```text
React + TypeScript + Vite
            |
         FastAPI
            |
   services / repositories
            |
 SQLAlchemy 2 + Alembic
            |
      PostgreSQL
```

Redis and MinIO remain infrastructure dependencies from Phase 0. They are not
separate application services. Authentication is provider-independent OIDC
with application-issued access tokens, and every organization or case query
must enforce tenant isolation.

## Phase 1B boundaries

Case management owns:

- organization-scoped investigation cases and case numbers;
- case membership roles: Case Lead, Investigator, Reviewer, Observer;
- explicit status transitions and immutable status history;
- administrative audit events.

Routes remain thin. Services own transaction boundaries, numbering, workflow
validation, role checks, and audit creation. SQLAlchemy models enforce
organization-scoped composite relationships and uniqueness.

## Deferred capabilities

Evidence ingestion, evidence hashing, TrustLedger, timeline reconstruction,
attack graphs, PathLogic, AI assistance, and evidence provenance are outside
this baseline and must not be added as part of Phase 1B.
