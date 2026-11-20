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

## Phase 2 boundaries

Evidence Vault owns:

- streamed quarantine uploads with bounded size and allow-listed media types;
- immutable original object keys and evidence metadata;
- SHA-256/SHA-512 inventory hashes and storage read-back checks;
- derivative/working-copy registration without mutating originals;
- append-only hash-chained TrustLedger events with canonical JSON;
- integrity-check history and retryable storage/database reconciliation.

Evidence operations use the existing case and organization authorization
boundary. Original evidence is never exposed through direct object-storage
credentials; API downloads stream through the backend after authorization.

## Phase 3 boundaries

Evidence ingestion owns:

- explicit provider-independent parser contracts and registry;
- Windows EVTX and Sysmon EVTX adapters;
- Microsoft Entra sign-in and directory-audit JSON/CSV adapters;
- Microsoft 365 Unified Audit Log JSON/CSV adapters;
- bounded processing runs with progress, attempts, controlled reprocessing,
  persisted errors, and raw-record preservation.

Raw records retain the source evidence ID, processing-run ID, parser name and
version, stable source locator, canonical raw payload, and payload hash.
Parsers never modify original Evidence Vault objects or create normalized
events.

## Deferred capabilities

Normalized events, ChronoTrace, entity resolution, timeline reconstruction,
attack graphs, PathLogic, AI assistance, ATT&CK mapping, and evidence
provenance are outside this baseline and must not be added as part of Phase 3.
