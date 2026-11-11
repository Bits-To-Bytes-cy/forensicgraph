# ForensicGraph Copilot Instructions

ForensicGraph is a modular monolith for evidence-centric digital forensics and
incident reconstruction.

## Current scope

Phase 1B provides authentication-backed organizations, investigation cases,
case membership, workflow history, and administrative audit events. Do not add
evidence ingestion, hashing, TrustLedger, timeline reconstruction, attack
graphs, PathLogic, AI, or evidence provenance until separately approved.

## Engineering rules

- Preserve applied Alembic migrations; add forward migrations only.
- Keep FastAPI routes thin and put business rules in services.
- Enforce organization and case authorization at every data access boundary.
- Use SQLAlchemy 2 typed models and Pydantic v2 schemas.
- Use UUID primary keys and organization-scoped constraints.
- Never hard-delete investigations or audit history.
- Validate workflow transitions explicitly and record their actor.
- Add focused backend and frontend tests for every behavior change.
- Do not introduce microservices or unnecessary dependencies.
- Never commit credentials; use environment-backed settings.

## Security rules

- Require authenticated application access tokens.
- Verify organization membership before accessing organization data.
- Verify case membership and role before case operations.
- Prevent cross-organization foreign-key relationships.
- Protect the last Case Lead from removal or demotion.
- Record sensitive administrative operations in `system_audit_events`.
