"""HTTP API for the ForensicGraph investigation workflow."""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field

from forensicgraph.evidence import sha256_file
from forensicgraph.attack_graph import analyze_attack_graph
from forensicgraph.timeline import custody_digest, reconstruct_timeline

app = FastAPI(
    title="ForensicGraph API",
    version="0.1.0",
    description="Evidence integrity services for authorized digital-forensics investigations.",
)
_dashboard = Path(__file__).parent / "static" / "index.html"


class EvidenceManifest(BaseModel):
    """Verifiable metadata for a collected evidence item."""

    model_config = ConfigDict(frozen=True)

    evidence_id: str = Field(min_length=1)
    source: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    collected_at: datetime


class EvidenceHashRequest(BaseModel):
    path: str = Field(min_length=1)
    evidence_id: str = Field(min_length=1)
    source: str = Field(min_length=1)


class EvidenceVerifyRequest(BaseModel):
    path: str = Field(min_length=1)
    expected_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class TimelineEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    event_id: str = Field(min_length=1)
    occurred_at: datetime
    source: str = Field(min_length=1)
    event_type: str = Field(min_length=1)
    actor: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class TimelineRequest(BaseModel):
    events: list[TimelineEvent] = Field(min_length=1, max_length=10_000)


class AttackGraphRequest(BaseModel):
    events: list[TimelineEvent] = Field(min_length=1, max_length=10_000)


class IncidentReportRequest(BaseModel):
    case_id: str = Field(min_length=1)
    events: list[TimelineEvent] = Field(min_length=1, max_length=10_000)


class CustodyEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    sequence: int = Field(ge=1)
    action: str = Field(min_length=1)
    actor: str = Field(min_length=1)
    evidence_id: str = Field(min_length=1)
    recorded_at: datetime
    previous_digest: str
    digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class CustodyRequest(BaseModel):
    action: str = Field(min_length=1)
    actor: str = Field(min_length=1)
    evidence_id: str = Field(min_length=1)


_custody_log: list[CustodyEntry] = []


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(_dashboard)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "forensicgraph"}


@app.post("/v1/evidence/hash", response_model=EvidenceManifest)
def hash_evidence(request: EvidenceHashRequest) -> EvidenceManifest:
    """Hash a local lab evidence file and return its signed-manifest payload."""
    path = Path(request.path)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Evidence file was not found")

    return EvidenceManifest(
        evidence_id=request.evidence_id,
        source=request.source,
        sha256=sha256_file(path),
        collected_at=datetime.now(timezone.utc),
    )


@app.post("/v1/evidence/verify")
def verify_evidence(request: EvidenceVerifyRequest) -> dict[str, bool | str]:
    """Re-hash evidence and compare it with a previously recorded digest."""
    path = Path(request.path)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Evidence file was not found")
    actual_sha256 = sha256_file(path)
    return {
        "valid": actual_sha256 == request.expected_sha256,
        "expected_sha256": request.expected_sha256,
        "actual_sha256": actual_sha256,
    }


@app.post("/v1/timeline/reconstruct", response_model=list[TimelineEvent])
def timeline(request: TimelineRequest) -> list[TimelineEvent]:
    """Normalize and deterministically order events from multiple evidence sources."""
    return [
        TimelineEvent.model_validate(event)
        for event in reconstruct_timeline(
            [event.model_dump() for event in request.events]
        )
    ]


@app.post("/v1/attack-graph/analyze")
def attack_graph(request: AttackGraphRequest) -> dict[str, Any]:
    """Return explainable attack-path edges and risk findings."""
    events = [event.model_dump() for event in request.events]
    return analyze_attack_graph(events)


@app.post("/v1/cases/report")
def incident_report(request: IncidentReportRequest) -> dict[str, Any]:
    """Create a reproducible investigation summary from normalized events."""
    timeline_events = reconstruct_timeline(
        [event.model_dump() for event in request.events]
    )
    graph = analyze_attack_graph(timeline_events)
    return {
        "case_id": request.case_id,
        "generated_at": datetime.now(timezone.utc),
        "event_count": len(timeline_events),
        "timeline": timeline_events,
        "attack_graph": graph,
        "custody": {
            "valid": verify_custody_log()["valid"],
            "entries": len(_custody_log),
        },
    }


@app.post("/v1/custody", response_model=CustodyEntry)
def append_custody_entry(request: CustodyRequest) -> CustodyEntry:
    """Append a hash-chained chain-of-custody entry for an evidence item."""
    recorded_at = datetime.now(timezone.utc)
    sequence = len(_custody_log) + 1
    previous_digest = _custody_log[-1].digest if _custody_log else "0" * 64
    digest = custody_digest(
        sequence=sequence,
        action=request.action,
        actor=request.actor,
        evidence_id=request.evidence_id,
        recorded_at=recorded_at,
        previous_digest=previous_digest,
    )
    entry = CustodyEntry(
        sequence=sequence,
        action=request.action,
        actor=request.actor,
        evidence_id=request.evidence_id,
        recorded_at=recorded_at,
        previous_digest=previous_digest,
        digest=digest,
    )
    _custody_log.append(entry)
    return entry


@app.get("/v1/custody", response_model=list[CustodyEntry])
def custody_log() -> list[CustodyEntry]:
    return list(_custody_log)


@app.get("/v1/custody/verify")
def verify_custody_log() -> dict[str, bool | int]:
    previous_digest = "0" * 64
    for entry in _custody_log:
        expected = custody_digest(
            sequence=entry.sequence,
            action=entry.action,
            actor=entry.actor,
            evidence_id=entry.evidence_id,
            recorded_at=entry.recorded_at,
            previous_digest=previous_digest,
        )
        if entry.previous_digest != previous_digest or entry.digest != expected:
            return {"valid": False, "entries": len(_custody_log)}
        previous_digest = entry.digest
    return {"valid": True, "entries": len(_custody_log)}
