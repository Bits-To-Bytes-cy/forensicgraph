"""HTTP API for the initial ForensicGraph vertical slice."""

from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from forensicgraph.evidence import sha256_file

app = FastAPI(
    title="ForensicGraph API",
    version="0.1.0",
    description="Evidence integrity services for authorized digital-forensics investigations.",
)


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
