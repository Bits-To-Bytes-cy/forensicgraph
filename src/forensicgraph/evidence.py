"""Evidence integrity primitives."""

from __future__ import annotations

import hashlib
from pathlib import Path


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """Return the SHA-256 digest of a file without loading it all into memory."""
    digest = hashlib.sha256()
    with path.open("rb") as evidence:
        for chunk in iter(lambda: evidence.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()
