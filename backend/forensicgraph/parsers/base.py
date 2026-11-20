"""Stable parser contracts for raw evidence extraction."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class ParsedRecord:
    source_locator: str
    raw_payload: str


class ParserError(Exception):
    """Controlled parser failure associated with a source or record."""

    def __init__(
        self,
        message: str,
        *,
        error_type: str = "parse_error",
        locator: str | None = None,
    ):
        super().__init__(message)
        self.error_type = error_type
        self.locator = locator


class Parser(Protocol):
    name: str
    version: str
    supported_formats: tuple[str, ...]

    def validate(self, media_type: str, filename: str) -> None: ...

    def parse(self, chunks: Iterable[bytes]) -> Iterator[ParsedRecord]: ...
