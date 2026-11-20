"""Windows EVTX and Sysmon EVTX parser adapters."""

from __future__ import annotations

import json
import tempfile
from collections.abc import Iterable, Iterator
from pathlib import Path

from forensicgraph.parsers.base import ParsedRecord, ParserError


class EvtxParser:
    def __init__(self, name: str, version: str, sysmon: bool = False):
        self.name = name
        self.version = version
        self.sysmon = sysmon
        self.supported_formats = ("evtx",)

    def validate(self, media_type: str, filename: str) -> None:
        if not filename.lower().endswith(".evtx"):
            raise ParserError(
                "EVTX parser requires an .evtx filename",
                error_type="unsupported_format",
            )
        if media_type not in {
            "application/octet-stream",
            "application/x-ms-evtx",
        }:
            raise ParserError(
                "EVTX parser requires a binary media type",
                error_type="unsupported_media_type",
            )

    def parse(self, chunks: Iterable[bytes]) -> Iterator[ParsedRecord]:
        try:
            from Evtx.Evtx import Evtx
        except ImportError as error:
            raise ParserError(
                "EVTX parser dependency is unavailable",
                error_type="parser_unavailable",
            ) from error
        with tempfile.NamedTemporaryFile(suffix=".evtx") as temporary:
            for chunk in chunks:
                temporary.write(chunk)
            temporary.flush()
            try:
                with Evtx(Path(temporary.name)) as log:
                    for index, record in enumerate(log.records()):
                        xml = record.xml()
                        yield ParsedRecord(
                            source_locator=f"record:{index}:offset:{record.offset()}",
                            raw_payload=json.dumps(
                                {"xml": xml}, sort_keys=True, separators=(",", ":")
                            ),
                        )
            except Exception as error:
                raise ParserError(
                    "Malformed or unreadable EVTX input",
                    error_type="malformed_input",
                ) from error
