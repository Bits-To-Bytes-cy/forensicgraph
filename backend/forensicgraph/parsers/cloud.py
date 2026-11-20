"""Microsoft Entra and Microsoft 365 audit export parsers."""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator

from forensicgraph.parsers.base import ParsedRecord, ParserError
from forensicgraph.parsers.tabular import parse_csv_records, parse_json_records


class CloudAuditParser:
    def __init__(
        self,
        name: str,
        version: str,
        required_fields: tuple[str, ...],
        formats: tuple[str, ...] = ("json", "csv"),
    ):
        self.name = name
        self.version = version
        self.required_fields = required_fields
        self.supported_formats = formats

    def validate(self, media_type: str, filename: str) -> None:
        suffix = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if suffix not in self.supported_formats:
            raise ParserError(
                f"Parser {self.name} does not support .{suffix or 'unknown'}",
                error_type="unsupported_format",
            )
        if media_type not in {
            "application/json",
            "text/csv",
            "application/octet-stream",
        }:
            raise ParserError(
                f"Parser {self.name} does not support media type {media_type}",
                error_type="unsupported_media_type",
            )

    def parse(self, chunks: Iterable[bytes]) -> Iterator[ParsedRecord]:
        if not hasattr(self, "_format"):
            raise ParserError(
                "Parser format was not initialized",
                error_type="parser_configuration",
            )
        records = (
            parse_csv_records(chunks)
            if self._format == "csv"
            else parse_json_records(chunks)
        )
        for record in records:
            try:
                payload = json.loads(record.raw_payload)
            except ValueError as error:
                raise ParserError(
                    "Parser produced invalid JSON",
                    error_type="parser_error",
                    locator=record.source_locator,
                ) from error
            missing = [field for field in self.required_fields if field not in payload]
            if missing:
                raise ParserError(
                    f"Required fields missing: {', '.join(missing)}",
                    error_type="schema_validation",
                    locator=record.source_locator,
                )
            yield record

    def set_format(self, filename: str) -> None:
        self._format = filename.rsplit(".", 1)[-1].lower()


ENTRA_SIGNIN = CloudAuditParser(
    "entra_signin", "1.0.0", ("createdDateTime", "userPrincipalName", "ipAddress")
)
ENTRA_DIRECTORY_AUDIT = CloudAuditParser(
    "entra_directory_audit", "1.0.0", ("activityDateTime", "activityDisplayName")
)
M365_UNIFIED_AUDIT = CloudAuditParser(
    "m365_unified_audit", "1.0.0", ("CreationTime", "Operation", "UserId")
)
