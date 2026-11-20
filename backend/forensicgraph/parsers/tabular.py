"""Bounded JSON and CSV parser helpers for cloud audit exports."""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterable, Iterator

from forensicgraph.parsers.base import ParsedRecord, ParserError


def _read_text(chunks: Iterable[bytes]) -> str:
    try:
        return b"".join(chunks).decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise ParserError(
            "Input is not valid UTF-8", error_type="invalid_encoding"
        ) from error


def parse_json_records(chunks: Iterable[bytes]) -> Iterator[ParsedRecord]:
    text = _read_text(chunks)
    if not text.strip():
        return
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as error:
                raise ParserError(
                    "Malformed JSON record",
                    error_type="malformed_record",
                    locator=f"line:{line_number}",
                ) from error
            yield ParsedRecord(
                source_locator=f"line:{line_number}",
                raw_payload=json.dumps(payload, sort_keys=True, separators=(",", ":")),
            )
        return
    if isinstance(document, list):
        for index, payload in enumerate(document):
            yield ParsedRecord(
                source_locator=f"index:{index}",
                raw_payload=json.dumps(payload, sort_keys=True, separators=(",", ":")),
            )
    elif isinstance(document, dict):
        yield ParsedRecord(
            source_locator="document:0",
            raw_payload=json.dumps(document, sort_keys=True, separators=(",", ":")),
        )
    else:
        raise ParserError(
            "JSON root must be an object or array", error_type="invalid_root"
        )


def parse_csv_records(chunks: Iterable[bytes]) -> Iterator[ParsedRecord]:
    text = _read_text(chunks)
    if not text.strip():
        return
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ParserError("CSV header is missing", error_type="invalid_schema")
    for row_number, row in enumerate(reader, start=2):
        if None in row:
            raise ParserError(
                "CSV row has more fields than its header",
                error_type="malformed_record",
                locator=f"line:{row_number}",
            )
        yield ParsedRecord(
            source_locator=f"line:{row_number}",
            raw_payload=json.dumps(dict(row), sort_keys=True, separators=(",", ":")),
        )
