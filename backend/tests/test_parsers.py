import json

import pytest
from forensicgraph.parsers import ParserError
from forensicgraph.parsers.cloud import (
    ENTRA_DIRECTORY_AUDIT,
    ENTRA_SIGNIN,
    M365_UNIFIED_AUDIT,
)
from forensicgraph.parsers.evtx import EvtxParser
from forensicgraph.parsers.tabular import parse_csv_records, parse_json_records


def test_json_and_csv_preserve_stable_locators():
    json_records = list(parse_json_records([b'[{"id": 1}, {"id": 2}]']))
    csv_records = list(parse_csv_records([b"id,name\n1,Alice\n2,Bob\n"]))

    assert [record.source_locator for record in json_records] == [
        "index:0",
        "index:1",
    ]
    assert [record.source_locator for record in csv_records] == ["line:2", "line:3"]
    assert json.loads(json_records[0].raw_payload) == {"id": 1}
    assert json.loads(csv_records[1].raw_payload) == {"id": "2", "name": "Bob"}


def test_large_json_export_extracts_all_bounded_records():
    payload = json.dumps(
        [
            {
                "createdDateTime": f"2026-01-01T00:{index:02d}:00Z",
                "userPrincipalName": f"user-{index}",
                "ipAddress": "10.0.0.1",
            }
            for index in range(120)
        ]
    ).encode()
    records = list(parse_json_records([payload]))
    assert len(records) == 120
    assert records[-1].source_locator == "index:119"


def test_malformed_and_empty_inputs_are_controlled():
    assert list(parse_json_records([b""])) == []
    with pytest.raises(ParserError, match="Malformed JSON record"):
        list(parse_json_records([b'{"id":\n']))
    assert list(parse_csv_records([b"\n"])) == []


@pytest.mark.parametrize(
    ("parser", "payload"),
    [
        (
            ENTRA_SIGNIN,
            {
                "createdDateTime": "2026-01-01",
                "userPrincipalName": "u",
                "ipAddress": "1.1.1.1",
            },
        ),
        (
            ENTRA_DIRECTORY_AUDIT,
            {"activityDateTime": "2026-01-01", "activityDisplayName": "Update user"},
        ),
        (
            M365_UNIFIED_AUDIT,
            {"CreationTime": "2026-01-01", "Operation": "Read", "UserId": "u"},
        ),
    ],
)
def test_cloud_parsers_validate_required_fields(parser, payload):
    parser.validate("application/json", "export.json")
    parser.set_format("export.json")
    records = list(parser.parse([json.dumps(payload).encode()]))
    assert records[0].source_locator == "document:0"


def test_cloud_parser_rejects_missing_required_field():
    ENTRA_SIGNIN.validate("application/json", "export.json")
    ENTRA_SIGNIN.set_format("export.json")
    with pytest.raises(ParserError, match="Required fields missing"):
        list(ENTRA_SIGNIN.parse([b'{"createdDateTime":"2026-01-01"}']))


def test_evtx_parser_rejects_malformed_input_and_keeps_explicit_contract():
    parser = EvtxParser("windows_evtx", "1.0.0")
    parser.validate("application/octet-stream", "Security.evtx")
    with pytest.raises(ParserError, match="Malformed or unreadable EVTX"):
        list(parser.parse([b"not-an-evtx-file"]))
