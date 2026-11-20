"""Explicit parser registry."""

from forensicgraph.parsers.base import ParserError
from forensicgraph.parsers.cloud import (
    ENTRA_DIRECTORY_AUDIT,
    ENTRA_SIGNIN,
    M365_UNIFIED_AUDIT,
)
from forensicgraph.parsers.evtx import EvtxParser

WINDOWS_EVTX = EvtxParser("windows_evtx", "1.0.0")
SYSMON_EVTX = EvtxParser("sysmon_evtx", "1.0.0", sysmon=True)

PARSERS = {
    parser.name: parser
    for parser in (
        WINDOWS_EVTX,
        SYSMON_EVTX,
        ENTRA_SIGNIN,
        ENTRA_DIRECTORY_AUDIT,
        M365_UNIFIED_AUDIT,
    )
}


def get_parser(name: str):
    try:
        return PARSERS[name]
    except KeyError as error:
        raise ParserError(
            f"Unknown parser: {name}", error_type="unknown_parser"
        ) from error


def list_parsers() -> list[dict[str, object]]:
    return [
        {
            "name": parser.name,
            "version": parser.version,
            "supported_formats": parser.supported_formats,
        }
        for parser in PARSERS.values()
    ]
