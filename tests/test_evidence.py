from pathlib import Path

from forensicgraph.evidence import sha256_file


def test_sha256_file_hashes_large_files_in_chunks(tmp_path: Path) -> None:
    evidence = tmp_path / "capture.bin"
    evidence.write_bytes(b"forensicgraph" * 100_000)

    assert sha256_file(evidence) == (
        "61e8b79355fc49a8883f403ee812a42a9bde751568be50448428cee8264868a0"
    )
