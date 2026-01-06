from pathlib import Path

from aegismeta.infra.filesystem import compute_blake3_hash, compute_sha256, hash_file


def test_hash_file(tmp_path: Path) -> None:
    file_path = tmp_path / "data.bin"
    file_path.write_bytes(b"aegismeta")
    sha = compute_sha256(str(file_path))
    blake = compute_blake3_hash(str(file_path))
    result = hash_file(str(file_path))
    assert sha == result.sha256
    assert blake == result.blake3
    assert len(sha) == 64
    assert len(blake) == 64
