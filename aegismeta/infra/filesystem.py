from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

try:
    import blake3  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    blake3 = None

MAGIC_SIGNATURES: Dict[bytes, str] = {
    b"\xFF\xD8\xFF": "jpg",
    b"\x89PNG": "png",
    b"GIF8": "gif",
    b"%PDF": "pdf",
    b"PK\x03\x04": "zip",
}


@dataclass
class FileHashResult:
    sha256: str
    blake3: str


def compute_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def compute_blake3_hash(path: str) -> str:
    if blake3 is not None:
        hasher = blake3.blake3()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    # fallback using blake2s to keep interface operational offline
    h = hashlib.blake2s()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_file(path: str) -> FileHashResult:
    return FileHashResult(sha256=compute_sha256(path), blake3=compute_blake3_hash(path))


def detect_magic_extension(path: str) -> Optional[str]:
    with open(path, "rb") as f:
        prefix = f.read(8)
    for magic, ext in MAGIC_SIGNATURES.items():
        if prefix.startswith(magic):
            return ext
    return None


def detect_mime_type(path: str) -> Optional[str]:
    mime, _ = mimetypes.guess_type(path)
    return mime


def read_json(path: Path) -> Dict[str, str]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, payload: Dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def calculate_entropy(path: Path) -> float:
    data = path.read_bytes()
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    entropy = 0.0
    length = len(data)
    for count in freq:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)
    return entropy
