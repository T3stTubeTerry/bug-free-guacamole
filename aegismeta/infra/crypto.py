from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Tuple

try:
    from cryptography.hazmat.backends import default_backend  # type: ignore
    from cryptography.hazmat.primitives import hashes  # type: ignore
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # type: ignore
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # type: ignore

    HAS_CRYPTO = True
except Exception:  # pragma: no cover - optional dependency
    HAS_CRYPTO = False


@dataclass
class EncryptionResult:
    nonce: bytes
    ciphertext: bytes
    tag: bytes


PBKDF2_ITERATIONS = 390000
KEY_LENGTH = 32


def derive_key(password: str, salt: bytes) -> bytes:
    if not HAS_CRYPTO:
        raise RuntimeError("cryptography dependency is required for key derivation")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(data: bytes, key: bytes) -> EncryptionResult:
    if not HAS_CRYPTO:
        raise RuntimeError("cryptography dependency is required for encryption")
    nonce = os.urandom(12)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend()).encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return EncryptionResult(nonce=nonce, ciphertext=ciphertext, tag=encryptor.tag)


def decrypt_bytes(enc: EncryptionResult, key: bytes) -> bytes:
    if not HAS_CRYPTO:
        raise RuntimeError("cryptography dependency is required for decryption")
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(enc.nonce, enc.tag),
        backend=default_backend(),
    ).decryptor()
    return decryptor.update(enc.ciphertext) + decryptor.finalize()


def encrypt_file(input_path: str, output_path: str, key: bytes) -> None:
    if not HAS_CRYPTO:
        raise RuntimeError("cryptography dependency is required for encryption")
    with open(input_path, "rb") as f:
        data = f.read()
    enc = encrypt_bytes(data, key)
    with open(output_path, "wb") as f:
        f.write(enc.nonce + enc.tag + enc.ciphertext)


def decrypt_file(input_path: str, output_path: str, key: bytes) -> None:
    if not HAS_CRYPTO:
        raise RuntimeError("cryptography dependency is required for decryption")
    with open(input_path, "rb") as f:
        content = f.read()
    nonce, tag, ciphertext = content[:12], content[12:28], content[28:]
    enc = EncryptionResult(nonce=nonce, ciphertext=ciphertext, tag=tag)
    data = decrypt_bytes(enc, key)
    with open(output_path, "wb") as f:
        f.write(data)
