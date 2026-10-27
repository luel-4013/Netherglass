"""Evidence vault primitives: AES-256-GCM encryption at rest.

Key management stance (documented, honest): the key lives under
<data_dir>/keys with 0600 file permissions on the operator-controlled host.
Raw PCAP and ordinary metadata never contain plaintext secret values; sensitive
evidence blobs are encrypted before they touch disk. OS keystore integration and
operator-supplied keys are later hardening milestones.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

VAULT_MAGIC = b"NGV1"
NONCE_SIZE = 12
KEY_SIZE = 32


def load_or_create_key(keys_dir: Path) -> bytes:
    keys_dir = Path(keys_dir)
    keys_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(keys_dir, 0o700)
    key_path = keys_dir / "vault.key"
    if key_path.exists():
        return key_path.read_bytes()
    key = secrets.token_bytes(KEY_SIZE)
    key_path.write_bytes(key)
    os.chmod(key_path, 0o600)
    return key


def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    nonce = secrets.token_bytes(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad or None)
    return VAULT_MAGIC + nonce + ciphertext


def decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    if not blob.startswith(VAULT_MAGIC):
        raise ValueError("not a netherglass vault blob")
    nonce = blob[len(VAULT_MAGIC) : len(VAULT_MAGIC) + NONCE_SIZE]
    ciphertext = blob[len(VAULT_MAGIC) + NONCE_SIZE :]
    return AESGCM(key).decrypt(nonce, ciphertext, aad or None)


def seal_evidence(
    keys_dir: Path, evidence_dir: Path, evidence_id: str, data: bytes
) -> dict:
    keys_dir = Path(keys_dir)
    evidence_dir = Path(evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(evidence_dir, 0o700)
    key = load_or_create_key(keys_dir)
    path = evidence_dir / f"{evidence_id}.ngv"
    path.write_bytes(encrypt(key, data, aad=evidence_id.encode()))
    return {
        "evidence_id": evidence_id,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "path": str(path),
    }


def open_evidence(keys_dir: Path, evidence_dir: Path, evidence_id: str) -> bytes:
    key = load_or_create_key(keys_dir)
    path = Path(evidence_dir) / f"{evidence_id}.ngv"
    try:
        return decrypt(key, path.read_bytes(), aad=evidence_id.encode())
    except InvalidTag as exc:
        raise ValueError(
            "evidence integrity check failed (blob modified or wrong key)"
        ) from exc
