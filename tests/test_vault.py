import stat
from pathlib import Path

import pytest

from netherglass.store.vault import (
    decrypt,
    encrypt,
    load_or_create_key,
    open_evidence,
    seal_evidence,
)


def test_encrypt_decrypt_roundtrip(tmp_path: Path) -> None:
    key = load_or_create_key(tmp_path / "keys")
    blob = encrypt(key, b"super secret evidence", aad=b"EVD-0001")
    assert b"super secret evidence" not in blob
    assert decrypt(key, blob, aad=b"EVD-0001") == b"super secret evidence"


def test_wrong_key_fails(tmp_path: Path) -> None:
    key1 = load_or_create_key(tmp_path / "k1")
    key2 = load_or_create_key(tmp_path / "k2")
    blob = encrypt(key1, b"data")
    with pytest.raises(Exception):
        decrypt(key2, blob)


def test_aad_mismatch_fails(tmp_path: Path) -> None:
    key = load_or_create_key(tmp_path / "keys")
    blob = encrypt(key, b"data", aad=b"one")
    with pytest.raises(Exception):
        decrypt(key, blob, aad=b"two")


def test_key_file_permissions(tmp_path: Path) -> None:
    load_or_create_key(tmp_path / "keys")
    mode = stat.S_IMODE((tmp_path / "keys" / "vault.key").stat().st_mode)
    assert mode == 0o600


def test_seal_and_open_evidence(tmp_path: Path) -> None:
    record = seal_evidence(tmp_path / "keys", tmp_path / "evidence", "EVD-0001", b"payload")
    assert record["evidence_id"] == "EVD-0001"
    assert record["size"] == 7
    assert len(record["sha256"]) == 64
    assert (
        open_evidence(tmp_path / "keys", tmp_path / "evidence", "EVD-0001") == b"payload"
    )


def test_rejects_foreign_blob(tmp_path: Path) -> None:
    key = load_or_create_key(tmp_path / "keys")
    with pytest.raises(ValueError):
        decrypt(key, b"not-a-vault-blob")
