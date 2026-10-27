import logging

from netherglass.logging_setup import REDACTION, RedactingFilter, redact


def test_password_assignment_redacted() -> None:
    out = redact("login password=hunter2 done")
    assert "hunter2" not in out
    assert REDACTION in out


def test_json_password_redacted() -> None:
    out = redact('{"username": "bob", "password": "s3cr3t!"}')
    assert "s3cr3t" not in out


def test_authorization_header_redacted() -> None:
    out = redact("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payloadpart.signaturepart")
    assert "eyJhbGciOiJIUzI1NiJ9" not in out


def test_cookie_header_redacted() -> None:
    out = redact("Cookie: SESSIONID=abc123; theme=dark")
    assert "abc123" not in out
    assert "theme=dark" not in out


def test_jwt_redacted() -> None:
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop"
    assert jwt not in redact(f"artifact {jwt} observed")


def test_aws_key_redacted() -> None:
    assert "AKIAIOSFODNN7EXAMPLE" not in redact("key AKIAIOSFODNN7EXAMPLE found")


def test_private_key_block_redacted() -> None:
    blob = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
    out = redact(f"captured: {blob}")
    assert "MIIEowIBAAKCAQEA" not in out


def test_ordinary_metadata_untouched() -> None:
    line = "flow 10.0.0.5:52344 -> 10.0.0.9:443 TLS1.3 4211 packets"
    assert redact(line) == line


def test_logging_filter_scrubs_record() -> None:
    record = logging.LogRecord(
        "netherglass.test", logging.INFO, __file__, 1, "password=%s", ("hunter2",), None
    )
    RedactingFilter().filter(record)
    assert "hunter2" not in record.getMessage()
