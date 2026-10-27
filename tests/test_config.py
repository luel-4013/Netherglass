import stat
from pathlib import Path

from netherglass.config import CAPTURE_PROFILES, AppConfig, ensure_layout


def test_defaults_are_safe(tmp_path: Path) -> None:
    cfg = AppConfig(data_dir=tmp_path)
    assert cfg.profile == "B"
    assert cfg.serve.host == "127.0.0.1"
    assert not cfg.is_network_exposed


def test_profile_a_retains_no_payload() -> None:
    profile = CAPTURE_PROFILES["A"]
    assert profile.store_payload is False
    assert profile.store_sensitive_values is False
    assert profile.store_pcap is False


def test_profile_c_warns() -> None:
    cfg = AppConfig(data_dir=Path("/tmp/does-not-matter"))
    cfg.profile = "C"
    joined = " ".join(cfg.warnings())
    assert "credentials" in joined.lower()


def test_network_exposure_warning(tmp_path: Path) -> None:
    cfg = AppConfig(data_dir=tmp_path)
    cfg.serve.host = "0.0.0.0"
    assert cfg.is_network_exposed
    joined = " ".join(cfg.warnings())
    assert "internet" in joined.lower()


def test_save_and_load_roundtrip(tmp_path: Path) -> None:
    cfg = AppConfig(data_dir=tmp_path)
    cfg.profile = "A"
    cfg.serve.port = 9999
    cfg.scope.allowed_cidrs = ["10.10.0.0/16"]
    cfg.save()
    loaded = AppConfig.load(tmp_path)
    assert loaded.profile == "A"
    assert loaded.serve.port == 9999
    assert loaded.scope.allowed_cidrs == ["10.10.0.0/16"]


def test_unknown_profile_rejected(tmp_path: Path) -> None:
    cfg = AppConfig(data_dir=tmp_path)
    cfg.profile = "Z"
    try:
        cfg.validate()
        raised = False
    except ValueError:
        raised = True
    assert raised


def test_ensure_layout_permissions(tmp_path: Path) -> None:
    dirs = ensure_layout(tmp_path / "d")
    for d in dirs.values():
        mode = stat.S_IMODE(d.stat().st_mode)
        assert mode == 0o700
