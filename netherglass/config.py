"""Configuration and safe defaults for Netherglass.

Design rules:
- Bind to localhost unless the operator explicitly opts into internal-network
  exposure. Netherglass must never be exposed to the public internet.
- Capture profile B (standard security) is the default; profile C (full
  evidence) requires explicit operator confirmation at the API layer.
- All data lives under one directory so retention, backup and secure deletion
  stay simple and auditable.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import asdict, dataclass, field
from pathlib import Path

ENV_DATA_DIR = "NETHERGLASS_DATA_DIR"


def default_data_dir() -> Path:
    override = os.environ.get(ENV_DATA_DIR)
    if override:
        return Path(override).expanduser()
    return Path.home() / ".local" / "share" / "netherglass"


@dataclass(frozen=True)
class CaptureProfile:
    id: str
    name: str
    description: str
    store_pcap: bool
    store_payload: bool
    store_sensitive_values: bool
    encrypt_evidence: bool
    retention_hours: int
    max_capture_bytes: int


CAPTURE_PROFILES: dict[str, CaptureProfile] = {
    "A": CaptureProfile(
        id="A",
        name="Metadata Only",
        description="No payloads retained. Metadata, flows and findings only.",
        store_pcap=False,
        store_payload=False,
        store_sensitive_values=False,
        encrypt_evidence=True,
        retention_hours=24,
        max_capture_bytes=0,
    ),
    "B": CaptureProfile(
        id="B",
        name="Standard Security Capture",
        description="Recommended default. PCAP within limits; sensitive values encrypted at rest.",
        store_pcap=True,
        store_payload=True,
        store_sensitive_values=True,
        encrypt_evidence=True,
        retention_hours=72,
        max_capture_bytes=4 * 1024**3,
    ),
    "C": CaptureProfile(
        id="C",
        name="Full Authorized Evidence Capture",
        description=(
            "Full payload/evidence capture. May retain credentials, tokens and "
            "personal data. Requires explicit operator confirmation."
        ),
        store_pcap=True,
        store_payload=True,
        store_sensitive_values=True,
        encrypt_evidence=True,
        retention_hours=168,
        max_capture_bytes=16 * 1024**3,
    ),
}


@dataclass
class ScopeConfig:
    allowed_cidrs: list[str] = field(default_factory=list)
    excluded_cidrs: list[str] = field(default_factory=list)
    allowed_domains: list[str] = field(default_factory=list)
    excluded_domains: list[str] = field(default_factory=list)
    allowed_interfaces: list[str] = field(default_factory=list)
    excluded_interfaces: list[str] = field(default_factory=list)
    allowed_ports: list[int] = field(default_factory=list)
    excluded_ports: list[int] = field(default_factory=list)
    max_capture_seconds: int = 3600
    storage_limit_bytes: int = 20 * 1024**3


@dataclass
class ServeConfig:
    host: str = "127.0.0.1"
    port: int = 8787
    behind_tls: bool = False
    session_hours: int = 12


@dataclass
class AppConfig:
    data_dir: Path
    profile: str = "B"
    serve: ServeConfig = field(default_factory=ServeConfig)
    scope: ScopeConfig = field(default_factory=ScopeConfig)

    @property
    def is_network_exposed(self) -> bool:
        return self.serve.host not in ("127.0.0.1", "localhost", "::1")

    def db_path(self) -> Path:
        return self.data_dir / "netherglass.db"

    def warnings(self) -> list[str]:
        out: list[str] = []
        if self.profile not in CAPTURE_PROFILES:
            raise ValueError(f"unknown capture profile: {self.profile}")
        if self.profile == "C":
            out.append(
                "PROFILE C: full evidence capture may retain credentials, tokens, "
                "cookies and personal data. Explicit confirmation is required and "
                "evidence access stays permission-gated."
            )
        if self.is_network_exposed:
            out.append(
                "Serving on a non-local interface. Netherglass must NEVER be exposed "
                "to the public internet; deploy only on a trusted internal network "
                "with authentication enabled (enforced by default)."
            )
        if not self.serve.behind_tls:
            out.append(
                "TLS is not enabled. On an internal network, place Netherglass behind "
                "a TLS reverse proxy or terminate TLS in front of it."
            )
        return out

    def validate(self) -> None:
        if self.profile not in CAPTURE_PROFILES:
            raise ValueError(f"unknown capture profile: {self.profile}")
        if not (1 <= self.serve.port <= 65535):
            raise ValueError("serve.port out of range")

    def save(self, path: Path | None = None) -> Path:
        target = path or (self.data_dir / "config.json")
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "profile": self.profile,
            "serve": asdict(self.serve),
            "scope": asdict(self.scope),
        }
        target.write_text(json.dumps(payload, indent=2) + "\n")
        os.chmod(target, stat.S_IRUSR | stat.S_IWUSR)
        return target

    @classmethod
    def load(cls, data_dir: Path | None = None) -> "AppConfig":
        root = Path(data_dir).expanduser() if data_dir else default_data_dir()
        cfg = cls(data_dir=root)
        path = root / "config.json"
        if path.exists():
            raw = json.loads(path.read_text())
            if raw.get("profile") in CAPTURE_PROFILES:
                cfg.profile = raw["profile"]
            serve = raw.get("serve", {})
            cfg.serve = ServeConfig(
                host=str(serve.get("host", cfg.serve.host)),
                port=int(serve.get("port", cfg.serve.port)),
                behind_tls=bool(serve.get("behind_tls", cfg.serve.behind_tls)),
                session_hours=int(serve.get("session_hours", cfg.serve.session_hours)),
            )
            scope = raw.get("scope", {})
            known = ScopeConfig.__dataclass_fields__
            cfg.scope = ScopeConfig(**{k: v for k, v in scope.items() if k in known})
        return cfg


def ensure_layout(data_dir: Path) -> dict[str, Path]:
    dirs = {
        "root": data_dir,
        "captures": data_dir / "captures",
        "evidence": data_dir / "evidence",
        "logs": data_dir / "logs",
        "keys": data_dir / "keys",
    }
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, stat.S_IRWXU)
    return dirs
