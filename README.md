# NETHERGLASS

**Network visibility, traffic analysis, evidence preservation and authorized
security-testing platform — internal red-team/engineering use only.**

> See everything crossing the wire. Prove it later.

Named after the Norse watchman of Bifröst, the bridge between realms: a guard
that sees everything that crosses and remembers it. The name was collision-
checked (GitHub API) and alternatives considered: Ratatoskr, Tiresias, Pharos,
Ariadne (all free) — Netherglass was chosen for uniqueness and the metaphor.

---

## Status: M8 complete — detection engine, sensitive-data engine, findings,
web security (M5), cases/timeline/graph/reports (M5), tunnels/VPN visibility,
cloud flow-log adapters, Kubernetes correlation (M6), controlled testing with
fail-closed scope enforcement (M7), hardening: fuzzing, malformed-traffic
tolerance, storage-limit enforcement, evidence secure deletion, secret-echo
defenses (M8), evidence vault + viewer with audited reveal (plus PCAPNG/PCAP
evidence export and the out-of-band `panic` stop, pulled forward from later
milestones)

| Layer | State |
|---|---|
| Python 3.12 + FastAPI + SQLite (WAL) backend | done |
| Auth (argon2id, server-side sessions, CSRF, login rate limit) | done |
| RBAC (spec §20 permission set + capture/emergency/manage extensions) | done |
| Hash-chained tamper-evident audit log | done (verified in tests + live) |
| Emergency Security Stop (trigger/recover, halts capture <2s, audit, fail-closed) | done |
| Interface discovery + capture-source readiness (honest limitations) | done |
| Evidence vault primitives (AES-256-GCM, 0600 keyfile) | done |
| Log redaction (passwords/JWT/cookies/keys never reach logs) | done |
| Green-phosphor terminal web UI (React + Vite + TS) | done |
| **Live capture** (dumpcap → PcapNG ring → tshark EK decode → SQLite) | **done** |
| **Offline PCAP/PCAPNG import** (sha256 manifest, background decode) | **done** |
| **Packet + flow browser** (filters, paging, live counters incl. drops) | **done** |
| **Host discovery** (names w/ source ranking, services, sent/recv counters) | **done** |
| **DNS analysis** (query/response correlation, answers, TTL, NXDOMAIN, orphans) | **done** |
| **HTTP analysis** (requests/responses, path + param names only, no values) | **done** |
| **TLS metadata** (SNI, version, cipher, ALPN, JA3/JA4, cert SANs + validity) | **done** |
| **Search query language** + graphical filter builder | **done** |
| **Statistics** (top talkers/domains/ports, traffic/DNS volume, encryption) | **done** |
| **`netherglass hosts` / `stats` / `search` headless commands** | **done** |
| **Security-quality grading** (GOOD/WEAK/INSECURE/UNKNOWN per §10) | **done** |
| **Sensitive-data detection** (auth headers, cookies, tokens, form/FTP creds) | **done** |
| **Evidence vault** (sealed values, metadata-only profile A, sha256) | **done** |
| **Audited reveal workflow** (reason required, 30s auto-hide, emergency-blocked) | **done** |
| **Detection engine** (23 rules, severity+confidence, rules.json overrides) | **done** |
| **Findings + on-demand analysis** (rebuild per run, evidence-cited) | **done** |
| **Web security** (cookies/headers/JWT metadata, app inventory, data flows) | **done** |
| **Cases, timeline, graph, reports** (masked + audited restricted export) | **done** |
| **VPN/tunnel visibility** (IPsec/WireGuard/OpenVPN/GRE/IP-in-IP/VXLAN) | **done** |
| **Cloud flow-log adapters** (AWS VPC / Azure NSG / GCP / generic CSV+JSON) | **done** |
| **Kubernetes correlation** (pod/service/node inventory + observed-flow match) | **done** |
| **Controlled testing** (fail-closed scope file, dry-run default, rate/time bounds, abort, audited) | **done** |
| **Hardening** (parser fuzzing, malformed packets, storage/volume bounds, API/authz matrix, leakage scans, tamper detection) | **done** |
| **Evidence secure deletion** (admin-only, reason + audit, zero-overwrite, emergency-blocked) | **done** |
| 207 backend tests + real-tshark integration, frontend build green | done |

Nothing here pretends to be more than it is. Features not listed do not exist
yet — no fake screens, no dead buttons.

---

## Quickstart

```bash
cd netherglass
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt

# interface inventory (works with zero privileges)
.venv/bin/python -m netherglass interfaces
.venv/bin/python -m netherglass doctor

# headless live capture (requires wireshark group; see below)
.venv/bin/python -m netherglass capture --interface wlo1 --seconds 15
.venv/bin/python -m netherglass capture --interface wlo1 --seconds 30 --bpf "tcp port 443"

# offline import (works with zero privileges; sha256 manifest + decode)
.venv/bin/python -m netherglass import /path/to/capture.pcapng

# analysis (defaults to the latest capture; --json for machines)
.venv/bin/python -m netherglass hosts
.venv/bin/python -m netherglass stats
.venv/bin/python -m netherglass search 'tls.sni ~ "example" AND port = 443'

# run the server (writes bootstrap admin credentials to the data dir)
.venv/bin/python -m netherglass serve                 # 127.0.0.1:8787
.venv/bin/python -m netherglass serve --host 0.0.0.0  # internal LAN (auth enforced)

# user management
.venv/bin/python -m netherglass user add --username analyst1 --role analyst
.venv/bin/python -m netherglass user list

# out-of-band emergency stop (works without the web UI; recovery still needs
# an authorized operator with RECOVER_EMERGENCY_STOP in the UI)
.venv/bin/python -m netherglass panic --reason "suspected compromise"
```

Captures can be exported back out as **PCAPNG or PCAP** from the capture
detail panel in the UI (`GET /api/captures/{id}/export?format=pcapng|pcap`,
requires `EXPORT_EVIDENCE`, blocked during an emergency stop, and audited as
`EVIDENCE_EXPORTED`). Ring files are merged with `mergecap` on export.

### Live capture permission (one-time)

`dumpcap` is installed group-executable for `wireshark`. Give your user that
group, then re-login (or use `newgrp wireshark` in a shell):

```bash
sudo usermod -aG wireshark $USER
```

Until then the UI shows the exact fix in CAPTURE READINESS, and offline import
remains fully usable. `doctor` never claims live capture is ready when it isn't.

Live capture needs **your** one-time install (sudo requires your password):

```bash
sudo pacman -S wireshark-cli    # provides dumpcap + tshark
.venv/bin/python -m netherglass doctor
```

Web UI:

```bash
# development (hot reload, proxies /api to :8787)
cd web && npm install && npm run dev        # http://localhost:5173

# production (FastAPI serves the built SPA — no node needed at runtime)
cd web && npm run build                     # then just run `netherglass serve`
```

First login: `admin` + the password in
`~/.local/share/netherglass/BOOTSTRAP_CREDENTIALS.txt` (0600). Change it,
delete the file.

---

## Deployment rule (non-negotiable)

NETHERGLASS must **never** be exposed to the public internet. It is built for a
trusted internal network, binds to localhost by default, and enforces
authentication, CSRF protection, login rate limiting and a hash-chained audit
trail from day one — but it will hold credentials, tokens, cookies and packet
evidence. Put TLS in front of it (reverse proxy) on shared networks. See
`SECURITY.md`.

---

## Interfaces on this machine (found by the tool)

| Interface | Kind | State | Address |
|---|---|---|---|
| `wlo1` | wifi | up | 192.168.1.71/24 |
| `eno1` | ethernet | down | — |
| `lo` | loopback | up | 127.0.0.1/8 |

The UI lists every interface and lets the analyst pick one. Honest limitation,
shown in the UI: Wi-Fi in managed mode captures this host's traffic and
broadcast/multicast only — that is physics, not a bug.

---

## Milestones

| # | Scope | Spec phase |
|---|---|---|
| M1 | Foundation: config, logging, auth/RBAC, audit, panic switch, interfaces, vault, UI shell | Phase 1 (part) |
| M2 | Capture engine: dumpcap ring buffers, PCAP import/export, packet model, bounded queues, drop counters, packets screen | Phase 1 (rest) — **done** |
| M3 | Flow engine, DNS/HTTP/TLS analysis, hosts, search, statistics | Phase 2 — **done** |
| M4 | Detection engine, sensitive-data engine, findings, evidence store + viewer + reveal workflow | Phase 3–4 — **done** |
| M5 | Web-security module, cookie/session/token analysis, reports (masked + restricted) | Phase 5 — **done** |
| M6 | VPN/tunnel visibility, Kubernetes, cloud flow-log adapters | Phase 6 — **done** |
| M7 | Controlled testing module (separate subsystem, separate permissions) | Phase 7 — **done** |
| M8 | Hardening: fuzzing, exhaustion bounds, secure deletion, API security tests | Phase 8 — **done** |

---

## Honesty rules (enforced like Warden32 and Breadcrumb)

1. Never claim packet visibility when the source provides flow metadata only.
2. Never claim decrypted content when only SNI/metadata is observable.
3. Drop counters, backpressure and capture health are always visible.
4. Secrets are never logged, never in the normal search index, never in audit
   records — only in the encrypted vault behind permission checks and reveals.
5. Findings carry confidence (OBSERVED / LIKELY / POSSIBLE / NOT_DETERMINED).
6. No automatic exploitation, credential replay or token abuse — ever.

## Documentation

- `docs/DESIGN.md` — architecture, threat model, and implemented design per milestone (M2–M8)
- `docs/AUDIT.md` — hardening audit: defects found/fixed, accepted risks, residual risks
- `docs/POSTMORTEM.md` — six-month failure post-mortem (adoption, operations, organization)
- `docs/RESEARCH.md` — market research: what succeeded, what died, why
- `SECURITY.md` — deployment rules and vulnerability disclosure

## Repository layout

```text
netherglass/        Python package (FastAPI app, capture engine, analysis, stores)
  capture/          dumpcap/PcapNG capture, PCAP import/export, tshark EK decode
  analysis/         protocols, rules, sensitive data, web security, reports
  store/            SQLite schema + stores (packets, flows, evidence vault, cases)
  api/              JSON API routes
  security/         auth, RBAC, audit chain, redaction
  ingest/           cloud flow-log + Kubernetes adapters
tests/              207 tests (incl. real-tshark integration, M8 hardening suite)
web/                React + Vite + TypeScript UI (green-phosphor terminal theme)
docs/               design, audit, post-mortem, research
```

## License

MIT — see [`LICENSE`](LICENSE). Copyright (c) 2026 luel-4013.

Netherglass is a defensive, audit-first tool. It performs no automatic
exploitation; its controlled-testing module only sends probes to targets that
appear in an operator-maintained authorization file, and every reveal, export
and test is written to the tamper-evident audit log.
