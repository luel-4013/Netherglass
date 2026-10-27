# NETHERGLASS design

## 1. Layering (spec §2) — implemented so far marked [M1]

```
Capture sources                     [M1: discovery/readiness; M2: engines]
   dumpcap (live, preferred)        ── PcapNG ring files
   tcpdump  (fallback)              ── captures/<cap-id>/ring-*.pcapng
   scapy    (fallback, CAP_NET_RAW)
   offline PCAP/PCAPNG import
        ↓
Decode (tshark -T ek JSON)                          [M2]
        ↓
Normalize → SQLite WAL                              [M1 schema planted]
   hosts · flows · dns · http · tls · packets-index
        ↓
Correlation (DNS→IP→flow→app)                       [M3]
        ↓
Detection rules → findings (evidence-cited)         [M4 — done]
        ↓
Evidence Vault (AES-256-GCM, chain of custody)      [M1 primitives + M4]
        ↓
Investigation (cases, timeline, graph)              [M4–M5]
        ↓
Reporting (masked / restricted)                     [M5]
```

## 2. Security architecture (the part CISSO will review)

**Trust boundaries**

```
[analyst browser] ──HTTPS reverse proxy──▶ [FastAPI :8787]
                                                │
                     ┌──────────────────────────┼──────────────────────┐
                     │                          │                      │
              SQLite (0600, WAL)        evidence/*.ngv (0600)    captures/*.pcapng
              metadata, flows,          AES-256-GCM blobs        ring files
              findings, audit chain     + vault.key (0600)
```

- **Auth**: argon2id; server-side sessions (only SHA-256 of the session id is
  stored); HttpOnly + SameSite=Strict cookies; `Secure` when behind TLS.
- **CSRF**: per-session CSRF token required on every state-changing request;
  cross-origin requests rejected at the middleware.
- **Rate limiting**: login limiter (5 failures / 5 min per IP+user).
- **RBAC**: spec §20 permission set. Role matrix: `admin` (all), `analyst`
  (view metadata/findings/sensitive-metadata, export evidence, create controlled
  tests, **trigger** emergency stop), `auditor` (view + audit log). Separate
  permissions guard: revealing sensitive values, exporting sensitive evidence,
  deleting evidence, managing profiles, enabling full capture, executing
  controlled tests, **recovering** from an emergency stop.
- **Audit**: every event hash-chains off the previous one (`prev_hash + sha256`);
  `verify_chain()` detects any tampering. Audit details pass the log-redaction
  scrubber — secrets never enter the audit record (tested).
- **Secret hygiene**: redaction filter installed on all log handlers;
  redaction patterns: key=value secrets, Authorization headers, cookies, JWTs,
  AWS access keys, private-key blocks (9 tests).
- **No docs endpoints** (`/docs`, `/openapi.json` disabled) — smaller attack
  surface; internal API only.
- **Fail closed**: emergency stop halts capture/tests/exports, locks the vault,
  and nothing auto-restarts.

## 3. Emergency Security Stop (spec §26/§62)

State machine: `READY ⇄ STOPPED` stored in `system_state`. Trigger requires
TRIGGER_EMERGENCY_STOP + exact phrase `EMERGENCY STOP` + CSRF. Recovery requires
RECOVER_EMERGENCY_STOP + non-empty reason + CSRF, and refuses when not stopped.
Both audit. `capture_halt` threading.Event is the hook the M2 capture engine
must observe before every write. Evidence files are never touched by stop.

## 4. Storage model (spec §24/§44)

| Store | Location | Protection |
|---|---|---|
| Metadata/flows/findings/audit | `netherglass.db` | dir 0700; single file; WAL |
| Raw capture | `captures/<cap-id>/*.pcapng` | dir 0700; ring-buffer limits (M2) |
| Sensitive evidence | `evidence/*.ngv` | AES-256-GCM, per-blob AAD = evidence id |
| Vault key | `keys/vault.key` | 0600; OS keystore integration scheduled (M8) |
| Logs | `logs/netherglass.log` | redaction filter mandatory |

Deployment default: `~/.local/share/netherglass` (`NETHERGLASS_DATA_DIR` to
override).

## 5. M2 — Capture engine (implemented)

**Purpose**: turn the readiness report into real live capture and offline import.

**Implementation** (module `netherglass/capture/`):

1. `DumpcapSource` (preferred): spawns
   `dumpcap -i <if> -b duration:<chunk> -b files:10 -b filesize:51200 -w captures/<id>/cap.pcapng [-f <bpf>]`,
   parses its stderr for `Packets captured` / `Packets received/dropped`
   counters (honest, tool-reported), stops via process group SIGINT then
   SIGKILL, and reports permission failures with exact remediation.
2. `TcpdumpSource` fallback with `-C -W` ring rotation.
3. `OfflinePcapSource` equivalent: `import_file()` copies the file into
   `captures/<id>/source/`, records sha256 + original name in `manifest.json`,
   and decodes in a background thread.
4. Decoder: each *closed* ring file is decoded with
   `tshark -r <file> -T ek -n` (streaming JSON lines). The newest ring file is
   never decoded while the source is alive (even when it is the only file), so
   an in-progress capture file cannot be consumed and silently retired early.
   This gives near-live packets with a latency of one chunk (~5s default) and
   flat memory usage. Timestamps are normalized from Wireshark 4.x ISO-8601 and
   millisecond EK forms. Payload contents are not stored in SQLite — sensitive
   values belong in the encrypted vault (M4), not the search index.
5. Queue discipline: bounded `queue.Queue(100_000)`; when full the decoder
   drops and increments `decode_drops`, which is displayed in the UI and the
   capture row. Drops are never silent. The writer exits only on the explicit
   end-of-stream sentinel sent after the decoder joins, so the final backlog is
   always persisted.
6. Live `packets_captured` comes from an incremental PcapNG block counter
   (`capture/pcapng.py`) because dumpcap reports its own counters only at exit;
   the final row prefers dumpcap's authoritative totals. Rotated ring files are
   retired by inode identity, so name reuse is counted as new packets.
7. Monitor thread enforces: emergency halt (stops within ~1s), scope duration
   limit (`max_capture_seconds`), unexpected source death, and byte counters.
   The stop path is lock-protected, joins decoder/writer, and writes a sha256
   manifest of every ring file.
8. Scope enforcement: interface allow/deny before start plus BPF filter derived
   from `allowed_cidrs`, `excluded_cidrs`, `allowed_ports`, `excluded_ports`,
   conjoined with an optional operator filter. Invalid scope refuses to start.
9. API: `POST /api/capture/start|stop|import`, `GET /api/capture/status`,
   `GET /api/captures[/{id}]`, `GET /api/packets`, `GET /api/flows`.
   Start/stop/import require `CONTROL_CAPTURE` (analyst/admin); profile C
   additionally requires `ENABLE_FULL_CAPTURE`; auditor is read-only.
10. CLI: `netherglass capture --interface ... --seconds ... [--bpf ...]` and
    `netherglass import <file>` for headless operation and field testing.
11. UI: interface selection → start/stop, live counters (captured, kernel
    drops, decode drops, queue depth, bytes), capture list, offline import by
    server path, and a packet/flow browser with proto/host/port filters and
    paging.

**Verified**: 104 tests (scope BPF, decode normalization incl. real tshark,
ring/lifecycle, open-file exclusion, writer drain, PcapNG counter incl. partial
tails and ring-name reuse, emergency halt, import hash/manifest, API permissions,
filters), plus live E2E import through the running server and live Wi-Fi
captures. Latest live run: 48 captured = 48 decoded = 48 stored rows, 0 kernel
drops, 0 decode drops, 6 ring files, 12 flows, sha256 manifest. Live capture
requires the operator's `wireshark` group membership (`dumpcap` is
`0750 root:wireshark`); the UI/CLI/doctor surface the exact command instead of
failing ambiguously.

## 6. M3 — Analysis: hosts, DNS, HTTP, TLS, search, statistics (implemented)

**Purpose**: turn decoded packets into network intelligence without weakening
the privacy rules: metadata is searchable, payload is not.

**Implementation** (modules `netherglass/analysis/`, `netherglass/store/analysis.py`):

1. `analysis/protocols.py` extracts per-packet intelligence from tshark EK
   fields and denormalizes it onto the `packets` row for fast filtering:
   `app_proto`, `encryption` (plaintext/encrypted/unknown), `stream`,
   `dns_qname/qtype/rcode`, `tls_sni/version`, `http_host/method/status`, plus
   `src_mac`/`dst_mac`. HTTP query **values** are dropped — only parameter
   names are kept; `Authorization` keeps only the scheme (`Bearer`), cookies
   keep only counts. The packet `info` string for HTTP also hides query values
   (`GET host/path?…`).
2. DNS: each query becomes a `dns_events` row; the matching response (same
   client/server/qname/qtype, earlier `matched = 0`) is correlated onto it
   (`matched = 1`, rcode, answers, CNAME chain, min TTL). Responses without a
   captured query are stored as `matched = 2` (honest orphan marker).
3. HTTP: requests and responses are stored as `http_events`; a response fills
   `status`, `content_type`, `server` on the request of the same TCP stream.
4. TLS: `tls_sessions` is one row per `(capture, stream)`, upserted from
   ClientHello (SNI, ALPN, JA3, JA4), ServerHello (negotiated version, cipher
   name) and Certificate (validity window) records. A second, targeted tshark
   pass (`-Y tls.handshake.type==11 -T fields`) extracts certificate SANs and
   name strings into the session and as `tls_cert_san` host names — EK flat
   fields cannot provide these. Subject/issuer are **not** guessed; the UI
   states that SANs/name hints are what is observable.
5. Hosts: every packet touches `hosts` with sent/recv counters, MAC and
   first/last timestamps; `host_names` records every discovered name with its
   source. A rank controls which name becomes the host's display hostname
   (dhcp > dns_answer > tls_cert_san > tls_sni > http_host > dns_query), so a
   weak hint never overwrites a strong one. `services` aggregates observed
   ports per host.
6. Search (`analysis/query.py`): a small query language —
   `field op value` combined with `AND`/`OR`/`NOT` and parentheses, ops
   `= == != > >= < <= ~ contains startswith endswith`. It is compiled to
   **parameterized** SQL over a fixed whitelist of fields; unknown fields list
   the available ones, and fields outside the packet index (`sensitive_data.*`,
   `finding.severity`) are rejected with a pointer to the FINDINGS/EVIDENCE
   tabs rather than silently returning nothing.
7. Statistics: top talkers/destinations/domains/ports/protocols, traffic and
   DNS volume over time, TLS version mix, encryption + security-quality mix,
   DNS summary (queries, NXDOMAIN, orphan responses), plus live findings and
   sensitive-artifact summaries (M4).
8. API: `GET /api/captures/{id}/hosts[/{ip}]`, `/dns`, `/http`, `/tls`,
   `/stats`, `GET /api/search`, `GET /api/search/fields` — all gated by
   `VIEW_NETWORK_METADATA`.
9. CLI: `netherglass hosts`, `netherglass stats`, `netherglass search "<q>"`
   (default: latest capture; `--json` for machines).
10. UI: the capture screen is now a workspace with tabs
    PACKETS | FLOWS | HOSTS | DNS | HTTP | TLS | STATS | SEARCH; the SEARCH tab
    has a graphical condition builder (field/op/value/AND-OR) that appends to
    the editable query text.
11. Evidence export (spec §5/§45, pulled forward from M8): raw captures can be
    exported as PCAPNG or PCAP via `GET /api/captures/{id}/export` — gated by
    `EXPORT_EVIDENCE`, refused during an emergency stop (423), refused while
    the capture is still running (409), and audited as `EVIDENCE_EXPORTED`.
    Ring files are merged/converted with `mergecap`; a temp file is streamed
    and deleted after the response. Each capture detail panel now states its
    **visibility level** (spec §4): profile A = metadata only, B/C =
    packet-level, unknown profiles are reported as undetermined.
12. Out-of-band emergency stop (spec §26): `netherglass panic --reason "..."`
    persists the stop and audits it without the web UI. The capture monitor
    now also polls the persisted stop flag every cycle, so a CLI panic halts
    a live capture even though the server process's in-memory event was never
    set. Recovery still requires `RECOVER_EMERGENCY_STOP` in the UI.

**Verified**: 134 tests (protocol extraction incl. redaction, query grammar
incl. parameterization/injection, DNS/HTTP/TLS correlation, hostname ranking,
stats, API permissions/search, export gating incl. auditor 403 / emergency
423 / running 409, CLI panic idempotency + audit redaction). Live E2E: a 4-file Wi-Fi ring capture
generating DNS + HTTP + TLS traffic was imported through the CLI — 563
captured = 563 decoded = 563 stored, 0 decode drops; DNS query/response pairs
correlated, HTTP GET request/response filled, TLS sessions merged, and the
certificate pass recovered the Wikipedia SAN set into the TLS session and host
names; searches were verified through both the CLI and the HTTP API.

## 7. M4 — Detection engine, sensitive-data engine, findings, evidence vault (implemented)

**Purpose**: classify *what was observed* with calibrated confidence, seal any
sensitive values that were genuinely visible in cleartext, and produce findings
that cite the exact evidence behind them.

**Implementation**:

1. Security-quality axis (spec §10): every packet and TLS session now carries a
   `security` grade — GOOD / WEAK / INSECURE / UNKNOWN
   (`analysis/protocols.py::classify_security`). Encrypted traffic with an
   obsolete version or weak cipher is WEAK/INSECURE; plaintext data protocols
   (HTTP, FTP, Telnet, SMTP/IMAP/POP3 without TLS, ...) are INSECURE;
   infrastructure protocols that are plaintext by design (DNS, DHCP, NTP, ARP)
   are UNKNOWN here — whether they *matter* is a detection-rule question, not a
   blanket grade.
2. Sensitive-data detection (`analysis/sensitive.py`) runs at decode time on
   the in-memory EK fields: HTTP `Authorization` (Basic decoded,
   Bearer/other schemes classified), request cookies, the first `Set-Cookie`
   pair with its attributes (Secure/HttpOnly/SameSite), URL query parameter
   **names** that mark session/token carriers, urlencoded form fields
   (`password` → PASSWORD, `email`/`user` → PERSONAL_INFORMATION), and FTP
   USER/PASS commands. Values are refined against default patterns (JWT, AWS
   access key, GitHub/Slack/Stripe tokens, private keys) plus operator-defined
   `custom_patterns` in `<data_dir>/rules.json`. Caps: 512-byte values,
   32 candidates per packet, 8 cookie pairs; duplicates (type+value) collapse.
3. Evidence vault (`store/evidence.py`): every candidate becomes an `evidence`
   row with full context (flow, host/path, stream, frame, transport security,
   confidence). Under profile A (`store_sensitive_values=false`) rows are
   `METADATA_ONLY` — the value is discarded. Otherwise the value is sealed
   immediately with AES-256-GCM into `evidence/EVD-xxxxxx.ngv` (AAD = evidence
   ID) and the row records sha256 + size; status `SEALED`. Engine-level
   de-duplication keeps one row per (type, field, stream, value) per capture.
   There is deliberately **no code path that returns a value except reveal**.
4. Reveal workflow (spec §21): `POST /api/evidence/{id}/reveal` requires
   `VIEW_SENSITIVE_VALUES`, a valid CSRF token and a stated reason (≥4 chars);
   it is refused during an emergency stop (423); it unseals in memory, returns
   the value with a 30-second client-side auto-hide hint, and writes a
   `REVEAL_SENSITIVE_VALUE` audit event (actor, evidence id, capture, reason)
   before returning. Metadata listing (`GET .../evidence`) needs only
   `VIEW_SENSITIVE_METADATA` and never contains values.
5. Detection rules (`analysis/rules.py`): 15 rules over stored metadata only —
   plaintext_credentials, weak_tls, cleartext_protocols, session_token_in_url,
   authorization_in_cleartext, unexpected_dns_server, suspicious_dns,
   dns_tunneling_indicator, unexpected_external_service, port_scan_indicator,
   unusual_traffic_volume, possible_exfiltration, possible_tunneling,
   authentication_anomaly, certificate_validity. Each emits severity +
   confidence from the mandated vocabulary and an explanation naming the
   observation it rests on (rules never read secret values — only artifact
   metadata). `rules.json` can disable rules or override their severity.
6. Findings (`store/findings.py`): analysis runs automatically when a capture
   finishes (live stop or import) and on demand via
   `POST /api/captures/{id}/analyze`; each run rebuilds the capture's findings
   atomically and audits `ANALYSIS_COMPLETED`. Findings carry title,
   description, explanation, mandatory remediation text, asset/flow, evidence
   IDs and packet refs. `GET /api/captures/{id}/findings` and
   `GET /api/findings/{id}` are gated by `VIEW_FINDINGS`; stats now return
   real findings + sensitive summaries (sensitive summary hidden from roles
   without `VIEW_SENSITIVE_METADATA`).
7. UI: new FINDINGS tab (severity/confidence filters, re-run analysis,
   expandable rows with explanation + remediation + evidence refs) and
   EVIDENCE tab (metadata table, type filter, reveal-on-reason workflow with
   countdown + HIDE NOW; reveal buttons disabled without the value permission).
   The PACKETS tab shows the security grade per packet; STATS gained the
   security-quality mix and live findings/sensitive summaries.

**Verified**: 148 tests. E2E with a synthetic cleartext HTTP session (Basic
auth + session cookie + `?token=` query): decode detected BASIC_AUTH,
SESSION_COOKIE and ACCESS_TOKEN artifacts; findings listed
plaintext_credentials (CRITICAL), authorization_in_cleartext (HIGH) and
session_token_in_url (POSSIBLE); secret values appeared **neither in SQLite
nor as plaintext in the .ngv blob**, and reveal returned the decoded
`alice:s3cr3t` while writing the audit event and 30s auto-hide hint.

## 8. M5 — Web security, investigation workflow, reporting (implemented)

1. Web metadata (spec §27–32): `extract_http` now captures request/response
   kind, status, cache-control, security headers (HSTS/CSP/XCTO/XFO/
   Referrer-Policy/Permissions-Policy), `Set-Cookie` attributes (Secure,
   HttpOnly, SameSite, Domain, Path, Max-Age) and request cookie names —
   **never values**. Multi-valued EK fields (`http_http_response_line`,
   `http_http_set_cookie`, `http_http_cookie`) are preserved as lists by
   `capture/decode._flatten` so all cookies/headers survive normalization.
2. `store/websec.py`: per-capture web app inventory (host ↔ IPs ↔ DNS names ↔
   TLS metadata ↔ endpoints ↔ auth schemes ↔ cookies ↔ findings), cookie
   upserts (MAX-merge for Secure/HttpOnly), token fingerprints only — tokens
   are HMAC-SHA256 keyed with `keys/fingerprint.key` (0600), never stored raw;
   JWT claims (alg/kid/iss/sub/aud/exp/iat/scope) recorded as metadata with
   `jwt_metadata`; data-flow attribution maps artifacts to destinations with a
   transport-risk grade; all of it exposed through `/api/captures/{id}/web/*`
   (tokens/flows need `VIEW_SENSITIVE_METADATA`, auditor excluded).
3. Investigation workflow (spec §33–34): timeline merges DNS/TLS/HTTP/
   findings/evidence/audit events with server-side permission filtering;
   cases (`CS-000001`) group findings/evidence/hosts/domains/notes with
   admin/analyst-only mutations; graph endpoints produce network and
   connection graphs; every mutation is audited.
4. Reporting (spec §39–41): `analysis/report.py` renders standard (masked)
   and restricted (decrypts sealed values, `EXPORT_SENSITIVE_EVIDENCE`, admin
   only, audited `REPORT_EXPORTED`) HTML/JSON reports with
   `Content-Disposition` attachment and honest notes (no PDF/CSV engine yet;
   disabled actions surface as absent features, never fake output).
5. New rules: cookie_attributes, cookie_over_plaintext,
   missing_security_headers, token_boundary, long_lived_token, http_not_https,
   sensitive_to_external.
6. UI: WEB tab (apps/cookies/headers/tokens/flows), TIMELINE (filters), GRAPH
   (network vs connection mode), CASES (open/add/close, role-aware), report
   download buttons in the capture header.

**Verified**: 163 tests including `test_m5_websec.py`; real-tshark E2E with a
request + complete response (Set-Cookie ×2, Cache-Control, Content-Length):
web tables populated from the packet path, restricted report decrypts, standard
report masks, audit chain records the export.

## 9. M6 — Tunnels, cloud flow logs, Kubernetes (implemented)

1. Tunnel visibility (spec §14): `protocols.detect_tunnel` classifies IPsec
   (IKE 500/4500 → HANDSHAKE; ESP/AH → DATA; NAT-T non-ESP-marked payloads
   follow tshark's ESP classification), WireGuard (51820), OpenVPN (1194),
   GRE, IP-in-IP, IPComp and VXLAN from the protocol chain, dissector names
   and ports. `tunnels` rows aggregate per direction/protocol/endpoints with
   packets/bytes/first/last/duration/state and an explicit `inner_visible`
   flag: 0 for encrypted tunnels (inner traffic is **never assumed visible**),
   1 only for plain encapsulations. Rule `unencrypted_tunnel` flags GRE/
   IP-in-IP/VXLAN; `possible_tunneling` also matches IKE/WireGuard/OpenVPN by
   dissected name or standard port. UI: TUNNELS tab.
2. Cloud flow-log adapters (spec §42): `netherglass/ingest/flowlogs.py` parses
   AWS VPC flow logs (default field order), Azure NSG flow-log JSON
   (flowTuples v2), GCP VPC flow JSON (jsonPayload.connection + counters on
   the entry) and generic CSV/JSON with flexible column names. Imports create
   a capture with source `cloud-flowlog`, profile A, **no packet rows and no
   evidence pipeline** — flows, hosts and services are aggregated directly
   from the records. Audited `FLOWLOG_IMPORTED`; refused during emergency
   stop (423); requires `CONTROL_CAPTURE`.
3. Kubernetes (spec §43): `netherglass/ingest/k8s.py` accepts raw `kubectl get
   … -o json` outputs (nodes/pods/services/namespaces), normalizes them into
   `k8s_entities` (labels, container ports, service selectors) and correlates
   pod IPs against observed flows: Pod → Service (selector matching) → Pod IP
   → Node → Destination. Correlation is observational; pod-IP reuse is called
   out in the UI copy. Audited `K8S_IMPORTED`; requires `CONTROL_CAPTURE`.
4. UI: TUNNELS tab, K8S tab (import inventory, correlation table, entity
   list), flow-log import form in the capture panel.

**Verified**: 175 tests including `test_m6_integrations.py`; real-tshark E2E
with IKE/ESP(4500)/WireGuard/GRE/VXLAN frames: six tunnel rows with correct
states, `unencrypted_tunnel` + `possible_tunneling` findings, AWS flow-log
import and K8s correlation against the decoded capture.

## 10. M7 — Controlled testing subsystem (implemented)

1. Separate subsystem (spec §50/§52/§66): `netherglass/testing_scope.py` +
   `netherglass/testing_runner.py` + `api/routes_testing.py`. It never touches
   the capture pipeline; results live in `controlled_tests` /
   `controlled_test_results`.
2. Fail-closed scope (spec §48/§49/§55): operator maintains
   `<data_dir>/testing_scope.json` (assessments with authorization_ref,
   domains, CIDRs, excluded CIDRs, ports, testing window). No file → every
   creation is refused (`409`); target matching re-runs **at execution time**
   (domains exact-or-subdomain, CIDR match, exclusions win, window enforced).
   Invalid config refuses rather than guessing.
3. Test types: `TCP_CONNECT`, `TLS_HANDSHAKE` (metadata only),
   `HTTP_PROBE` (HEAD, records status + security headers), and
   `SESSION_COOKIE_CHECK` / `BEARER_TOKEN_CHECK` which use one sealed
   evidence value: it is unsealed in memory only, sent once, and **never**
   written to results/audit/logs — results reference the evidence ID only
   (spec §51/§53). Never automatic: replay exists only as this explicit,
   separately-permissioned module.
4. Bounds (spec §52/§55): max_requests ≤ 50, rate limit ≥ 100 ms (default
   1 s), per-request timeout, 5-minute wall-clock cap, abort flag checked
   between requests, dry-run default (preview without traffic). Emergency
   Security Stop refuses new executions (423) and aborts running tests.
5. Permissions: viewing = VIEW_FINDINGS; planning = CREATE_CONTROLLED_TEST
   (analyst+); executing/aborting = EXECUTE_CONTROLLED_TEST (admin only) plus
   CSRF and the exact confirmation phrase `AUTHORIZE TEST`. Every
   create/execute/abort writes an audit event; refusals are recorded on the
   test row and in results.
6. UI: CONTROLLED TESTING panel on the dashboard (scope table with
   active/inactive assessments, plan form, authorize-with-phrase dialog,
   abort button, results drill-down).

**Verified**: 13 new tests with a real loopback HTTP server: dry-run sends no
traffic; live probes respect max_requests/rate; cookie-check delivers the
sealed secret to the server while SQLite + audit text contain no trace of it;
emergency stop refuses execution; abort stops a slow run; scope exhaustion
(no file, bad file, expired window, excluded CIDR, wrong port) refuses.

## 11. M8 — Hardening (implemented)

1. **Fuzzing** (spec §67): malformed EK trees, protocol extractors, sensitive
   collector, flow-log parsers, K8s inventory, detect_format. Two real crashes
   were found and fixed (Azure NSG and GCP entries with non-dict members were
   AttributeErrors; both now refuse cleanly or skip bad members).
2. **Malformed traffic**: truncated Ethernet/IP frames, lying IP lengths, and
   zeroed frames import without crashing; decodable packets still land.
3. **Volume/storage bounds**: 1500-frame import asserts exact packet counts;
   `scope.storage_limit_bytes` is now enforced — imports are refused (507)
   before copying and live captures finalize with a storage-limit reason when
   the data dir crosses the limit (checked at most every 5 s).
4. **Emergency interactions**: import refused under emergency (423); evidence
   deletion refused (423); active testing refused (423, M7).
5. **API security**: security headers asserted; cross-origin POST rejected;
   unauthenticated sweep returns 401; role matrix asserts auditor/analyst
   denials (capture control, evidence metadata/reveal/delete, emergency
   recovery).
6. **Evidence integrity**: tampered blobs (bit flipped) surface as a clean
   410 "integrity check failed" instead of a raw crypto exception (vault now
   translates `InvalidTag`).
7. **Secure deletion** (spec §44/§67): `DELETE /api/evidence/{id}` (admin,
   CSRF, reason required, audited `EVIDENCE_DELETED`) zero-overwrites the blob,
   fsyncs, unlinks it, and keeps a DELETED tombstone row; reveal afterwards is
   refused. Limitation: not a forensic guarantee on CoW/journaling filesystems
   (documented).
8. **Secret-echo defense**: controlled tests summarize chosen response
   headers; a hostile target could echo the sent credential back into one of
   them. The runner now redacts the secret and the exact derived header value
   from stored details; a regression test with an echoing server proves no
   trace reaches SQLite.
9. **Dry runs are now truly traffic-free**: the runner no longer performs DNS
   resolution in dry-run mode (previously a dry-run of an unresolvable host
   failed AND a DNS query was sent). Literal-IP targets now match CIDR scope
   directly (no resolution needed); hostname targets authorized only via CIDR
   cannot be dry-run (fail closed, documented).
10. Static hygiene: `preexec_fn=os.setsid` replaced with the thread-safe
    `start_new_session=True`; dead code and unused imports removed.

**Verified**: 19 new tests (206→207 incl. storage guards, fuzz corpus, echo
defense, permission matrix, delete workflow, tamper detection, dry-run
traffic-free) plus a live-server smoke script (`/tmp/opencode/m8_smoke.py`)
covering headers, scope fail-closed, plan/execute dry-run, out-of-scope
refusal, delete 404, and emergency refusal + recovery.

## 12. Honest limitations register

| Limitation | Shown in UI? |
|---|---|
| Wi-Fi managed mode sees only this host + broadcast/multicast | yes (interface table note) |
| Live packets appear after the current ring chunk closes (~5s) | yes (capture panel note) |
| Encrypted protocols: SNI/cert SANs/JA3/JA4 only, payloads never decrypted | yes (TLS view note) |
| Certificate subject/issuer not shown — EK flat fields cannot provide them; SANs + name hints only | yes (TLS view note) |
| HTTP query values, cookies and Authorization values are never stored | yes (HTTP view note) |
| DNS answers without a captured query are marked "orphan resp" | yes (DNS view column) |
| dumpcap/tshark absent → live capture unavailable until operator installs | yes (readiness panel + hint) |
| dumpcap installed but user not in `wireshark` group → live capture refused | yes (readiness + exact command) |
| No CAP_NET_RAW → tcpdump/scapy fallbacks unavailable | yes (readiness detail) |
| System DNS servers may bypass capture point | documented; automatic detection not implemented yet |
| Flow-log/cloud sources provide metadata only | yes (capture panel + report note) |
| Tunnels: inner traffic never assumed visible; encrypted = opaque by definition | yes (TUNNELS view `INNER` column) |
| Kubernetes correlation is IP-based; pod-IP reuse can mis-attribute | yes (K8S view note) |
| Flow-log imports create no packets/evidence (metadata-only capture) | yes (source column + profile A) |
| Reports: HTML/JSON only (no PDF/CSV engine yet) | yes (endpoint accepts only these formats) |
| Controlled tests support only TCP/TLS/HTTP(S) probes; no exploitation, no crawling | yes (TEST_TYPES list is closed) |
| Controlled-test HTTP uses the target host; TLS verification accepts any cert (probe context) | documented here; result records cert notAfter only |
| Secure deletion is best-effort (zero-overwrite + unlink); CoW/journaling filesystems may retain blocks | documented here and in the DELETE endpoint docstring |
| Login rate limiter is in-memory (resets on restart; single-process assumption) | documented here; audit log still records every attempt |
| Shutdown of tshark children relies on process groups; zombie children under extreme kill scenarios possible | bounded by one capture at a time |

## 13. Deployment topology

Single host on a trusted internal network, bound to LAN if remote use is
required. TLS via reverse proxy recommended. Never internet-facing. The audit
chain, RBAC and vault make an internal-host compromise detectable and bounded,
but the host itself must follow normal hardening (disk encryption, patched OS,
limited SSH).
