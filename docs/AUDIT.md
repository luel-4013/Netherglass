# Netherglass — Hardening Audit (M8)

Date: 2026-10-19 · Scope: all code in `netherglass/`, `web/src/`, tests ·
Method: static analysis (ruff), full-suite stress (3 consecutive runs), live
server smoke, adversarial fuzzing of every parser, targeted review of the
high-risk paths (auth, scope, vault, controlled tests, ingest, export).

## 1. Summary

| Class | Count |
|---|---|
| Defects found and fixed in this milestone | 10 |
| Findings reviewed and accepted (no change) | 7 |
| Residual risks / deliberately unimplemented | 8 |

No open high-severity findings remain. Evidence of verification: **207 tests
pass (×3 consecutive runs)**, live smoke script `/tmp/opencode/m8_smoke.py`
passes against a real server, and every parser survives a junk-input corpus.

## 2. Defects found and fixed

### F1 — Azure NSG flow-log parser crashed on malformed members (High)
`_parse_azure` assumed `records[*].properties.flows[*].flows[*].flowTuples`
were always dicts/lists of the expected shape. A crafted or corrupt file
(`{"records": "x"}`, `records: ["str"]`, `flowTuples: [7]`) raised
`AttributeError`, surfacing as an unhandled 500 on `POST
/api/integrations/flowlogs`.
Fixed in `netherglass/ingest/flowlogs.py`: wrong top-level shape → clean
`FlowlogError`; non-dict members are skipped. Regression corpus in
`tests/test_m8_hardening.py::test_fuzz_flowlog_parsers_raise_clean_errors`.

### F2 — GCP flow-log parser crashed on non-dict entries (High)
`_parse_gcp` called `entry.get(...)` on every element of `entries`. A JSON
array containing strings/numbers raised `AttributeError` → 500.
Fixed: non-dict entries are skipped. Same regression corpus as F1.

### F3 — Tampered evidence blobs leaked a raw crypto exception (Medium)
`vault.open_evidence` let `cryptography.exceptions.InvalidTag` propagate.
A flipped byte in an `.ngv` blob produced an unhandled 500 with a traceback
instead of a controlled denial.
Fixed: `open_evidence` translates `InvalidTag` into
`ValueError("evidence integrity check failed …")`, which `reveal_value`
already maps to a clean `410`. Test:
`test_evidence_tamper_detected` (bit-flip, expects `EvidenceError`).

### F4 — Controlled-test results could persist an echoed credential (High)
Artifact tests (`SESSION_COOKIE_CHECK`, `BEARER_TOKEN_CHECK`) send a sealed
secret and store a summary of selected response headers. A hostile or debug
target that echoes the request credential into `Set-Cookie` (or any
summarized header) would have written the secret into SQLite, outside the
vault — a direct violation of the "value never stored" contract.
Fixed in `testing_runner.py::_one_request`: the secret and the exact derived
header value are redacted from the detail before storage. Regression test
runs a real echoing HTTP server and asserts `[redacted]` appears and the
secret bytes are absent from the database file
(`test_controlled_test_scrubs_echoed_secret`).

### F5 — Dry runs performed DNS lookups and failed for unresolvable hosts (Medium)
The runner resolved the target before scope re-checking even in dry-run
mode. Two consequences: (a) a "no traffic" dry run still sent a DNS query;
(b) a dry run of a valid but currently unresolvable hostname failed as
`DNS resolution failed` instead of returning a preview.
Fixed: dry runs skip resolution entirely; literal-IP targets now match CIDR
scope directly (in `testing_scope.match_target`), so IP dry runs still work.
Hostnames authorized only via CIDR cannot be dry-run (fail closed) — this is
the honest trade-off and is documented. Tests:
`test_dry_run_is_traffic_free_even_without_dns`, plus the M7 dry/live test.

### F6 — `storage_limit_bytes` declared but never enforced (Medium)
`CaptureScope.storage_limit_bytes` (default 20 GiB) existed since M2 but
nothing read it; a runaway capture or import could fill the disk.
Fixed in `capture/engine.py`: imports are refused up front (HTTP 507 via
`CaptureError.code`), and the live-capture monitor finalizes the capture with
a `"storage limit reached (N bytes)"` reason. Usage scan is cached (≥5 s
between walks) to bound the cost. Test:
`test_storage_pressure_boundaries`.

### F7 — `preexec_fn=os.setsid` with threads (Low)
Both capture-source spawn sites used `preexec_fn`, documented as unsafe when
threads exist (and this process is threaded) because it runs Python in the
post-fork child before `exec`.
Fixed: `start_new_session=True`, which achieves the same new-process-group
semantics in the C layer. `netherglass/capture/sources.py:94,227`.

### F8 — No secure-deletion path for sensitive evidence (Low / spec gap)
Spec §44/§67 require secure deletion and evidence locking; retention
conflicts had no remediation short of editing the database by hand.
Added: `DELETE /api/evidence/{id}` — admin-only (`DELETE_EVIDENCE`), CSRF,
mandatory reason (≥4 chars), refused during Emergency Security Stop (423),
zero-overwrites the blob, fsyncs, unlinks it, keeps a `DELETED` tombstone row
for chain of custody, writes `EVIDENCE_DELETED` to the audit log, and makes
subsequent reveals fail (409). UI: `[ DELETE ]` with a confirm row in
`EvidenceView.tsx`. Tests: `test_evidence_delete_workflow`,
`test_evidence_delete_refused_under_emergency`.

### F9 — Dead code and unused imports (Low)
`flowlogs._parse_generic_csv` built an unused `header_map`; unused imports in
`analysis/protocols.py`, `store/cases.py`, `store/websec.py`; unused test
variables. Removed; pyflakes-class lint is now clean for source modules.

### F10 — Flaky test helper raced the transient `PLANNED` state (Low)
`_wait_status` in the M7/M8 tests treated "not EXECUTING" as terminal, but
`execute()` starts a thread that briefly leaves the row in `PLANNED`. Under
load the helper returned `PLANNED` and assertions failed intermittently.
Fixed: helpers now wait for a state that is neither `PLANNED` nor
`EXECUTING`; 3 consecutive full-suite runs are green.

## 3. Findings reviewed and accepted (no change)

| # | Finding | Assessment |
|---|---|---|
| A1 | Blind `except Exception` in 5 locations (engine analysis thread, test runner, CLI, logging setup) | Deliberate fail-safe: none of these may abort a capture/request thread; every one logs or records the failure. Reviewed individually. |
| A2 | `Depends(...)` in FastAPI defaults (ruff B008, ×79) | Required FastAPI idiom; not a defect. |
| A3 | Session cookie lacks `Secure` until `behind_tls=True` | Device is bound to loopback; TLS is a deployment decision. HttpOnly + SameSite=strict always set; documented. |
| A4 | Login rate limiter is in-memory | Accepted for single-process loopback deployment; every attempt is still audit-logged; documented limitation. |
| A5 | TLS verification disabled in controlled-test probes | That is the probe's purpose (observe version/cipher/cert dates); no secrets are sent by `TLS_HANDSHAKE`, and cert verification would block the observation. Documented. |
| A6 | Best-effort secure deletion | Overwrite+fsync+unlink is honest but not a forensic guarantee on CoW/journaling filesystems; documented in the endpoint docstring and limitations register. |
| A7 | SQL construction | Spot-checked every dynamic statement: values are always bound parameters; the only interpolation is static column lists. No injection found. |

## 4. Residual risks (known, not implemented)

1. **No SIEM/alerting export yet** — findings live in the UI/reports only
   (spec places syslog/OpenSearch export in a later phase). This is the
   single largest operational gap.
2. **Single-process / SQLite writer** — no clustered deployment; WAL keeps
   readers fine, but one host is the ceiling.
3. **tshark dependency drift** — EK field names can change between Wireshark
   releases; decode is defensive but a field rename silently degrades
   extraction until tests are updated.
4. **Storage scan cost** — `rglob` walk scales with file count; cached 5 s,
   acceptable for single-host volumes, would need inode accounting at scale.
5. **Unseal is in-memory** — reveal/test artifact loads the whole plaintext
   value into process memory; sizes are naturally small (credentials), but
   not size-capped explicitly.
6. **Reports are HTML/JSON only** — no PDF/CSV engine.
7. **No user-management API** — accounts are CLI-only by choice (smaller
   attack surface).
8. **Emergency stop affects exhibits** — exports/reveals/deletes are blocked
   during a stop by design; recovery is explicit and audited. Operators must
   know this before a drill.

## 5. Verification evidence

- `pytest tests/` → **207 passed** (three consecutive runs), including
  19 M8 hardening tests.
- Fuzz corpus: malformed EK trees, protocol extractors, sensitive collector,
  flow-log parsers (11 bad inputs), K8s inventory, detect_format.
- Malformed pcap: truncated Ethernet/IP frames, lying IP length, zeroed
  frames — import completes `ready` with decodable packets preserved.
- Volume: 1500-frame import, exact count, zero decode drops, bounded time.
- Live smoke: security headers, scope fail-closed, plan→dry-run execute,
  out-of-scope refusal (domain + window + port), delete 404 path, emergency
  execute refusal (423), recovery. Full pass.
