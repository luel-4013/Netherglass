# Security policy and deployment rules

## Scope of use

NETHERGLASS is an **internal-use** network visibility and evidence platform for
authorized security assessment, monitoring and investigation only. It must
**never** be exposed to the public internet. If remote access is required, it is
for trusted internal networks only, behind TLS, with named accounts.

## Reporting a vulnerability

For public/source use: open a **private security advisory** on the GitHub
repository (Security → Advisories → Report a vulnerability) or contact the
maintainer directly. For internal deployments: use your organization's
security channel.

Include: version (`netherglass --version`), reproduction steps, impact.
Do not include real captured secrets in reports; reference evidence IDs.

## Hard deployment rules

1. **Never port-forward, never public DNS, never cloud-load-balancer exposure.**
   If it is reachable from the internet, deployment is wrong.
2. Bind default is `127.0.0.1`. LAN binding (`--host 0.0.0.0`) prints a warning
   and is intended for your internal network only.
3. Put TLS in front (reverse proxy) on any shared network; then start with
   `behind_tls: true` in `config.json` so session cookies get `Secure`.
4. Change the bootstrap admin password immediately; delete
   `BOOTSTRAP_CREDENTIALS.txt`.
5. One account per analyst. No shared logins — the audit trail is the point.
6. Disk encryption on the host. The vault key protects evidence blobs, not the
   whole operating system.
7. Back up `netherglass.db` + `keys/` + evidence together, all protected; a
   backup without the key is deliberately useless, a backup with the key is
   evidence — treat it as sensitive material.
8. Run `netherglass user list` periodically; disable accounts that left the team.
9. Emergency Security Stop is reachable from the dashboard top bar at all times.
   Test recovery quarterly.

## Threat model (condensed)

| Threat | Mitigation |
|---|---|
| Stolen analyst credential | argon2id, login rate limit, session expiry, full audit trail |
| Compromised monitoring host | vault encryption at rest, permission separation, emergency stop, audit chain |
| Evidence tampering | encrypted blobs + audit hash chain (tamper-evident) |
| Sensitive-value leakage via logs/API | mandatory redaction filter; values only via authorized reveal (M4); no secrets in audit records |
| Off-scope capture | scope config + BPF filter enforcement (M2) + visible scope banner + panic switch |
| Unauthorized active testing | controlled-testing module is a separate subsystem with separate permissions and its own audit (M7) |
| Insider misuse of captured credentials | analyst role cannot reveal sensitive values, export sensitive evidence or execute controlled tests — by design, not by policy alone |

## What this product will never do

- Replay credentials, cookies, sessions or tokens automatically
- Exploit, stuff, hijack or persist automatically
- Claim "unhackable" outcomes or absolute security; findings carry confidence
  levels and evidence references only
- Hide drops, gaps or visibility limitations
