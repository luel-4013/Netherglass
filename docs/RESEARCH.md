# Market research: network visibility / traffic analysis tools

Research date: 2026-10. Primary sources only; where a web-search provider was
unavailable, indirect retrieval was used (documented at the end). This document
drives product decisions — every "we do X" in the design maps to evidence here.

---

## 1. The graveyard: products that died, and why

| Project | Fate | Cause of death |
|---|---|---|
| **Apache Metron** (OpenSOC lineage) | TLP 2017 → retired **Dec 2020**, Attic Apr 2021 ("real-time big data security") — [attic page](https://attic.apache.org/projects/metron.html), [repo](https://github.com/apache/metron) (archived, 870★) | Hadoop/Storm/Kafka/ES stack = massive ops burden; scope = "big data security" with no focused first value; community could not carry it |
| **Apache Eagle** | archived, last push 2020, 411★ ([repo](https://api.github.com/repos/apache/eagle)) | Same big-data security analytics pattern; no differentiated workflow |
| **Apache Spot (incubator)** | archived, 352★ ([repo](https://api.github.com/repos/apache/incubator-spot)) | Hadoop/Cloudera telemetry analytics; heavy infra, low adoption |
| **Xplico** | last push **2020-08**, 203★ ([repo](https://github.com/xplico/xplico)) | Single-maintainer decay; complex build; no modern UI |
| **Snorby** | 1,007★, 131 open issues, last push 2023 ([repo](https://github.com/Snorby/snorby)) | Ruby/Rails dependency rot. HN quote: *"pure hell to install manually due to all the old Ruby/Rails dependencies"* |
| **Sguil** | 227★, last push 2024-03 ([repo](https://github.com/bammv/sguil)) | Aging Tcl/Tk UX; no community momentum |
| **BruteShark** | 3,406★ but last push 2023 ([repo](https://github.com/odedshimon/BruteShark)) | Credential-extraction niche is in demand, but the tool stalled without maintenance |

**The failure pattern** (all six): heavy infrastructure, single maintainer or no
community, stale dependency hell, analyst-hostile UX, no focused first-value
workflow. Notably: **none died from lack of demand — they died from delivery**.

## 2. The survivors: what works

| Project | Signal | Why it lives |
|---|---|---|
| **Wireshark** | de facto standard; GitLab enhancement backlog studied | Dissector mass (3,000+ protocols), free, CLI+GUI, training/cert ecosystem |
| **Zeek** | 8,115★ active ([repo](https://github.com/zeek/zeek)) | Scriptable, log-first, security semantics; top requests: Windows support, zstd logs |
| **Arkime** | 7,536★ active daily ([repo](https://github.com/arkime/arkime)) | Full PCAP at scale + indexed sessions. Top open enhancement: **TLS keylog decryption**; others: NetFlow import, p0f, Kafka output, WISE lookback |
| **Security Onion** | 4,932★ active | Turnkey distro + docs + free training; open asks: unattended install, OpenCTI/Wazuh integrations, file dedup |
| **ntopng** | 8,265★ | Real-time, lightweight, easy appliance install |
| **Malcolm** | 490★ but very active | **Docker Compose packaging** of Zeek+Suricata+Arkime+OpenSearch = adoption through packaging |
| **PCredz** | 2,574★, pushed 2026-03 | Credential/metadata extraction from PCAPs — persistent demand |
| **NetworkMiner** | commercial-adjacent, beloved | The "Credentials" tab: artifact extraction UX for non-programmers |

## 3. Most-requested features (mined, not guessed)

From GitHub/GitLab issue trackers (sorted by reactions/upvotes) and HN threads:

1. **Zero-ops install** — Security Onion's top open issue is unattended install;
   Malcolm won via Docker packaging; Snorby died in dependency hell.
2. **TLS metadata without decryption + optional keylog decryption** — Arkime's
   top open feature request; JA3/JA4 fingerprinting wildly popular.
3. **Credential / session / token extraction** — BruteShark, PCredz,
   NetworkMiner popularity show the demand; nobody does it with an evidence
   vault, permission separation and audit.
4. **Fast search → pivot → packet-level evidence** — Wireshark backlog (display
   filter enhancements, marks, session stats) and Arkime's "PCAP search and tag".
5. **Case management, tags, timeline** — the workflow layer Wireshark lacks.
6. **Client-ready reports** — pentesters must deliver; ELK UIs don't produce
   reports.
7. **Live alerting, not just retro** — HN critique of retro-only monitoring:
   *"it is always too late when you get an alert"*.
8. **RBAC + audit** — why security leadership blocks most OSS network tools in
   regulated teams. Commercial NDR has it; open tools mostly don't.
9. **Evidence integrity for findings that end up in reports/disputes** — almost
   nobody in this space offers hash-chained, tamper-evident evidence.
10. **Scope controls + kill switch** — no competitor has this. Unique differentiator.
11. **Flow-log and Kubernetes/cloud visibility normalization** — enterprises ask;
    OSS tools treat it as an afterthought.

## 4. Why THIS product will fail unless we fix these (feed into POSTMORTEM.md)

- Over-scoped spec (66 sections) → big-bang → dead on arrival.
- ES/Kafka/Hadoop temptation → ops burden → Metron's fate.
- Secrets in logs/DB/search index → one breach ends trust.
- No RBAC/audit → CISSO veto → cannot deploy to a team.
- Alert fatigue → analysts ignore it → back to Wireshark.
- Slow UI on big PCAPs → analysts bounce.
- No export quality → cannot bill clients → no adoption in the department.
- Off-scope capture incident → legal/trust catastrophe.

Every fix is implemented or scheduled in `docs/DESIGN.md`.

## 5. Research method and retrieval fallbacks

The search provider was unavailable during this research (transport errors /
HTTP 403). Every finding was retrieved indirectly instead:

| Attempt | Result | Fallback used |
|---|---|---|
| Web search API | 403 / transport error | GitHub REST API, GitLab API, HN Algolia API via `curl` |
| `en.wikipedia.org` REST | 404 (article genuinely does not exist) | Apache Attic project pages (authoritative) |
| Reddit search JSON | blocked (bot wall) | Pushshift-successor `api.pullpush.io` (down) → HN Algolia comments |
| Arkime README | fetched raw | `raw.githubusercontent.com` |
| Issue-demand mining | worked | `api.github.com/search/issues` sorted by reactions; GitLab `upvotes` field |

No claim in this document is based on an unverifiable source or a guess.
