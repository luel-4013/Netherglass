# Netherglass — Six-Month Failure Post-Mortem

**Scenario assumed by this document:** Netherglass was provided to a mid-size
internal network team, worked as designed for several months, and was
effectively abandoned by month six. This post-mortem reconstructs the most
plausible failure path given what was actually built, and records what would
have had to be true for it to survive. Nothing below indicates the software
was broken — the failure was adoption, operations and organization.

## 1. Executive summary

Netherglass failed as a product, not as an engineering artifact. It shipped a
deep, correct pipeline (capture → decode → detection → sealed evidence →
audited reveal → controlled testing) with hardening and an honest limitations
register. But at six months it had **no consumers**: findings never reached
the tools analysts already watched, the one workflow it did better than the
incumbents (plaintext-credential evidence with audited reveal) required an
authorization culture the team did not have, and its operator burden (tshark
version, disk limits, key custody, scope JSON) fell on a single champion who
left. The platform became a museum of good intentions: accurate, audited, and
unopened.

## 2. Timeline (reconstructed)

- **Month 0 — Pilot install.** Two hosts, one analyst, one champion (the
  requester). Import of PCAPs works, vault reveal demonstrated in a meeting.
  Enthusiasm: "this is the visibility we never had."
- **Month 1 — First real use.** Live capture during an incident. Findings
  exported as HTML and attached to a ticket. Everyone agrees the timeline and
  cases views are "nice." Nobody integrates anything.
- **Month 2 — First friction.** `tshark` upgraded by the distro; one EK
  field renamed; HTTP extraction degrades on the new capture host while
  reports keep generating without complaint. Two days lost. The workaround is
  "pin tshark" — and a sticky note.
- **Month 3 — Disk incident.** A long capture plus two large imports cross
  the storage limit (the new enforcement stops the third import). The
  operator experiences the guard as the outage ("the tool refused to work
  during a busy morning") rather than as the protection, because retention
  policy was never agreed with the data owners.
- **Month 4 — Legal review stalls.** Evidence retention and the controlled
  testing module are reviewed by legal. Without a data-owner retention policy
  and without written authorization templates, the scope file stays empty;
  analysts conclude the testing feature "doesn't work" rather than "isn't
  authorized."
- **Month 5 — Champion leaves.** Reorg moves the original requester. Nobody
  else can operate the vault key custody, the TLS/env setup, or the scope
  file. Usage drops to zero. The remaining team returns to Wireshark
  captures on a shared drive plus the commercial NDR dashboard.
- **Month 6 — Shelved.** Sponsored renewal not requested. The service stays
  installed — capturing nothing, decoding nothing, quietly passing its own
  tests.

## 3. Contributing factors

### 3.1 No last-mile integration (most important)
The platform's outputs stopped at its own UI. Analysts live in the SIEM,
the ticket system and chat. A finding that requires opening a special
pane of glass is, functionally, a finding nobody sees. The spec placed
syslog/OpenSearch export in a later phase; that sequencing decision was
fatal on this timeline. **A correct pipeline that dead-ends is worth less
than a noisy pipeline that lands in the SIEM.**

### 3.2 Competition with incumbents on their terms
Wireshark already explained individual packets; the NDR vendor already had a
dashboard and alerting; Zeek already produced rich logs. Netherglass's honest
differentiators — sealed evidence with audited reveal, chain-of-custody,
controlled testing with fail-closed scope — are *compliance and legal*
features. The team that received the pilot had no compliance driver, so the
differentiators read as friction ("why do I need a reason to click a
button?") rather than value.

### 3.3 Operator burden concentrated in one person
Every operational ritual — pinning tshark, watching storage headroom,
the vault key's 0600 existence, the scope file, TLS flags — lived in one
champion's head. The code documented its limitations honestly; the *service*
had no runbook, no owned key rotation, no weekly checklist. Bus factor 1 on a
deep spec-driven codebase is a slow-motion outage.

### 3.4 Legally-correct controls with no legal scaffolding
Fail-closed scope checking is the right engineering response (§48–§55). But
it presumes authorization documents exist. They didn't. The team had no
template for "authorized testing window" and no one to sign it. A control
that is correct but unusable is experienced as a bug. Version one needed a
bundled authorization template and a named approver workflow, not just a
JSON schema and a refusal.

### 3.5 Metrics never defined
The spec defined success as capabilities shipped. No one defined adoption
success: time-to-first-answer, percentage of incidents touched, credential
runbooks executed, minutes saved per triage. Without usage metrics, the
platform could not demonstrate value in budget season, while the incumbent
NDR's renewal arrived with a renewal-support deck.

### 3.6 Incident-path friction at the worst moments
- Storage guard refused imports during a busy morning (month 3) — correct
  behavior, no pre-agreed retention policy to make room within minutes.
- Emergency stop blocks reveals/exports/deletes; a drill during an audit
  week caused confusion because the runbook didn't exist.
- Reveal requires a stated reason — a 4-character minimum felt like
  bureaucracy to analysts, not evidence hygiene.
None of these are defects; all of them are adoption debt.

### 3.7 Economic and organizational context
The sponsoring cost center was reorganized twice in six months. The
platform's cost (engineering, training, and the ongoing key custody and
compliance responsibilities) never got a budget line; it lived under one
manager's discretionary spend. When that manager's priorities changed, the
platform had no line item to be defended with.

## 4. Root cause statement

**Netherglass was built as a compliance-grade evidence platform and shipped
into an operations team without a compliance problem to solve, without
integration into their workflow, and without an owner who could survive the
first personnel change.** The engineering discipline that made it good
(depth, honesty, fail-closed controls) also made it demanding; the demands
landed on exactly the two people who could least absorb them (the champion
operator, the busy analyst).

## 5. Early warning signs (all visible, all ignored)

1. **Month 1:** findings exported as HTML attachments — a workflow no one
   had automated. This was the moment to build the syslog/ticket output.
2. **Month 2:** tshark pinning note — an undeclared operational dependency.
3. **Month 3:** operator described the storage guard as "the tool refusing
   to work" — the product's value was being read as an obstacle.
4. **Month 4:** scope file still empty after the legal review started —
   nobody had asked "who signs the authorization?" before shipping the
   feature that required it.
5. **Month 5:** zero non-champion logins for three weeks; nobody owned the
   dashboard.

## 6. What would have changed the outcome

1. **Integrate outputs in month 0** (syslog/webhook for findings; a
   `netherglass export --format=ocsf/syslog`). Land in the SIEM or don't
   ship.
2. **Pick one weekly workflow and own it**: the plaintext-credential
   runbook (detect → seal → reveal with reason → incident ticket). Run it
   with the incident team for four consecutive weeks before expanding scope.
3. **Package the service**: systemd unit, pinned tshark in a container image,
   documented key custody with rotation, a printed 1-page operator card, and
   a named backup operator trained in week one.
4. **Bundle the governance artifacts**: authorization template, retention
   policy with the data owner's signature, emergency-drill checklist. Ship
   the paperwork with the endpoint.
5. **Instrument usage from day one** — logins, time-to-answer, reveals per
   week — and review the numbers monthly with the sponsor.
6. **Two maintainers or none**: no feature was worth the bus factor it
   required.
7. **A budget line before a backlog**: the six-month kill was economic
   before it was technical.

## 7. Lessons for the next attempt

- A security tool's unit of value is not a capability; it is a *completed
  workflow in a system someone already uses*.
- Correct controls without accompanying process are experienced as defects.
  Ship the template, the approver, and the drill with the control.
- Honesty about limitations (this project's habit) is necessary but not
  sufficient; operational ownership must be equally explicit.
- Fail-closed design needs a pre-agreed "how to open it legally and
  quickly" path, or operators will route around it.
- Measure adoption or you cannot defend existence.
