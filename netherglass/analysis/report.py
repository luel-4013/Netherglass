"""Report generation (spec section 45).

Two modes:
- standard: findings, assets, connections, timeline and evidence *metadata*;
  sensitive values are omitted entirely.
- restricted: same report plus decrypted evidence values. Requires the
  EXPORT_SENSITIVE_EVIDENCE permission, is marked on every page, and the
  export is audited by the API layer.

Formats: HTML and JSON. PDF/CSV are intentionally not claimed: PDF requires a
renderer dependency, and the HTML is print-ready. PCAP export already exists
separately on the capture endpoint.
"""

from __future__ import annotations

import html
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from ..store import analysis as analysis_store
from ..store import evidence as evidence_store
from ..store import findings as findings_store
from ..store import packets as packets_store
from ..store import timeline as timeline_store


def _escape(value) -> str:
    if value is None:
        return "-"
    return html.escape(str(value))


def _finding_rows(conn: sqlite3.Connection, capture_id: str) -> list[dict]:
    return findings_store.list_findings(conn, capture_id, limit=1000)["findings"]


def _evidence_rows(conn: sqlite3.Connection, capture_id: str) -> list[dict]:
    return evidence_store.list_evidence(conn, capture_id, limit=1000)["artifacts"]


def _hosts(conn: sqlite3.Connection, capture_id: str) -> list[dict]:
    return analysis_store.list_hosts(conn, capture_id, limit=500)


def build_report(
    conn: sqlite3.Connection,
    capture_id: str,
    *,
    data_dir: Path,
    restricted: bool = False,
    generated_by: str,
) -> dict:
    capture = packets_store.get_capture(conn, capture_id)
    if capture is None:
        raise ValueError("capture not found")
    findings = _finding_rows(conn, capture_id)
    evidence = _evidence_rows(conn, capture_id)
    hosts = _hosts(conn, capture_id)
    timeline = timeline_store.build_timeline(conn, capture_id, limit=200)
    stats = analysis_store.stats(conn, capture_id)

    values: dict[str, str] = {}
    if restricted:
        for artifact in evidence:
            if artifact.get("status") != "SEALED":
                continue
            try:
                payload = evidence_store.reveal_value(data_dir, artifact)
                values[artifact["id"]] = payload.get("value", "")
            except evidence_store.EvidenceError:
                values[artifact["id"]] = "<unavailable>"

    report = {
        "report": {
            "capture_id": capture_id,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "generated_by": generated_by,
            "restricted": restricted,
            "mode": "RESTRICTED — CONTAINS SENSITIVE VALUES" if restricted else "STANDARD",
            "capture": capture,
            "executive_summary": {
                "hosts": len(hosts),
                "findings": len(findings),
                "critical": sum(1 for item in findings if item["severity"] == "CRITICAL"),
                "high": sum(1 for item in findings if item["severity"] == "HIGH"),
                "evidence_artifacts": len(evidence),
                "plaintext_packets": next(
                    (
                        bucket.get("packets", 0)
                        for bucket in stats.get("encryption", [])
                        if bucket.get("encryption") == "plaintext"
                    ),
                    0,
                ),
            },
            "findings": findings,
            "hosts": hosts,
            "evidence": [
                {
                    **artifact,
                    "value": values.get(artifact["id"]) if restricted else None,
                }
                for artifact in evidence
            ],
            "timeline": timeline["events"],
            "remediation": sorted(
                {item["remediation"] for item in findings if item.get("remediation")}
            ),
        }
    }
    return report


def render_json(report: dict) -> str:
    return json.dumps(report, indent=2, default=str)


def _severity_class(severity: str) -> str:
    return f"sev-{severity.lower()}"


def render_html(report: dict) -> str:
    body = report["report"]
    restricted = body["restricted"]
    banner = (
        '<div class="restricted">RESTRICTED — THIS REPORT CONTAINS SENSITIVE '
        "EVIDENCE VALUES. HANDLE ACCORDING TO AUTHORIZATION TERMS.</div>"
        if restricted
        else ""
    )
    finding_rows = "".join(
        f"<tr><td class='{_severity_class(item['severity'])}'>{_escape(item['severity'])}</td>"
        f"<td>{_escape(item['confidence'])}</td>"
        f"<td>{_escape(item['title'])}</td>"
        f"<td>{_escape(item['asset'])}</td>"
        f"<td>{_escape(item['explanation'])}</td>"
        f"<td>{_escape(item['remediation'])}</td></tr>"
        for item in body["findings"]
    ) or "<tr><td colspan='6'>no findings</td></tr>"
    host_rows = "".join(
        f"<tr><td>{_escape(item['ip'])}</td><td>{_escape(item['hostname'])}</td>"
        f"<td>{_escape(item['mac'])}</td><td>{item['packets']}</td>"
        f"<td>{item['bytes']}</td></tr>"
        for item in body["hosts"]
    ) or "<tr><td colspan='5'>no hosts</td></tr>"
    evidence_rows = "".join(
        f"<tr><td>{_escape(item['id'])}</td><td>{_escape(item['artifact_type'])}</td>"
        f"<td>{_escape(item['field'])}</td><td>{_escape(item['host'])}</td>"
        f"<td>{_escape(item['transport_security'])}</td>"
        f"<td class='value'>{_escape(item['value']) if restricted else '&lt;omitted&gt;'}</td></tr>"
        for item in body["evidence"]
    ) or "<tr><td colspan='6'>no evidence</td></tr>"
    timeline_rows = "".join(
        f"<tr><td>{_escape(item.get('ts'))}</td><td>{_escape(item.get('kind'))}</td>"
        f"<td>{_escape(item.get('title'))}</td><td>{_escape(item.get('detail'))}</td></tr>"
        for item in body["timeline"][:100]
    ) or "<tr><td colspan='4'>no timeline events</td></tr>"
    remediation = "".join(
        f"<li>{_escape(item)}</li>" for item in body["remediation"]
    ) or "<li>no remediation required by observed findings</li>"
    summary = body["executive_summary"]
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Netherglass report {_escape(body['capture_id'])}</title>
<style>
body {{ font-family: ui-monospace, monospace; background:#0b0f0b; color:#9dff9d; margin:2rem; }}
h1,h2 {{ color:#c8ffc8; letter-spacing:0.1em; }}
table {{ border-collapse:collapse; width:100%; margin-bottom:1.5rem; }}
th,td {{ border:1px solid #2f5f2f; padding:0.35rem 0.5rem; font-size:0.8rem; text-align:left; vertical-align:top; }}
th {{ background:#132613; }}
.restricted {{ background:#5a0f0f; color:#ffd7d7; padding:0.8rem; font-weight:bold; margin-bottom:1rem; }}
.sev-critical {{ color:#ff5f5f; font-weight:bold; }}
.sev-high {{ color:#ff9f5f; }}
.sev-medium {{ color:#ffd75f; }}
.sev-low {{ color:#8fd7ff; }}
.value {{ color:#ffd7a0; word-break:break-all; }}
.dim {{ color:#6f9f6f; }}
@media print {{ body {{ background:#fff; color:#000; }} th {{ background:#eee; }} }}
</style></head><body>
{banner}
<h1>NETHERGLASS SECURITY REPORT</h1>
<p class="dim">capture {_escape(body['capture_id'])} · generated {_escape(body['generated_at'])}
by {_escape(body['generated_by'])} · mode {_escape(body['mode'])}</p>
<h2>EXECUTIVE SUMMARY</h2>
<ul>
<li>hosts observed: {summary['hosts']}</li>
<li>findings: {summary['findings']} (critical {summary['critical']}, high {summary['high']})</li>
<li>sensitive evidence artifacts: {summary['evidence_artifacts']}</li>
<li>plaintext packets: {summary['plaintext_packets']}</li>
</ul>
<h2>TECHNICAL FINDINGS</h2>
<table><tr><th>SEVERITY</th><th>CONFIDENCE</th><th>TITLE</th><th>ASSET</th>
<th>EXPLANATION</th><th>REMEDIATION</th></tr>{finding_rows}</table>
<h2>AFFECTED ASSETS</h2>
<table><tr><th>IP</th><th>HOSTNAME</th><th>MAC</th><th>PACKETS</th><th>BYTES</th></tr>{host_rows}</table>
<h2>EVIDENCE REFERENCES</h2>
<table><tr><th>ID</th><th>TYPE</th><th>FIELD</th><th>HOST</th><th>TRANSPORT</th>
<th>VALUE</th></tr>{evidence_rows}</table>
<h2>TIMELINE (most recent 100)</h2>
<table><tr><th>TS</th><th>KIND</th><th>EVENT</th><th>DETAIL</th></tr>{timeline_rows}</table>
<h2>REMEDIATION</h2>
<ul>{remediation}</ul>
<p class="dim">Sensitive values are omitted from standard reports by design.
Restricted reports are audited and must be stored per the engagement's
evidence-handling terms.</p>
</body></html>"""
