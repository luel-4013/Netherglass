import { useCallback, useEffect, useState } from "react";
import { getTimeline } from "../api";
import { fmtTime } from "../format";
import type { TimelinePage } from "../types";

interface Props {
  captureId: string;
}

const KINDS = ["", "dns", "tls", "http", "finding", "evidence", "audit"];
const SEVERITIES = ["", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

const KIND_LABEL: Record<string, string> = {
  dns: "DNS",
  tls: "TLS",
  http: "HTTP",
  finding: "FINDING",
  evidence: "EVIDENCE",
  audit: "AUDIT",
};

export default function TimelineView({ captureId }: Props) {
  const [page, setPage] = useState<TimelinePage | null>(null);
  const [kind, setKind] = useState("");
  const [severity, setSeverity] = useState("");
  const [host, setHost] = useState("");
  const [domain, setDomain] = useState("");
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const data = await getTimeline(captureId, {
        kind: kind || undefined,
        severity: severity || undefined,
        host: host || undefined,
        domain: domain || undefined,
      });
      setPage(data);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed to load timeline");
    }
  }, [captureId, kind, severity, host, domain]);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <>
      <h2>TIMELINE {page ? `(${page.total})` : ""}</h2>
      <p className="dim">
        unified event feed: DNS, TLS, HTTP, findings, sealed evidence and
        security-stop audit events. emergency stops appear here as CRITICAL
        audit rows.
      </p>
      {error && <div className="error-bar">!! {error}</div>}
      <div className="filterbar">
        <select value={kind} onChange={(event) => setKind(event.target.value)}>
          {KINDS.map((item) => (
            <option key={item} value={item}>
              {item ? item : "all kinds"}
            </option>
          ))}
        </select>
        <select
          value={severity}
          onChange={(event) => setSeverity(event.target.value)}
        >
          {SEVERITIES.map((item) => (
            <option key={item} value={item}>
              {item ? item : "all severities"}
            </option>
          ))}
        </select>
        <input
          placeholder="host / asset"
          value={host}
          onChange={(event) => setHost(event.target.value)}
        />
        <input
          placeholder="domain"
          value={domain}
          onChange={(event) => setDomain(event.target.value)}
        />
        <button className="btn btn-small" onClick={() => void load()}>
          [ REFRESH ]
        </button>
      </div>
      <table className="tbl">
        <thead>
          <tr>
            <th>TIME</th>
            <th>KIND</th>
            <th>EVENT</th>
            <th>DETAIL</th>
            <th>REF</th>
          </tr>
        </thead>
        <tbody>
          {page?.events.map((event, index) => (
            <tr key={`${event.kind}-${event.ref ?? index}-${event.ts ?? index}`}>
              <td className="mono-small">{fmtTime(event.ts)}</td>
              <td
                className={
                  event.severity === "CRITICAL"
                    ? "sev sev-critical"
                    : event.severity === "HIGH"
                      ? "sev sev-high"
                      : "dim"
                }
              >
                {KIND_LABEL[event.kind] ?? event.kind.toUpperCase()}
              </td>
              <td>{event.title}</td>
              <td className="dim">{event.detail}</td>
              <td className="mono-small dim">{event.ref ?? "-"}</td>
            </tr>
          ))}
          {page && page.events.length === 0 && (
            <tr>
              <td colSpan={5} className="dim">
                no events match the filters
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </>
  );
}
