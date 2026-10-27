import { Fragment, useCallback, useEffect, useState } from "react";
import { analyzeCapture, getFindings } from "../api";
import { fmtTime, parseJsonList } from "../format";
import type { FindingsPage, FindingsSummary } from "../types";

interface Props {
  captureId: string;
}

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const CONFIDENCES = ["OBSERVED", "LIKELY", "POSSIBLE", "NOT_DETERMINED"];

function severityClass(severity: string): string {
  return `sev sev-${severity.toLowerCase()}`;
}

export default function FindingsView({ captureId }: Props) {
  const [page, setPage] = useState<FindingsPage | null>(null);
  const [severity, setSeverity] = useState("");
  const [confidence, setConfidence] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const data = await getFindings(captureId, {
        severity: severity || undefined,
        confidence: confidence || undefined,
      });
      setPage(data);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed to load findings");
    }
  }, [captureId, severity, confidence]);

  useEffect(() => {
    void load();
  }, [load]);

  async function rerun() {
    setBusy(true);
    try {
      await analyzeCapture(captureId);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "analysis failed");
    } finally {
      setBusy(false);
    }
  }

  if (error && !page) {
    return <div className="error-bar">!! {error}</div>;
  }

  const summary = page?.summary as FindingsSummary | undefined;
  return (
    <>
      <h2>FINDINGS {page ? `(${page.total})` : ""}</h2>
      <p className="dim">
        every finding carries a severity and a confidence; explanations state the
        observation behind them. remediation text is written for the report.
      </p>
      {error && <div className="error-bar">!! {error}</div>}
      <div className="filterbar">
        <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
          <option value="">all severities</option>
          {SEVERITIES.map((item) => (
            <option key={item} value={item}>
              {item}
            </option>
          ))}
        </select>
        <select value={confidence} onChange={(event) => setConfidence(event.target.value)}>
          <option value="">all confidences</option>
          {CONFIDENCES.map((item) => (
            <option key={item} value={item}>
              {item}
            </option>
          ))}
        </select>
        <button className="btn btn-small" onClick={() => void rerun()} disabled={busy}>
          {busy ? "[ ANALYZING ... ]" : "[ RE-RUN ANALYSIS ]"}
        </button>
      </div>
      {summary && (
        <p className="dim">
          {Object.entries(summary.by_severity)
            .sort(
              ([a], [b]) =>
                SEVERITIES.indexOf(a) - SEVERITIES.indexOf(b),
            )
            .map(([level, count]) => `${level.toLowerCase()}: ${count}`)
            .join(" · ") || "no findings"}
        </p>
      )}
      <table className="tbl">
        <thead>
          <tr>
            <th>SEVERITY</th>
            <th>CONFIDENCE</th>
            <th>RULE</th>
            <th>TITLE</th>
            <th>ASSET</th>
            <th>PROTO</th>
            <th>FIRST OBSERVED</th>
          </tr>
        </thead>
        <tbody>
          {page?.findings.map((finding) => (
            <Fragment key={finding.id}>
              <tr
                className={expanded === finding.id ? "selected" : ""}
                style={{ cursor: "pointer" }}
                onClick={() => setExpanded(expanded === finding.id ? null : finding.id)}
              >
                <td className={severityClass(finding.severity)}>{finding.severity}</td>
                <td className="dim">{finding.confidence}</td>
                <td className="mono-small">{finding.rule_id}</td>
                <td>{finding.title}</td>
                <td>{finding.asset ?? <span className="dim">-</span>}</td>
                <td className="accent">{finding.protocol ?? "-"}</td>
                <td className="mono-small">{fmtTime(finding.first_ts)}</td>
              </tr>
              {expanded === finding.id && (
                <tr className="detail-row">
                  <td colSpan={7}>
                    <p className="finding-detail">{finding.explanation}</p>
                    <p className="dim">
                      {finding.src ?? "-"} → {finding.dst ?? "-"} · status{" "}
                      {finding.status} · finding {finding.id}
                    </p>
                    <p className="remediation">
                      <span className="dim">remediation: </span>
                      {finding.remediation}
                    </p>
                    <p className="dim">
                      evidence:{" "}
                      {parseJsonList(finding.evidence_ids).join(", ") || "(none)"} ·
                      packets:{" "}
                      {parseJsonList(finding.packet_refs).join(", ") || "(none)"}
                    </p>
                  </td>
                </tr>
              )}
            </Fragment>
          ))}
          {page && page.findings.length === 0 && (
            <tr>
              <td colSpan={7} className="dim">
                no findings yet — analysis runs automatically when a capture
                finishes; use [ RE-RUN ANALYSIS ] after changing rules.json
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </>
  );
}
