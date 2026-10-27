import { useEffect, useState } from "react";
import { getStats } from "../api";
import { fmtBytes } from "../format";
import type { StatsBucket, StatsData } from "../types";

interface Props {
  captureId: string;
}

interface BarsProps {
  title: string;
  rows: StatsBucket[];
  label: (row: StatsBucket) => string;
  value: (row: StatsBucket) => number;
  format: (value: number) => string;
}

function Bars({ title, rows, label, value, format }: BarsProps) {
  const max = rows.reduce((acc, row) => Math.max(acc, value(row)), 0) || 1;
  return (
    <section className="stat-block">
      <h4>{title}</h4>
      {rows.length === 0 && <p className="dim">no data yet</p>}
      {rows.map((row, index) => {
        const amount = value(row);
        return (
          <div className="bar-row" key={index}>
            <span className="bar-label dim" title={label(row)}>
              {label(row)}
            </span>
            <span className="bar-track">
              <span
                className="bar-fill"
                style={{ width: `${Math.max(2, (amount / max) * 100)}%` }}
              />
            </span>
            <span className="bar-value">{format(amount)}</span>
          </div>
        );
      })}
    </section>
  );
}

export default function StatsView({ captureId }: Props) {
  const [data, setData] = useState<StatsData | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    getStats(captureId)
      .then(setData)
      .catch((err: unknown) =>
        setError(err instanceof Error ? err.message : "failed to load statistics"),
      );
  }, [captureId]);

  if (error) {
    return <div className="error-bar">!! {error}</div>;
  }
  if (!data) {
    return <p className="dim">computing statistics ...</p>;
  }

  const dns = data.dns_summary ?? {};
  return (
    <>
      <h2>STATISTICS</h2>
      <p className="dim">
        dns: {String(dns.queries ?? 0)} queries · {String(dns.nxdomain ?? 0)} nxdomain ·{" "}
        {String(dns.orphan_responses ?? 0)} orphan responses (no matching query captured)
      </p>
      <div className="stats-grid">
        <Bars
          title="TOP TALKERS"
          rows={data.top_talkers}
          label={(row) => `${row.ip}${row.hostname ? ` (${row.hostname})` : ""}`}
          value={(row) => Number(row.bytes ?? 0)}
          format={fmtBytes}
        />
        <Bars
          title="TOP DESTINATIONS"
          rows={data.top_destinations}
          label={(row) => String(row.ip ?? "-")}
          value={(row) => Number(row.bytes ?? 0)}
          format={fmtBytes}
        />
        <Bars
          title="TOP DOMAINS"
          rows={data.top_domains}
          label={(row) => String(row.qname ?? "-")}
          value={(row) => Number(row.queries ?? 0)}
          format={(value) => `${value} q`}
        />
        <Bars
          title="TOP PORTS"
          rows={data.top_ports}
          label={(row) => `${row.port}/${row.proto}`}
          value={(row) => Number(row.packets ?? 0)}
          format={(value) => `${value} pkt`}
        />
        <Bars
          title="PROTOCOLS"
          rows={data.top_protocols}
          label={(row) => String(row.protocol ?? "-")}
          value={(row) => Number(row.packets ?? 0)}
          format={(value) => `${value} pkt`}
        />
        <Bars
          title="TLS VERSIONS"
          rows={data.tls_versions}
          label={(row) => String(row.version ?? "-")}
          value={(row) => Number(row.sessions ?? 0)}
          format={(value) => `${value} sess`}
        />
        <Bars
          title="ENCRYPTION"
          rows={data.encryption}
          label={(row) => String(row.encryption ?? "unknown")}
          value={(row) => Number(row.packets ?? 0)}
          format={(value) => `${value} pkt`}
        />
        <Bars
          title="SECURITY QUALITY"
          rows={data.security}
          label={(row) => String(row.security ?? "unknown")}
          value={(row) => Number(row.packets ?? 0)}
          format={(value) => `${value} pkt`}
        />
      </div>
      {data.findings.available ? (
        <p className="dim">
          findings: {data.findings.total} ·{" "}
          {Object.entries(data.findings.by_severity)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([level, count]) => `${level.toLowerCase()}: ${count}`)
            .join(" · ") || "none"} · open the FINDINGS tab for details
        </p>
      ) : (
        <p className="dim">{data.findings.note}</p>
      )}
      {data.sensitive_data.available ? (
        <p className="dim">
          sensitive artifacts:{" "}
          {data.sensitive_data.by_type
            .map((item) => `${item.artifact_type.toLowerCase()}: ${item.count}`)
            .join(" · ") || "none detected"}{" "}
          · values are sealed in the evidence vault (EVIDENCE tab)
        </p>
      ) : (
        <p className="dim">{data.sensitive_data.note}</p>
      )}
    </>
  );
}
