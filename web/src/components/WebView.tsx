import { Fragment, useCallback, useEffect, useState } from "react";
import {
  getWebApps,
  getWebCookies,
  getWebFlows,
  getWebHeaders,
  getWebTokens,
} from "../api";
import { fmtTime } from "../format";
import type {
  DataFlowRow,
  SessionInfo,
  WebApp,
  WebCookieRow,
  WebHeaderRow,
  WebTokenRow,
} from "../types";

interface Props {
  captureId: string;
  session: SessionInfo;
}

type Section = "apps" | "cookies" | "headers" | "tokens" | "flows";

const SECTIONS: { id: Section; label: string; permission?: string }[] = [
  { id: "apps", label: "APPLICATIONS" },
  { id: "cookies", label: "COOKIES" },
  { id: "headers", label: "HEADERS" },
  { id: "tokens", label: "TOKENS", permission: "VIEW_SENSITIVE_METADATA" },
  { id: "flows", label: "DATA FLOWS", permission: "VIEW_SENSITIVE_METADATA" },
];

function yes(value: number | boolean | null | undefined): string {
  if (value === null || value === undefined) return "-";
  return value ? "yes" : "no";
}

export default function WebView({ captureId, session }: Props) {
  const [section, setSection] = useState<Section>("apps");
  const [apps, setApps] = useState<WebApp[]>([]);
  const [cookies, setCookies] = useState<WebCookieRow[]>([]);
  const [headers, setHeaders] = useState<WebHeaderRow[]>([]);
  const [tokens, setTokens] = useState<WebTokenRow[]>([]);
  const [flows, setFlows] = useState<DataFlowRow[]>([]);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [error, setError] = useState("");

  const canSensitive = session.permissions.includes("VIEW_SENSITIVE_METADATA");

  const load = useCallback(async () => {
    try {
      if (section === "apps") {
        setApps((await getWebApps(captureId)).applications);
      } else if (section === "cookies") {
        setCookies((await getWebCookies(captureId)).cookies);
      } else if (section === "headers") {
        setHeaders((await getWebHeaders(captureId)).hosts);
      } else if (section === "tokens" && canSensitive) {
        setTokens((await getWebTokens(captureId)).tokens);
      } else if (section === "flows" && canSensitive) {
        setFlows((await getWebFlows(captureId)).flows);
      }
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed to load web analysis");
    }
  }, [captureId, section, canSensitive]);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <>
      <h2>WEB SECURITY</h2>
      <p className="dim">
        network-observable analysis of web applications: inventory, cookie and
        token metadata, response headers and sensitive-data flows. token values
        are never shown — rows are keyed by a one-way fingerprint.
      </p>
      {error && <div className="error-bar">!! {error}</div>}
      <div className="tabs">
        {SECTIONS.map((item) => {
          const blocked = item.permission
            ? !session.permissions.includes(item.permission)
            : false;
          return (
            <button
              key={item.id}
              className={`btn btn-small ${section === item.id ? "btn-active" : ""}`}
              onClick={() => {
                if (blocked) {
                  setError(
                    `requires ${item.permission} permission for this section`,
                  );
                  return;
                }
                setSection(item.id);
              }}
              title={blocked ? `requires ${item.permission}` : undefined}
            >
              [ {item.label}{blocked ? " *" : ""} ]
            </button>
          );
        })}
      </div>

      {section === "apps" && (
        <table className="tbl">
          <thead>
            <tr>
              <th>HOST</th>
              <th>IPS</th>
              <th>PORTS</th>
              <th>REQ / RESP</th>
              <th>TLS</th>
              <th>AUTH</th>
              <th>COOKIES</th>
              <th>TOKENS</th>
              <th>FINDINGS</th>
            </tr>
          </thead>
          <tbody>
            {apps.map((app) => (
              <Fragment key={app.host}>
                <tr
                  style={{ cursor: "pointer" }}
                  className={expanded === app.host ? "selected" : ""}
                  onClick={() =>
                    setExpanded(expanded === app.host ? null : app.host)
                  }
                >
                  <td className="accent">{app.host}</td>
                  <td className="mono-small">
                    {app.ips.slice(0, 3).join(", ") || "-"}
                    {app.external_ips.length > 0 && (
                      <span className="warn"> (external)</span>
                    )}
                  </td>
                  <td>{app.ports.join(", ") || "-"}</td>
                  <td>
                    {app.http_requests} / {app.http_responses}
                  </td>
                  <td>
                    {app.tls[0]?.version ?? "-"}
                    {app.tls[0]?.security && (
                      <span
                        className={
                          app.tls[0].security === "good" ? "dim" : "warn"
                        }
                      >
                        {" "}
                        {app.tls[0].security}
                      </span>
                    )}
                  </td>
                  <td className="dim">{app.auth_schemes.join(", ") || "-"}</td>
                  <td>{app.cookies.length}</td>
                  <td>{app.tokens}</td>
                  <td className={app.findings > 0 ? "warn" : "dim"}>
                    {app.findings}
                  </td>
                </tr>
                {expanded === app.host && (
                  <tr className="detail-row">
                    <td colSpan={9}>
                      <p className="finding-detail">
                        dns names: {app.dns_names.join(", ") || "(none observed)"}
                      </p>
                      <p className="finding-detail">
                        endpoints:{" "}
                        {app.endpoints.slice(0, 20).join(" · ") ||
                          "(none observed)"}
                      </p>
                      <p className="finding-detail">
                        cookies:{" "}
                        {app.cookies
                          .map((cookie) => `${cookie.name} (${cookie.kind})`)
                          .join(", ") || "(none observed)"}
                      </p>
                      {app.security_headers && (
                        <p className="dim">
                          security headers — hsts:{" "}
                          {yes(app.security_headers.hsts as number)}, csp:{" "}
                          {yes(app.security_headers.csp as number)}, nosniff:{" "}
                          {yes(app.security_headers.x_content_type_options as number)},
                          frame:{" "}
                          {yes(app.security_headers.x_frame_options as number)},
                          referrer:{" "}
                          {yes(app.security_headers.referrer_policy as number)},
                          permissions:{" "}
                          {yes(app.security_headers.permissions_policy as number)}
                        </p>
                      )}
                      {app.tls.map((tls, index) => (
                        <p key={index} className="dim mono-small">
                          tls {tls.version ?? "?"} · {tls.cipher ?? "unknown cipher"} ·
                          cert {tls.not_before ?? "?"} → {tls.not_after ?? "?"}
                        </p>
                      ))}
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
            {apps.length === 0 && (
              <tr>
                <td colSpan={9} className="dim">
                  no HTTP/TLS application metadata observed yet
                </td>
              </tr>
            )}
          </tbody>
        </table>
      )}

      {section === "cookies" && (
        <table className="tbl">
          <thead>
            <tr>
              <th>NAME</th>
              <th>KIND</th>
              <th>HOST</th>
              <th>SECURE</th>
              <th>HTTPONLY</th>
              <th>SAMESITE</th>
              <th>MAX-AGE</th>
              <th>PLAINTEXT</th>
              <th>SEEN</th>
            </tr>
          </thead>
          <tbody>
            {cookies.map((cookie) => (
              <tr key={`${cookie.name}-${cookie.host}`}>
                <td>{cookie.name}</td>
                <td className="accent">{cookie.kind}</td>
                <td className="dim">{cookie.host || "-"}</td>
                <td className={cookie.set_observed && !cookie.secure ? "warn" : "dim"}>
                  {cookie.set_observed ? yes(cookie.secure) : "n/a"}
                </td>
                <td
                  className={cookie.set_observed && !cookie.http_only ? "warn" : "dim"}
                >
                  {cookie.set_observed ? yes(cookie.http_only) : "n/a"}
                </td>
                <td
                  className={
                    cookie.set_observed &&
                    !["strict", "lax"].includes(
                      (cookie.same_site ?? "").toLowerCase(),
                    )
                      ? "warn"
                      : "dim"
                  }
                >
                  {cookie.set_observed ? cookie.same_site ?? "absent" : "n/a"}
                </td>
                <td className="dim">
                  {cookie.max_age !== null ? `${cookie.max_age}s` : "-"}
                </td>
                <td className={cookie.plaintext ? "warn" : "dim"}>
                  {yes(cookie.plaintext)}
                </td>
                <td>{cookie.seen_count}</td>
              </tr>
            ))}
            {cookies.length === 0 && (
              <tr>
                <td colSpan={9} className="dim">
                  no cookies observed
                </td>
              </tr>
            )}
          </tbody>
        </table>
      )}

      {section === "headers" && (
        <table className="tbl">
          <thead>
            <tr>
              <th>HOST</th>
              <th>RESPONSES</th>
              <th>HSTS</th>
              <th>CSP</th>
              <th>NOSNIFF</th>
              <th>FRAME</th>
              <th>REFERRER</th>
              <th>PERMISSIONS</th>
              <th>CACHE-CONTROL</th>
              <th>SERVER</th>
            </tr>
          </thead>
          <tbody>
            {headers.map((row) => (
              <tr key={row.host}>
                <td className="accent">{row.host}</td>
                <td>{row.responses}</td>
                {(
                  [
                    "hsts",
                    "csp",
                    "x_content_type_options",
                    "x_frame_options",
                    "referrer_policy",
                    "permissions_policy",
                  ] as const
                ).map((key) => (
                  <td
                    key={key}
                    className={row[key] > 0 ? "dim" : "warn"}
                  >
                    {row[key] > 0 ? "yes" : "no"}
                  </td>
                ))}
                <td className="dim">{row.cache_control ?? "-"}</td>
                <td className="dim">{row.server ?? "-"}</td>
              </tr>
            ))}
            {headers.length === 0 && (
              <tr>
                <td colSpan={10} className="dim">
                  no HTTP responses observed
                </td>
              </tr>
            )}
          </tbody>
        </table>
      )}

      {section === "tokens" && (
        <table className="tbl">
          <thead>
            <tr>
              <th>FINGERPRINT</th>
              <th>KIND</th>
              <th>NAME</th>
              <th>ALG</th>
              <th>HOSTS</th>
              <th>CLIENTS</th>
              <th>PLAINTEXT</th>
              <th>SEEN</th>
              <th>FIRST</th>
            </tr>
          </thead>
          <tbody>
            {tokens.map((token) => (
              <tr key={token.fingerprint}>
                <td className="mono-small dim">{token.fingerprint}…</td>
                <td className="accent">{token.kind}</td>
                <td>{token.name ?? "-"}</td>
                <td className="dim">{token.alg ?? "-"}</td>
                <td className="mono-small">{token.hosts.join(", ") || "-"}</td>
                <td className="mono-small">{token.clients.join(", ") || "-"}</td>
                <td className={token.plaintext ? "warn" : "dim"}>
                  {yes(token.plaintext)}
                </td>
                <td>{token.seen_count}</td>
                <td className="mono-small">{fmtTime(token.first_ts)}</td>
              </tr>
            ))}
            {tokens.length === 0 && (
              <tr>
                <td colSpan={9} className="dim">
                  no token fingerprints observed
                </td>
              </tr>
            )}
          </tbody>
        </table>
      )}

      {section === "flows" && (
        <table className="tbl">
          <thead>
            <tr>
              <th>ARTIFACT</th>
              <th>ORIGIN HOST</th>
              <th>DESTINATION</th>
              <th>TRANSPORT</th>
              <th>APP</th>
              <th>COUNT</th>
              <th>RISK</th>
              <th>LAST</th>
            </tr>
          </thead>
          <tbody>
            {flows.map((flow, index) => (
              <tr key={`${flow.artifact_type}-${flow.dst}-${index}`}>
                <td className="accent">{flow.artifact_type}</td>
                <td>{flow.host ?? "-"}</td>
                <td className="mono-small">
                  {flow.dst ?? "-"}
                  {flow.destination_internal === false && (
                    <span className="warn"> external</span>
                  )}
                </td>
                <td
                  className={
                    (flow.transport_security ?? "").toLowerCase() === "plaintext"
                      ? "warn"
                      : "dim"
                  }
                >
                  {flow.transport_security ?? "unknown"}
                </td>
                <td className="dim">{flow.app_proto ?? "-"}</td>
                <td>{flow.count}</td>
                <td
                  className={
                    flow.transport_risk === "HIGH"
                      ? "sev sev-critical"
                      : flow.transport_risk === "MEDIUM"
                        ? "sev sev-high"
                        : "dim"
                  }
                >
                  {flow.transport_risk}
                </td>
                <td className="mono-small">{fmtTime(flow.last_ts)}</td>
              </tr>
            ))}
            {flows.length === 0 && (
              <tr>
                <td colSpan={8} className="dim">
                  no sensitive-data flows observed
                </td>
              </tr>
            )}
          </tbody>
        </table>
      )}
    </>
  );
}
