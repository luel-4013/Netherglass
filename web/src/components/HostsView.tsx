import { useCallback, useEffect, useState } from "react";
import { getHost, getHosts } from "../api";
import { fmtBytes, fmtTime, parseJsonList } from "../format";
import type { HostDetail, HostRow } from "../types";

interface Props {
  captureId: string;
}

export default function HostsView({ captureId }: Props) {
  const [hosts, setHosts] = useState<HostRow[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [detail, setDetail] = useState<HostDetail | null>(null);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const data = await getHosts(captureId, 500);
      setHosts(data.hosts);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed to load hosts");
    }
  }, [captureId]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (!selected) {
      setDetail(null);
      return;
    }
    getHost(captureId, selected)
      .then(setDetail)
      .catch((err: unknown) =>
        setError(err instanceof Error ? err.message : "failed to load host"),
      );
  }, [captureId, selected]);

  return (
    <>
      <h2>HOSTS ({hosts.length})</h2>
      <p className="dim">
        scope: a capture only sees traffic that reaches its capture point — this
        host&apos;s conversations plus broadcast/multicast (ARP, mDNS, DHCP) on
        the link. Unicast traffic between other devices stays invisible on
        managed Wi-Fi; use monitor mode or a TAP/SPAN feed to observe it.
      </p>
      <table className="tbl">
        <thead>
          <tr>
            <th>IP</th>
            <th>HOSTNAME</th>
            <th>SOURCE</th>
            <th>MAC</th>
            <th>PACKETS</th>
            <th>BYTES</th>
            <th>SENT / RECV</th>
            <th>LAST SEEN</th>
          </tr>
        </thead>
        <tbody>
          {hosts.map((host) => (
            <tr
              key={host.ip}
              className={selected === host.ip ? "selected" : ""}
              onClick={() => setSelected(selected === host.ip ? null : host.ip)}
              style={{ cursor: "pointer" }}
            >
              <td>{host.ip}</td>
              <td>{host.hostname ?? <span className="dim">-</span>}</td>
              <td className="dim">{host.hostname_source ?? "-"}</td>
              <td className="mono-small">{host.mac ?? "-"}</td>
              <td>{host.packets}</td>
              <td>{fmtBytes(host.bytes)}</td>
              <td className="dim">
                {fmtBytes(host.sent_bytes)} / {fmtBytes(host.recv_bytes)}
              </td>
              <td className="mono-small">{fmtTime(host.last_ts)}</td>
            </tr>
          ))}
          {hosts.length === 0 && (
            <tr>
              <td colSpan={8} className="dim">
                no hosts discovered yet
              </td>
            </tr>
          )}
        </tbody>
      </table>

      {detail && (
        <div className="detail-block">
          <h3>HOST {detail.host.ip}</h3>
          {detail.names.length > 0 && (
            <p className="dim">
              names:{" "}
              {detail.names.map((name) => (
                <span key={`${name.source}-${name.name}`} className="chip">
                  {name.name} ({name.source})
                </span>
              ))}
            </p>
          )}

          <h4>SERVICES</h4>
          <table className="tbl">
            <thead>
              <tr>
                <th>PORT</th>
                <th>PROTO</th>
                <th>APP</th>
                <th>PACKETS</th>
                <th>BYTES</th>
                <th>LAST</th>
              </tr>
            </thead>
            <tbody>
              {detail.services.map((service) => (
                <tr key={`${service.proto}-${service.port}`}>
                  <td>{service.port}</td>
                  <td>{service.proto}</td>
                  <td className="accent">{service.app_proto ?? "-"}</td>
                  <td>{service.packets}</td>
                  <td>{fmtBytes(service.bytes)}</td>
                  <td className="mono-small">{fmtTime(service.last_ts)}</td>
                </tr>
              ))}
              {detail.services.length === 0 && (
                <tr>
                  <td colSpan={6} className="dim">
                    no observed services
                  </td>
                </tr>
              )}
            </tbody>
          </table>

          <h4>FLOWS</h4>
          <table className="tbl">
            <thead>
              <tr>
                <th>SRC</th>
                <th>DST</th>
                <th>PROTO</th>
                <th>DPORT</th>
                <th>PACKETS</th>
                <th>BYTES</th>
              </tr>
            </thead>
            <tbody>
              {detail.flows.map((flow, index) => (
                <tr key={index}>
                  <td>{flow.src}</td>
                  <td>{flow.dst}</td>
                  <td className="accent">{flow.proto}</td>
                  <td>{flow.dport}</td>
                  <td>{flow.packets}</td>
                  <td>{fmtBytes(flow.bytes)}</td>
                </tr>
              ))}
              {detail.flows.length === 0 && (
                <tr>
                  <td colSpan={6} className="dim">
                    no flows
                  </td>
                </tr>
              )}
            </tbody>
          </table>

          {detail.dns.length > 0 && (
            <>
              <h4>DNS</h4>
              <table className="tbl">
                <thead>
                  <tr>
                    <th>TIME</th>
                    <th>QNAME</th>
                    <th>QTYPE</th>
                    <th>RCODE</th>
                    <th>ANSWERS</th>
                  </tr>
                </thead>
                <tbody>
                  {detail.dns.map((event) => (
                    <tr key={event.id}>
                      <td className="mono-small">{fmtTime(event.ts)}</td>
                      <td>{event.qname}</td>
                      <td>{event.qtype ?? "-"}</td>
                      <td className={event.rcode === "NXDOMAIN" ? "warn" : ""}>
                        {event.rcode ?? "-"}
                      </td>
                      <td className="dim">{parseJsonList(event.answers).join(", ") || "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}

          {detail.http.length > 0 && (
            <>
              <h4>HTTP</h4>
              <table className="tbl">
                <thead>
                  <tr>
                    <th>TIME</th>
                    <th>KIND</th>
                    <th>HOST</th>
                    <th>PATH</th>
                    <th>STATUS</th>
                  </tr>
                </thead>
                <tbody>
                  {detail.http.map((event) => (
                    <tr key={event.id}>
                      <td className="mono-small">{fmtTime(event.ts)}</td>
                      <td>{event.kind}</td>
                      <td>{event.host ?? "-"}</td>
                      <td className="dim">{event.path ?? "-"}</td>
                      <td>{event.status ?? "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}

          {detail.tls.length > 0 && (
            <>
              <h4>TLS</h4>
              <table className="tbl">
                <thead>
                  <tr>
                    <th>STREAM</th>
                    <th>SERVER</th>
                    <th>VERSION</th>
                    <th>SNI</th>
                    <th>VALID</th>
                    <th>SANS</th>
                  </tr>
                </thead>
                <tbody>
                  {detail.tls.map((session) => (
                    <tr key={session.stream}>
                      <td>{session.stream}</td>
                      <td>{session.server ?? "-"}</td>
                      <td>{session.version ?? "-"}</td>
                      <td className="accent">{session.sni ?? "-"}</td>
                      <td className="mono-small">
                        {session.cert_not_before ?? "-"} .. {session.cert_not_after ?? "-"}
                      </td>
                      <td className="dim">
                        {parseJsonList(session.cert_sans).join(", ") || "-"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </div>
      )}
      {error && <div className="error-bar">!! {error}</div>}
    </>
  );
}
