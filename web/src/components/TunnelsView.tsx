import { useEffect, useState } from "react";
import { getTunnels } from "../api";
import type { TunnelRow } from "../types";

interface Props {
  captureId: string;
}

function fmtBytes(bytes: number): string {
  if (bytes >= 1024 ** 2) return `${(bytes / 1024 ** 2).toFixed(1)} MiB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${bytes} B`;
}

function fmtDuration(seconds: number | null): string {
  if (seconds === null) return "-";
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  return `${(seconds / 3600).toFixed(1)}h`;
}

const PROTO_LABEL: Record<string, string> = {
  "ipsec-esp": "IPsec ESP",
  "ipsec-ah": "IPsec AH",
  "ipsec-ike": "IPsec IKE",
  wireguard: "WireGuard",
  openvpn: "OpenVPN",
  gre: "GRE",
  "ip-in-ip": "IP-in-IP",
  ipcomp: "IPComp",
  vxlan: "VXLAN",
};

export default function TunnelsView({ captureId }: Props) {
  const [tunnels, setTunnels] = useState<TunnelRow[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    getTunnels(captureId)
      .then((data) => setTunnels(data.tunnels))
      .catch((err) =>
        setError(err instanceof Error ? err.message : "failed to load tunnels"),
      );
  }, [captureId]);

  return (
    <>
      <h2>VPN / TUNNEL ANALYSIS</h2>
      <p className="dim">
        observed tunnel and encapsulation traffic. inner traffic of encrypted
        tunnels is only visible if the capture point provided it; this view does
        not assume that.
      </p>
      {error && <div className="error-bar">!! {error}</div>}
      <table className="tbl">
        <thead>
          <tr>
            <th>PROTOCOL</th>
            <th>LOCAL</th>
            <th>REMOTE</th>
            <th>PORT</th>
            <th>STATE</th>
            <th>INNER</th>
            <th>PACKETS</th>
            <th>BYTES</th>
            <th>DURATION</th>
          </tr>
        </thead>
        <tbody>
          {tunnels.map((tunnel, index) => (
            <tr key={`${tunnel.tunnel_proto}-${tunnel.src}-${index}`}>
              <td className="accent">
                {PROTO_LABEL[tunnel.tunnel_proto] ?? tunnel.tunnel_proto}
              </td>
              <td className="mono-small">{tunnel.src}</td>
              <td className="mono-small">{tunnel.dst}</td>
              <td>{tunnel.dport || tunnel.sport || "-"}</td>
              <td className={tunnel.state === "HANDSHAKE" ? "warn" : "dim"}>
                {tunnel.state}
              </td>
              <td className={tunnel.inner_visible ? "warn" : "dim"}>
                {tunnel.inner_visible ? "visible" : "opaque"}
              </td>
              <td>{tunnel.packets}</td>
              <td>{fmtBytes(tunnel.bytes)}</td>
              <td>{fmtDuration(tunnel.duration)}</td>
            </tr>
          ))}
          {tunnels.length === 0 && (
            <tr>
              <td colSpan={9} className="dim">
                no tunnel traffic observed in this capture
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </>
  );
}
