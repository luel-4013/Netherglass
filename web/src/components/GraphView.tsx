import { useCallback, useEffect, useState } from "react";
import { getGraph } from "../api";
import type { GraphPage } from "../types";

interface Props {
  captureId: string;
}

type Mode = "network" | "connection";

const KIND_CLASS: Record<string, string> = {
  host: "graph-host",
  domain: "graph-domain",
  tls: "graph-tls",
  http: "graph-http",
  finding: "graph-finding",
};

export default function GraphView({ captureId }: Props) {
  const [mode, setMode] = useState<Mode>("network");
  const [graph, setGraph] = useState<GraphPage | null>(null);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      setGraph(await getGraph(captureId, mode));
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed to load graph");
    }
  }, [captureId, mode]);

  useEffect(() => {
    void load();
  }, [load]);

  const nodesById = new Map((graph?.nodes ?? []).map((node) => [node.id, node]));
  const degree = new Map<string, number>();
  for (const edge of graph?.edges ?? []) {
    degree.set(edge.source, (degree.get(edge.source) ?? 0) + 1);
    degree.set(edge.target, (degree.get(edge.target) ?? 0) + 1);
  }
  const ranked = [...(graph?.nodes ?? [])].sort(
    (a, b) => (degree.get(b.id) ?? 0) - (degree.get(a.id) ?? 0),
  );

  return (
    <>
      <h2>NETWORK GRAPH</h2>
      <p className="dim">
        adjacency listing of observed hosts, domains, TLS sessions, endpoints and
        findings. rendered as ranked rows to stay readable in a terminal-style UI.
      </p>
      {error && <div className="error-bar">!! {error}</div>}
      <div className="filterbar">
        <button
          className={`btn btn-small ${mode === "network" ? "btn-active" : ""}`}
          onClick={() => setMode("network")}
        >
          [ NETWORK ]
        </button>
        <button
          className={`btn btn-small ${mode === "connection" ? "btn-active" : ""}`}
          onClick={() => setMode("connection")}
        >
          [ CONNECTIONS ]
        </button>
        <span className="dim">
          {graph ? `${graph.nodes.length} nodes · ${graph.edges.length} edges` : ""}
          {graph?.truncated ? " · truncated" : ""}
        </span>
      </div>
      <table className="tbl">
        <thead>
          <tr>
            <th>NODE</th>
            <th>KIND</th>
            <th>DETAIL</th>
            <th>DEGREE</th>
            <th>CONNECTED TO</th>
          </tr>
        </thead>
        <tbody>
          {ranked.map((node) => {
            const neighbours = (graph?.edges ?? [])
              .filter((edge) => edge.source === node.id || edge.target === node.id)
              .slice(0, 8)
              .map((edge) => {
                const otherId =
                  edge.source === node.id ? edge.target : edge.source;
                const other = nodesById.get(otherId);
                return `${other?.label ?? otherId} (${edge.kind})`;
              });
            return (
              <tr key={node.id}>
                <td className={KIND_CLASS[node.kind] ?? "accent"}>{node.label}</td>
                <td className="dim">{node.kind}</td>
                <td className="mono-small dim">
                  {node.kind === "host" && node.internal === false
                    ? "external"
                    : node.severity
                      ? node.severity
                      : node.security
                        ? node.security
                        : node.mac
                          ? node.mac
                          : "-"}
                </td>
                <td>{degree.get(node.id) ?? 0}</td>
                <td className="dim mono-small">{neighbours.join(" · ") || "-"}</td>
              </tr>
            );
          })}
          {graph && graph.nodes.length === 0 && (
            <tr>
              <td colSpan={5} className="dim">
                no graph data yet
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </>
  );
}
