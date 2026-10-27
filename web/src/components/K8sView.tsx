import { useCallback, useEffect, useState } from "react";
import { getK8sCorrelation, getK8sEntities, importK8s } from "../api";
import type { K8sCorrelation, K8sEntity } from "../types";

interface Props {
  captureId: string;
}

export default function K8sView({ captureId }: Props) {
  const [entities, setEntities] = useState<K8sEntity[]>([]);
  const [correlation, setCorrelation] = useState<K8sCorrelation | null>(null);
  const [inventoryPath, setInventoryPath] = useState("");
  const [label, setLabel] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const [entityData, correlationData] = await Promise.all([
        getK8sEntities(),
        getK8sCorrelation(captureId),
      ]);
      setEntities(entityData.entities);
      setCorrelation(correlationData);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed to load k8s data");
    }
  }, [captureId]);

  useEffect(() => {
    void load();
  }, [load]);

  async function handleImport() {
    if (!inventoryPath.trim()) return;
    setBusy(true);
    setNotice("");
    try {
      const result = await importK8s({
        path: inventoryPath.trim(),
        label: label.trim() || undefined,
      });
      setNotice(
        `imported ${result.entities} entities (pods ${result.pod}, services ` +
          `${result.service}, nodes ${result.node}, namespaces ${result.namespace})`,
      );
      setInventoryPath("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "import failed");
    } finally {
      setBusy(false);
    }
  }

  const podFlows = correlation?.flows.filter((f) => f.src_pod || f.dst_pod) ?? [];

  return (
    <>
      <h2>KUBERNETES CORRELATION</h2>
      <p className="dim">
        pod IPs are matched against observed flows using an imported inventory
        (kubectl get pods/nodes/services -o json). correlation is observational;
        pod IPs can be reused.
      </p>
      {error && <div className="error-bar">!! {error}</div>}
      {notice && <div className="ok-bar">{notice}</div>}

      <div className="filterbar">
        <input
          placeholder="inventory JSON path (e.g. kubectl dump saved on this server)"
          value={inventoryPath}
          onChange={(event) => setInventoryPath(event.target.value)}
        />
        <input
          placeholder="cluster label (optional)"
          value={label}
          onChange={(event) => setLabel(event.target.value)}
        />
        <button
          className="btn btn-small"
          disabled={busy || !inventoryPath.trim()}
          onClick={() => void handleImport()}
        >
          [ IMPORT INVENTORY ]
        </button>
      </div>

      {correlation && (
        <>
          <p className="dim">
            pods known: {correlation.pods_known} · matched flows:{" "}
            {correlation.matched}/{correlation.total}
          </p>
          <table className="tbl">
            <thead>
              <tr>
                <th>SRC</th>
                <th>SRC POD</th>
                <th>DST</th>
                <th>DST POD</th>
                <th>SERVICE PATH</th>
                <th>PROTO</th>
                <th>PORT</th>
                <th>PACKETS</th>
                <th>BYTES</th>
              </tr>
            </thead>
            <tbody>
              {podFlows.map((flow, index) => (
                <tr key={index}>
                  <td className="mono-small">{flow.src}</td>
                  <td className={flow.src_pod ? "accent" : "dim"}>
                    {flow.src_pod
                      ? `${flow.src_pod.namespace}/${flow.src_pod.name}` +
                        (flow.src_pod.node ? ` @${flow.src_pod.node}` : "")
                      : "-"}
                  </td>
                  <td className="mono-small">{flow.dst}</td>
                  <td className={flow.dst_pod ? "accent" : "dim"}>
                    {flow.dst_pod
                      ? `${flow.dst_pod.namespace}/${flow.dst_pod.name}` +
                        (flow.dst_pod.node ? ` @${flow.dst_pod.node}` : "")
                      : "-"}
                  </td>
                  <td className="dim">
                    {(flow.dst_services.length
                      ? flow.dst_services
                      : flow.src_services
                    )
                      .map((service) => `${service.namespace}/${service.name}`)
                      .join(", ") || "-"}
                  </td>
                  <td>{flow.proto}</td>
                  <td>{flow.dport || "-"}</td>
                  <td>{flow.packets}</td>
                  <td>{flow.bytes}</td>
                </tr>
              ))}
              {podFlows.length === 0 && (
                <tr>
                  <td colSpan={9} className="dim">
                    no flows matched known pod IPs in this capture
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </>
      )}

      <h2 className="section-gap">CLUSTER INVENTORY</h2>
      <table className="tbl">
        <thead>
          <tr>
            <th>KIND</th>
            <th>NAMESPACE</th>
            <th>NAME</th>
            <th>NODE</th>
            <th>IP</th>
            <th>PORTS</th>
            <th>LABELS</th>
          </tr>
        </thead>
        <tbody>
          {entities.map((entity) => (
            <tr key={entity.id}>
              <td className="accent">{entity.kind}</td>
              <td>{entity.namespace || "-"}</td>
              <td>{entity.name}</td>
              <td className="dim">{entity.node ?? "-"}</td>
              <td className="mono-small">{entity.ip ?? "-"}</td>
              <td className="dim">{entity.ports ?? "-"}</td>
              <td className="dim mono-small">{entity.labels ?? "-"}</td>
            </tr>
          ))}
          {entities.length === 0 && (
            <tr>
              <td colSpan={7} className="dim">
                no inventory imported yet
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </>
  );
}
