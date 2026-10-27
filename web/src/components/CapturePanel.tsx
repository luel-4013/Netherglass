import { useCallback, useEffect, useRef, useState } from "react";
import {
  captureStart,
  captureStop,
  getCaptureStatus,
  getCaptures,
  importFlowlogs,
  importPcap,
} from "../api";
import type { CaptureStatus, CaptureSummary, SessionInfo } from "../types";

interface Props {
  session: SessionInfo;
  selectedInterface: string;
  stopped: boolean;
  onOpenPackets: (captureId: string) => void;
  onError: (message: string) => void;
}

function fmtBytes(bytes: number): string {
  if (bytes >= 1024 ** 3) return `${(bytes / 1024 ** 3).toFixed(2)} GiB`;
  if (bytes >= 1024 ** 2) return `${(bytes / 1024 ** 2).toFixed(1)} MiB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${bytes} B`;
}

export default function CapturePanel({
  session,
  selectedInterface,
  stopped,
  onOpenPackets,
  onError,
}: Props) {
  const [status, setStatus] = useState<CaptureStatus | null>(null);
  const [captures, setCaptures] = useState<CaptureSummary[]>([]);
  const [bpf, setBpf] = useState("");
  const [stopReason, setStopReason] = useState("");
  const [importPath, setImportPath] = useState("");
  const [flowlogPath, setFlowlogPath] = useState("");
  const [flowlogFormat, setFlowlogFormat] = useState("auto");
  const [busy, setBusy] = useState(false);
  const timer = useRef<number | null>(null);

  const canControl = session.permissions.includes("CONTROL_CAPTURE");

  const refresh = useCallback(async () => {
    try {
      const [captureStatus, listings] = await Promise.all([
        getCaptureStatus(),
        getCaptures(20),
      ]);
      setStatus(captureStatus);
      setCaptures(listings.captures);
    } catch (err) {
      onError(err instanceof Error ? err.message : "capture status failed");
    }
  }, [onError]);

  useEffect(() => {
    void refresh();
    timer.current = window.setInterval(() => void refresh(), 2000);
    return () => {
      if (timer.current !== null) window.clearInterval(timer.current);
    };
  }, [refresh]);

  async function guard(action: () => Promise<void>) {
    setBusy(true);
    try {
      await action();
      await refresh();
    } catch (err) {
      onError(err instanceof Error ? err.message : "capture operation failed");
    } finally {
      setBusy(false);
    }
  }

  const active = status?.active ?? false;

  return (
    <section className="panel">
      <h2>LIVE CAPTURE</h2>
      {!canControl && (
        <p className="dim">Your role can view captures but not control them.</p>
      )}
      {canControl && !active && (
        <div className="capture-form">
          <div className="dim">
            interface:{" "}
            <span className="accent">{selectedInterface || "(select above)"}</span>{" "}
            · near-live: decoded in {`~5s`} chunks, drops always shown
          </div>
          <input
            placeholder="extra BPF filter (optional, e.g. tcp port 443)"
            value={bpf}
            onChange={(event) => setBpf(event.target.value)}
          />
          <button
            className="btn"
            disabled={busy || !selectedInterface || stopped}
            onClick={() =>
              void guard(async () => {
                await captureStart(selectedInterface, bpf);
              })
            }
          >
            [ START CAPTURE ]
          </button>
        </div>
      )}

      {active && (
        <div className="capture-live">
          <div className="capture-live-head">
            <span className="blink-dot">●</span> REC{" "}
            <span className="accent">{status?.capture_id}</span> on{" "}
            {status?.interface} via {status?.source} ·{" "}
            {status?.elapsed_seconds ?? 0}s
          </div>
          <table className="tbl">
            <tbody>
              <tr>
                <td>packets captured</td>
                <td className="up">{status?.packets_captured ?? 0}</td>
                <td>kernel drops</td>
                <td className={status?.packets_dropped ? "warn" : "up"}>
                  {status?.packets_dropped ?? 0}
                </td>
              </tr>
              <tr>
                <td>decoded</td>
                <td className="up">{status?.packets_decoded ?? 0}</td>
                <td>decode drops (queue)</td>
                <td className={status?.decode_drops ? "warn" : "up"}>
                  {status?.decode_drops ?? 0}
                </td>
              </tr>
              <tr>
                <td>queue depth</td>
                <td>{status?.queue_depth ?? 0}</td>
                <td>bytes on disk</td>
                <td>{fmtBytes(status?.bytes_written ?? 0)}</td>
              </tr>
            </tbody>
          </table>
          {status?.last_error && <p className="warn">source: {status.last_error}</p>}
          {canControl && (
            <div className="recover">
              <input
                placeholder="stop reason (optional)"
                value={stopReason}
                onChange={(event) => setStopReason(event.target.value)}
              />
              <button
                className="btn"
                disabled={busy}
                onClick={() =>
                  void guard(async () => {
                    await captureStop(stopReason);
                    setStopReason("");
                  })
                }
              >
                [ STOP CAPTURE ]
              </button>
            </div>
          )}
        </div>
      )}

      {canControl && (
        <div className="capture-form">
          <div className="dim">
            TELEMETRY IMPORT — cloud flow logs (AWS VPC / Azure NSG / GCP / CSV /
            JSON). Metadata only; no packets or payloads are created.
          </div>
          <input
            placeholder="/path/to/vpc-flow.log (on this server)"
            value={flowlogPath}
            onChange={(event) => setFlowlogPath(event.target.value)}
          />
          <select
            value={flowlogFormat}
            onChange={(event) => setFlowlogFormat(event.target.value)}
          >
            {["auto", "aws", "azure", "gcp", "generic-json", "generic-csv"].map(
              (fmt) => (
                <option key={fmt} value={fmt}>
                  {fmt}
                </option>
              ),
            )}
          </select>
          <button
            className="btn"
            disabled={busy || !flowlogPath.trim() || stopped}
            onClick={() =>
              void guard(async () => {
                const result = await importFlowlogs(
                  flowlogPath.trim(),
                  flowlogFormat,
                );
                setFlowlogPath("");
                onOpenPackets(result.capture_id);
              })
            }
          >
            [ IMPORT FLOW LOG ]
          </button>
        </div>
      )}

      {canControl && (
        <div className="capture-form">
          <div className="dim">
            OFFLINE IMPORT — copy a PCAP/PCAPNG from this server, hash it
            (sha256), decode it. Always available.
          </div>
          <input
            placeholder="/path/to/capture.pcapng (on this server)"
            value={importPath}
            onChange={(event) => setImportPath(event.target.value)}
          />
          <button
            className="btn"
            disabled={busy || !importPath.trim() || stopped}
            onClick={() =>
              void guard(async () => {
                const result = await importPcap(importPath.trim());
                setImportPath("");
                onOpenPackets(result.capture_id);
              })
            }
          >
            [ IMPORT + DECODE ]
          </button>
        </div>
      )}

      <h2 className="section-gap">CAPTURES</h2>
      <table className="tbl">
        <thead>
          <tr>
            <th>ID</th>
            <th>SRC</th>
            <th>STATUS</th>
            <th>PACKETS</th>
            <th>DROPS</th>
            <th>SIZE</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {captures.map((capture) => (
            <tr key={capture.id}>
              <td className="mono-small">{capture.id}</td>
              <td>{capture.source}</td>
              <td className={capture.status === "error" ? "warn" : "up"}>
                {capture.status}
              </td>
              <td>{capture.packets_captured}</td>
              <td className={capture.packets_dropped ? "warn" : ""}>
                {capture.packets_dropped}
                {capture.decode_drops ? `+${capture.decode_drops}d` : ""}
              </td>
              <td>{fmtBytes(capture.bytes_written)}</td>
              <td>
                <button className="btn btn-small" onClick={() => onOpenPackets(capture.id)}>
                  [ OPEN ]
                </button>
              </td>
            </tr>
          ))}
          {captures.length === 0 && (
            <tr>
              <td colSpan={7} className="dim">
                no captures yet
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </section>
  );
}
