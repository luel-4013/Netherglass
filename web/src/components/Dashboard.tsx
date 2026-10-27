import { useCallback, useEffect, useState } from "react";
import {
  emergencyRecover,
  emergencyStop,
  getAudit,
  getConfig,
  getInterfaces,
  getReadiness,
  getStatus,
  logout,
} from "../api";
import type {
  AuditPage,
  ConfigInfo,
  InterfaceInfo,
  Readiness,
  SessionInfo,
  SystemStatus,
} from "../types";
import AuditTail from "./AuditTail";
import TestingPanel from "./TestingPanel";
import CapturePanel from "./CapturePanel";
import PanicDialog from "./PanicDialog";

interface Props {
  session: SessionInfo;
  onOpenPackets: (captureId: string) => void;
  onLogout: () => void;
}

export default function Dashboard({ session, onOpenPackets, onLogout }: Props) {
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [interfaces, setInterfaces] = useState<InterfaceInfo[]>([]);
  const [readiness, setReadiness] = useState<Readiness | null>(null);
  const [config, setConfig] = useState<ConfigInfo | null>(null);
  const [audit, setAudit] = useState<AuditPage | null>(null);
  const [selectedInterface, setSelectedInterface] = useState("");
  const [error, setError] = useState("");
  const [panicOpen, setPanicOpen] = useState(false);
  const [recoverReason, setRecoverReason] = useState("");

  const canViewAudit = session.permissions.includes("VIEW_AUDIT_LOG");
  const canRecover = session.permissions.includes("RECOVER_EMERGENCY_STOP");
  const stopped = status?.emergency.emergency_stopped ?? false;

  const load = useCallback(async () => {
    try {
      const [statusInfo, interfaceInfo, readinessInfo, configInfo] =
        await Promise.all([getStatus(), getInterfaces(), getReadiness(), getConfig()]);
      setStatus(statusInfo);
      setInterfaces(interfaceInfo.interfaces);
      setReadiness(readinessInfo);
      setConfig(configInfo);
      if (canViewAudit) {
        setAudit(await getAudit(50));
      }
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "request failed");
    }
  }, [canViewAudit]);

  useEffect(() => {
    void load();
  }, [load]);

  async function handleLogout() {
    try {
      await logout();
    } catch {
      // session may already be gone; reset the UI anyway
    }
    onLogout();
  }

  async function handleRecover() {
    try {
      await emergencyRecover(recoverReason);
      setRecoverReason("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "recovery failed");
    }
  }

  async function handleStop(reason: string) {
    await emergencyStop(reason);
    setPanicOpen(false);
    await load();
  }

  return (
    <div className="shell">
      <header className="topbar">
        <div className="brand">
          <span className="brand-name">NETHERGLASS</span>
          <span className="brand-sub">
            network visibility :: evidence vault :: internal use only
          </span>
        </div>
        <div className="topbar-right">
          {config && (
            <span className="meta">
              {config.serve.host}:{config.serve.port} · profile {config.profile}
            </span>
          )}
          <span className="meta">
            {session.user?.username} [{session.user?.role}]
          </span>
          <button className="btn" onClick={() => void handleLogout()}>
            [ LOGOUT ]
          </button>
          <button className="btn btn-panic" onClick={() => setPanicOpen(true)}>
            !! EMERGENCY SECURITY STOP
          </button>
        </div>
      </header>

      {stopped && (
        <div className="emergency-banner">
          EMERGENCY SECURITY STOP ACTIVE — capture halted, exports disabled,
          sensitive evidence LOCKED
        </div>
      )}
      {error && <div className="error-bar">!! {error}</div>}

      <main className="grid">
        <section className="panel">
          <h2>INTERFACES</h2>
          <p className="dim">
            Choose the interface to observe. Wi-Fi in managed mode sees this
            host&apos;s traffic and broadcast/multicast only.
          </p>
          <table className="tbl">
            <thead>
              <tr>
                <th></th>
                <th>NAME</th>
                <th>KIND</th>
                <th>STATE</th>
                <th>ADDRESSES</th>
              </tr>
            </thead>
            <tbody>
              {interfaces.map((iface) => (
                <tr
                  key={iface.name}
                  className={selectedInterface === iface.name ? "selected" : ""}
                >
                  <td>
                    <input
                      type="radio"
                      name="interface"
                      checked={selectedInterface === iface.name}
                      onChange={() => setSelectedInterface(iface.name)}
                    />
                  </td>
                  <td>{iface.name}</td>
                  <td>{iface.kind}</td>
                  <td className={iface.operstate === "up" ? "up" : "down"}>
                    {iface.operstate}
                  </td>
                  <td>{iface.addresses.join(", ") || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {selectedInterface && (
            <p className="dim">
              selected: <span className="accent">{selectedInterface}</span> — the
              live capture panel below uses this selection.
            </p>
          )}
        </section>

        <CapturePanel
          session={session}
          selectedInterface={selectedInterface}
          stopped={stopped}
          onOpenPackets={onOpenPackets}
          onError={setError}
        />

        <section className="panel">
          <h2>CAPTURE READINESS</h2>
          <table className="tbl">
            <tbody>
              {readiness?.sources.map((source) => (
                <tr key={source.id}>
                  <td className={source.available ? "up" : "down"}>
                    {source.available ? "[OK]" : "[--]"}
                  </td>
                  <td>{source.label}</td>
                  <td className="dim">{source.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {readiness?.hints.map((hint) => (
            <p className="warn" key={hint}>
              {hint}
            </p>
          ))}
        </section>

        <section className="panel">
          <h2>CAPTURE PROFILE</h2>
          {config?.profiles.map((profile) => (
            <div
              key={profile.id}
              className={`profile ${profile.id === config.profile ? "profile-active" : ""}`}
            >
              <div className="profile-head">
                <span className="accent">
                  [{profile.id}] {profile.name}
                </span>
                {profile.id === config.profile && <span className="badge">ACTIVE</span>}
              </div>
              <div className="dim">{profile.description}</div>
              <div className="dim">
                pcap: {profile.store_pcap ? "yes" : "no"} · payload:{" "}
                {profile.store_payload ? "yes" : "no"} · retention:{" "}
                {profile.retention_hours}h
              </div>
            </div>
          ))}
          {config?.warnings.map((warning) => (
            <p className="warn" key={warning}>
              {warning}
            </p>
          ))}
        </section>

        <section className="panel">
          <h2>EMERGENCY STATE</h2>
          <table className="tbl">
            <tbody>
              <tr>
                <td>CAPTURE</td>
                <td className={stopped ? "down" : "up"}>
                  {status?.emergency.capture ?? "-"}
                </td>
              </tr>
              <tr>
                <td>PROCESSING</td>
                <td>{status?.emergency.processing ?? "-"}</td>
              </tr>
              <tr>
                <td>ACTIVE TESTS</td>
                <td>{status?.emergency.active_tests ?? "-"}</td>
              </tr>
              <tr>
                <td>EXPORTS</td>
                <td>{status?.emergency.exports ?? "-"}</td>
              </tr>
              <tr>
                <td>SENSITIVE EVIDENCE</td>
                <td className={stopped ? "down" : "up"}>
                  {status?.emergency.sensitive_evidence ?? "-"}
                </td>
              </tr>
            </tbody>
          </table>
          {stopped && canRecover && (
            <div className="recover">
              <input
                placeholder="recovery reason (required)"
                value={recoverReason}
                onChange={(event) => setRecoverReason(event.target.value)}
              />
              <button
                className="btn"
                disabled={!recoverReason.trim()}
                onClick={() => void handleRecover()}
              >
                [ AUTHORIZED RECOVERY ]
              </button>
            </div>
          )}
          {stopped && !canRecover && (
            <p className="warn">
              Recovery requires an administrator with RECOVER_EMERGENCY_STOP.
            </p>
          )}
        </section>

        {session.permissions.includes("VIEW_FINDINGS") && (
          <TestingPanel session={session} stopped={stopped} />
        )}

        {canViewAudit && <AuditTail audit={audit} />}
      </main>

      <PanicDialog
        open={panicOpen}
        onClose={() => setPanicOpen(false)}
        onConfirm={handleStop}
      />
    </div>
  );
}
