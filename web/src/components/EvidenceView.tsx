import { Fragment, useCallback, useEffect, useState } from "react";
import { deleteEvidence, getEvidence, revealEvidence } from "../api";
import { fmtTime } from "../format";
import type { EvidencePage } from "../types";

interface Props {
  captureId: string;
  canReveal: boolean;
  canDelete: boolean;
}

interface Revealed {
  id: string;
  value: string;
  source: string | null;
  secondsLeft: number;
}

const ARTIFACT_TYPES = [
  "PASSWORD",
  "BASIC_AUTH",
  "BEARER_TOKEN",
  "ACCESS_TOKEN",
  "SESSION_COOKIE",
  "AUTH_COOKIE",
  "CSRF_TOKEN",
  "JWT",
  "API_KEY",
  "PRIVATE_KEY",
  "CLOUD_CREDENTIAL",
  "PERSONAL_INFORMATION",
  "UNKNOWN_SECRET",
];

export default function EvidenceView({ captureId, canReveal, canDelete }: Props) {
  const [page, setPage] = useState<EvidencePage | null>(null);
  const [artifactType, setArtifactType] = useState("");
  const [target, setTarget] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const [revealed, setRevealed] = useState<Revealed | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);
  const [deleteReason, setDeleteReason] = useState("");

  const load = useCallback(async () => {
    try {
      const data = await getEvidence(captureId, {
        artifactType: artifactType || undefined,
      });
      setPage(data);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed to load evidence");
    }
  }, [captureId, artifactType]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (!revealed) return;
    if (revealed.secondsLeft <= 0) {
      setRevealed(null);
      return;
    }
    const handle = window.setTimeout(
      () =>
        setRevealed((current) =>
          current ? { ...current, secondsLeft: current.secondsLeft - 1 } : null,
        ),
      1000,
    );
    return () => window.clearTimeout(handle);
  }, [revealed]);

  async function confirmReveal() {
    if (!target || reason.trim().length < 4) {
      setError("a reason of at least 4 characters is required to reveal a value");
      return;
    }
    setBusy(true);
    try {
      const result = await revealEvidence(target, reason.trim());
      setRevealed({
        id: result.evidence_id,
        value: result.value,
        source: result.source ?? null,
        secondsLeft: result.auto_hide_seconds,
      });
      setTarget(null);
      setReason("");
      setExpanded(result.evidence_id);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "reveal failed");
    } finally {
      setBusy(false);
    }
  }

  async function confirmDelete() {
    if (!deleteTarget || deleteReason.trim().length < 4) {
      setError("a reason of at least 4 characters is required to delete evidence");
      return;
    }
    setBusy(true);
    try {
      await deleteEvidence(deleteTarget, deleteReason.trim());
      setDeleteTarget(null);
      setDeleteReason("");
      setError("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "delete failed");
    } finally {
      setBusy(false);
    }
  }

  if (error && !page) {
    return <div className="error-bar">!! {error}</div>;
  }

  return (
    <>
      <h2>EVIDENCE VAULT {page ? `(${page.total})` : ""}</h2>
      <p className="dim">
        listings show metadata only. retained values live encrypted at rest and
        are never rendered until an authorized reveal — every reveal requires a
        stated reason and is written to the audit log.
      </p>
      {error && <div className="error-bar">!! {error}</div>}
      {!canReveal && (
        <p className="dim">
          :: your role can view sensitive metadata but not values — reveal
          buttons are disabled
        </p>
      )}
      <div className="filterbar">
        <select
          value={artifactType}
          onChange={(event) => setArtifactType(event.target.value)}
        >
          <option value="">all artifact types</option>
          {ARTIFACT_TYPES.map((item) => (
            <option key={item} value={item}>
              {item}
            </option>
          ))}
        </select>
      </div>
      {page && page.summary.length > 0 && (
        <p className="dim">
          {page.summary
            .map(
              (item) =>
                `${item.artifact_type.toLowerCase()}: ${item.count}` +
                (item.metadata_only ? ` (${item.metadata_only} metadata-only)` : ""),
            )
            .join(" · ")}
        </p>
      )}
      <table className="tbl">
        <thead>
          <tr>
            <th>ID</th>
            <th>TYPE</th>
            <th>FIELD</th>
            <th>FLOW</th>
            <th>HOST / PATH</th>
            <th>TRANSPORT</th>
            <th>STATUS</th>
            <th>SEEN</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {page?.artifacts.map((artifact) => (
            <Fragment key={artifact.id}>
              <tr
                className={expanded === artifact.id ? "selected" : ""}
                style={{ cursor: "pointer" }}
                onClick={() =>
                  setExpanded(expanded === artifact.id ? null : artifact.id)
                }
              >
                <td className="mono-small">{artifact.id}</td>
                <td className="accent">{artifact.artifact_type}</td>
                <td>{artifact.field ?? "-"}</td>
                <td>
                  {artifact.src ?? "-"}
                  {artifact.sport ? `:${artifact.sport}` : ""} →{" "}
                  {artifact.dst ?? "-"}
                  {artifact.dport ? `:${artifact.dport}` : ""}
                </td>
                <td className="dim">
                  {artifact.host ?? artifact.domain ?? "-"}
                  {artifact.path ?? ""}
                </td>
                <td
                  className={
                    artifact.transport_security === "plaintext" ? "warn" : "dim"
                  }
                >
                  {artifact.transport_security ?? "-"}
                </td>
                <td className={artifact.status === "SEALED" ? "" : "dim"}>
                  {artifact.status}
                </td>
                <td className="mono-small">{fmtTime(artifact.ts)}</td>
                <td>
                  {artifact.status === "SEALED" ? (
                    <button
                      className="btn btn-small"
                      disabled={!canReveal || busy}
                      title={
                        canReveal
                          ? "reveal (audited)"
                          : "requires VIEW_SENSITIVE_VALUES"
                      }
                      onClick={(event) => {
                        event.stopPropagation();
                        setTarget(target === artifact.id ? null : artifact.id);
                        setReason("");
                      }}
                    >
                      [ REVEAL ]
                    </button>
                  ) : (
                    <span className="dim">[ NO VALUE ]</span>
                  )}
                  {artifact.status === "SEALED" && canDelete && (
                    <>
                      {" "}
                      <button
                        className="btn btn-small btn-panic"
                        disabled={busy}
                        title="best-effort secure deletion (zero-overwrite + unlink), audited"
                        onClick={(event) => {
                          event.stopPropagation();
                          setDeleteTarget(
                            deleteTarget === artifact.id ? null : artifact.id,
                          );
                          setDeleteReason("");
                        }}
                      >
                        [ DELETE ]
                      </button>
                    </>
                  )}
                </td>
              </tr>
              {target === artifact.id && revealed?.id !== artifact.id && (
                <tr className="detail-row">
                  <td colSpan={9}>
                    <div className="reveal-bar">
                      <span className="warn">
                        revealing {artifact.id} writes to the audit log ·
                      </span>{" "}
                      <input
                        placeholder="reason (required, recorded in audit)"
                        value={reason}
                        maxLength={400}
                        onChange={(event) => setReason(event.target.value)}
                        onClick={(event) => event.stopPropagation()}
                      />{" "}
                      <button
                        className="btn btn-small"
                        disabled={busy}
                        onClick={(event) => {
                          event.stopPropagation();
                          void confirmReveal();
                        }}
                      >
                        {busy ? "[ ... ]" : "[ CONFIRM REVEAL ]"}
                      </button>{" "}
                      <button
                        className="btn btn-small"
                        onClick={(event) => {
                          event.stopPropagation();
                          setTarget(null);
                        }}
                      >
                        [ CANCEL ]
                      </button>
                    </div>
                  </td>
                </tr>
              )}
              {deleteTarget === artifact.id && (
                <tr className="detail-row">
                  <td colSpan={9}>
                    <div className="reveal-bar">
                      <span className="warn">
                        secure deletion of {artifact.id} destroys the encrypted
                        blob and writes to the audit log ·
                      </span>{" "}
                      <input
                        placeholder="reason (required, recorded in audit)"
                        value={deleteReason}
                        maxLength={400}
                        onChange={(event) => setDeleteReason(event.target.value)}
                        onClick={(event) => event.stopPropagation()}
                      />{" "}
                      <button
                        className="btn btn-small btn-panic"
                        disabled={busy}
                        onClick={(event) => {
                          event.stopPropagation();
                          void confirmDelete();
                        }}
                      >
                        {busy ? "[ ... ]" : "[ CONFIRM DELETE ]"}
                      </button>{" "}
                      <button
                        className="btn btn-small"
                        onClick={(event) => {
                          event.stopPropagation();
                          setDeleteTarget(null);
                        }}
                      >
                        [ CANCEL ]
                      </button>
                    </div>
                  </td>
                </tr>
              )}
              {expanded === artifact.id && (
                <tr className="detail-row">
                  <td colSpan={9}>
                    <p className="dim">
                      rule of record: confidence {artifact.confidence} · stream{" "}
                      {artifact.stream ?? "-"} · frame {artifact.frame ?? "-"} ·
                      sha256 {artifact.sha256?.slice(0, 16) ?? "-"} ·{" "}
                      {artifact.size ?? 0} bytes
                    </p>
                    {artifact.meta && (
                      <p className="mono-small dim">meta: {artifact.meta}</p>
                    )}
                    {revealed?.id === artifact.id ? (
                      <div className="reveal-box">
                        <div>
                          <span className="warn">VALUE (audited reveal):</span>{" "}
                          <span className="reveal-value">{revealed.value}</span>
                        </div>
                        <div className="dim">
                          {revealed.source ? `source: ${revealed.source} · ` : ""}
                          auto-hides in {revealed.secondsLeft}s ·{" "}
                          <button
                            className="btn btn-small"
                            onClick={(event) => {
                              event.stopPropagation();
                              setRevealed(null);
                            }}
                          >
                            [ HIDE NOW ]
                          </button>
                        </div>
                      </div>
                    ) : (
                      <p className="dim">
                        value: sealed — reveal to display (audited)
                      </p>
                    )}
                  </td>
                </tr>
              )}
            </Fragment>
          ))}
          {page && page.artifacts.length === 0 && (
            <tr>
              <td colSpan={9} className="dim">
                no sensitive artifacts detected in this capture — detection runs
                automatically during decode
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </>
  );
}
