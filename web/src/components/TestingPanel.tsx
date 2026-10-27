import { useCallback, useEffect, useState } from "react";
import {
  abortControlledTest,
  createControlledTest,
  executeControlledTest,
  getControlledTest,
  getControlledTests,
  getTestingScope,
} from "../api";
import type { ControlledTestRow, SessionInfo, TestingScope } from "../types";

interface Props {
  session: SessionInfo;
  stopped: boolean;
}

const TEST_TYPES = [
  "TCP_CONNECT",
  "TLS_HANDSHAKE",
  "HTTP_PROBE",
  "SESSION_COOKIE_CHECK",
  "BEARER_TOKEN_CHECK",
];

export default function TestingPanel({ session, stopped }: Props) {
  const [scope, setScope] = useState<TestingScope | null>(null);
  const [tests, setTests] = useState<ControlledTestRow[]>([]);
  const [expanded, setExpanded] = useState<ControlledTestRow | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [confirming, setConfirming] = useState<string | null>(null);
  const [confirmText, setConfirmText] = useState("");

  const [authRef, setAuthRef] = useState("");
  const [target, setTarget] = useState("");
  const [testType, setTestType] = useState("TCP_CONNECT");
  const [port, setPort] = useState("");
  const [artifact, setArtifact] = useState("");
  const [caseId, setCaseId] = useState("");
  const [dryRun, setDryRun] = useState(true);
  const [maxRequests, setMaxRequests] = useState("5");
  const [rateLimit, setRateLimit] = useState("1000");
  const [timeoutMs, setTimeoutMs] = useState("5000");

  const canCreate = session.permissions.includes("CREATE_CONTROLLED_TEST");
  const canExecute = session.permissions.includes("EXECUTE_CONTROLLED_TEST");

  const load = useCallback(async () => {
    try {
      const [scopeData, testsData] = await Promise.all([
        getTestingScope(),
        getControlledTests(),
      ]);
      setScope(scopeData);
      setTests(testsData.tests);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed to load tests");
    }
  }, []);

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => void load(), 3000);
    return () => window.clearInterval(timer);
  }, [load]);

  async function handleCreate() {
    setBusy(true);
    setNotice("");
    try {
      const created = await createControlledTest({
        authorization_ref: authRef.trim(),
        target: target.trim(),
        test_type: testType,
        port: port.trim() ? Number(port) : null,
        artifact_id: artifact.trim() || null,
        case_id: caseId.trim() || null,
        dry_run: dryRun,
        max_requests: Number(maxRequests) || 5,
        rate_limit_ms: Number(rateLimit) || 1000,
        timeout_ms: Number(timeoutMs) || 5000,
      });
      setNotice(
        `planned ${created.id} (${created.test_type} → ${created.target}) — ` +
          `${created.dry_run ? "dry run" : "live"}`,
      );
      setTarget("");
      setArtifact("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "create failed");
    } finally {
      setBusy(false);
    }
  }

  async function handleExecute(testId: string) {
    setBusy(true);
    setError("");
    try {
      await executeControlledTest(testId, confirmText.trim());
      setConfirming(null);
      setConfirmText("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "execute failed");
    } finally {
      setBusy(false);
    }
  }

  async function handleAbort(testId: string) {
    try {
      await abortControlledTest(testId);
      setNotice(`abort requested for ${testId}`);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "abort failed");
    }
  }

  async function toggleDetail(testId: string) {
    if (expanded?.id === testId) {
      setExpanded(null);
      return;
    }
    try {
      setExpanded(await getControlledTest(testId));
    } catch (err) {
      setError(err instanceof Error ? err.message : "detail failed");
    }
  }

  const activeAssessments = scope?.assessments.filter((item) => item.active) ?? [];

  return (
    <section className="panel">
      <h2>CONTROLLED TESTING — ACTIVE VALIDATION</h2>
      <p className="dim">
        separate subsystem: sends traffic to an authorized target only. every
        run needs an active assessment in testing_scope.json, is rate-limited
        and bounded, and is audited. dry run is the default; captured secret
        values are never written to results or audit.
      </p>
      {error && <div className="error-bar">!! {error}</div>}
      {notice && <div className="ok-bar">{notice}</div>}

      {scope && !scope.configured && (
        <div className="warn">
          scope not configured — all controlled tests are refused (fail
          closed). {scope.error}
        </div>
      )}
      {scope?.configured && (
        <table className="tbl">
          <thead>
            <tr>
              <th>ASSESSMENT</th>
              <th>AUTH REF</th>
              <th>DOMAINS / CIDRS</th>
              <th>PORTS</th>
              <th>WINDOW</th>
              <th>STATE</th>
            </tr>
          </thead>
          <tbody>
            {scope.assessments.map((item) => (
              <tr key={item.id}>
                <td>{item.name}</td>
                <td className="accent">{item.authorization_ref}</td>
                <td className="mono-small">
                  {[...item.domains, ...item.cidrs].join(", ") || "-"}
                  {item.excluded_cidrs.length > 0 &&
                    ` (excl: ${item.excluded_cidrs.join(", ")})`}
                </td>
                <td>{item.ports.length ? item.ports.join(", ") : "any"}</td>
                <td className="dim mono-small">
                  {item.window_start ?? "-"} → {item.window_end ?? "-"}
                </td>
                <td className={item.active ? "up" : "dim"}>
                  {item.active ? "ACTIVE" : "INACTIVE"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {canCreate && (
        <div className="capture-form">
          <div className="dim">
            NEW TEST PLAN — {activeAssessments.length} active assessment(s)
          </div>
          <div className="filterbar">
            <select value={authRef} onChange={(e) => setAuthRef(e.target.value)}>
              <option value="">select authorization…</option>
              {activeAssessments.map((item) => (
                <option key={item.id} value={item.authorization_ref}>
                  {item.authorization_ref} — {item.name}
                </option>
              ))}
            </select>
            <select value={testType} onChange={(e) => setTestType(e.target.value)}>
              {TEST_TYPES.map((type) => (
                <option key={type} value={type}>
                  {type}
                </option>
              ))}
            </select>
            <input
              placeholder="target host or IP"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            />
            <input
              placeholder="port"
              value={port}
              onChange={(e) => setPort(e.target.value)}
            />
            {(testType === "SESSION_COOKIE_CHECK" ||
              testType === "BEARER_TOKEN_CHECK") && (
              <input
                placeholder="evidence id (EVD-…)"
                value={artifact}
                onChange={(e) => setArtifact(e.target.value)}
              />
            )}
            <input
              placeholder="case id (optional)"
              value={caseId}
              onChange={(e) => setCaseId(e.target.value)}
            />
          </div>
          <div className="filterbar">
            <label className="dim">
              <input
                type="checkbox"
                checked={dryRun}
                onChange={(e) => setDryRun(e.target.checked)}
              />{" "}
              dry run (preview, no traffic)
            </label>
            <input
              placeholder="max requests"
              value={maxRequests}
              onChange={(e) => setMaxRequests(e.target.value)}
            />
            <input
              placeholder="rate limit ms"
              value={rateLimit}
              onChange={(e) => setRateLimit(e.target.value)}
            />
            <input
              placeholder="timeout ms"
              value={timeoutMs}
              onChange={(e) => setTimeoutMs(e.target.value)}
            />
            <button
              className="btn btn-small"
              disabled={busy || !authRef || !target.trim() || stopped}
              onClick={() => void handleCreate()}
            >
              [ PLAN TEST ]
            </button>
          </div>
        </div>
      )}

      <table className="tbl">
        <thead>
          <tr>
            <th>ID</th>
            <th>TYPE</th>
            <th>TARGET</th>
            <th>AUTH REF</th>
            <th>MODE</th>
            <th>STATUS</th>
            <th>REQS</th>
            <th>CREATED BY</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {tests.map((test) => (
            <tr key={test.id}>
              <td className="accent">{test.id}</td>
              <td>{test.test_type}</td>
              <td className="mono-small">
                {test.target}
                {test.port ? `:${test.port}` : ""}
              </td>
              <td className="dim">{test.authorization_ref}</td>
              <td className={test.dry_run ? "dim" : "warn"}>
                {test.dry_run ? "DRY RUN" : "LIVE"}
              </td>
              <td
                className={
                  test.status === "COMPLETED" || test.status === "DRY_RUN"
                    ? "up"
                    : test.status === "EXECUTING"
                      ? "warn"
                      : test.status === "REFUSED" || test.status === "FAILED"
                        ? "down"
                        : "dim"
                }
              >
                {test.status}
              </td>
              <td>{test.request_count}</td>
              <td className="dim">{test.created_by}</td>
              <td>
                <button
                  className="btn btn-small"
                  onClick={() => void toggleDetail(test.id)}
                >
                  [ DETAIL ]
                </button>{" "}
                {canExecute && test.status !== "EXECUTING" && test.status !== "REFUSED" && (
                  <button
                    className="btn btn-small"
                    disabled={stopped || busy}
                    onClick={() => {
                      setConfirming(test.id);
                      setConfirmText("");
                    }}
                  >
                    [ AUTHORIZE TEST ]
                  </button>
                )}
                {canExecute && test.status === "EXECUTING" && (
                  <button
                    className="btn btn-small btn-panic"
                    onClick={() => void handleAbort(test.id)}
                  >
                    [ ABORT ]
                  </button>
                )}
              </td>
            </tr>
          ))}
          {tests.length === 0 && (
            <tr>
              <td colSpan={9} className="dim">
                no controlled tests planned yet
              </td>
            </tr>
          )}
        </tbody>
      </table>

      {confirming && (
        <div className="recover">
          <p className="warn">
            This operation sends requests to the configured target. Type the
            confirmation phrase to authorize.
          </p>
          <input
            placeholder='type "AUTHORIZE TEST" exactly'
            value={confirmText}
            onChange={(e) => setConfirmText(e.target.value)}
          />
          <button
            className="btn"
            disabled={busy || confirmText.trim() !== "AUTHORIZE TEST"}
            onClick={() => void handleExecute(confirming)}
          >
            [ AUTHORIZE TEST ]
          </button>
          <button
            className="btn btn-small"
            onClick={() => {
              setConfirming(null);
              setConfirmText("");
            }}
          >
            [ CANCEL ]
          </button>
        </div>
      )}

      {expanded && (
        <section className="panel">
          <h2>
            {expanded.id} — {expanded.test_type} → {expanded.target}
            {expanded.port ? `:${expanded.port}` : ""}
          </h2>
          {expanded.error && <div className="error-bar">!! {expanded.error}</div>}
          <table className="tbl">
            <thead>
              <tr>
                <th>#</th>
                <th>TIME</th>
                <th>KIND</th>
                <th>METHOD</th>
                <th>STATUS</th>
                <th>OUTCOME</th>
                <th>DETAIL</th>
                <th>MS</th>
              </tr>
            </thead>
            <tbody>
              {(expanded.results ?? []).map((row) => (
                <tr key={row.id}>
                  <td>{row.seq}</td>
                  <td className="mono-small">{row.ts}</td>
                  <td className="accent">{row.request_kind}</td>
                  <td>{row.method ?? "-"}</td>
                  <td>{row.status_code ?? "-"}</td>
                  <td className={row.outcome === "OK" ? "up" : "dim"}>
                    {row.outcome}
                  </td>
                  <td className="dim">{row.detail ?? "-"}</td>
                  <td>{row.duration_ms ?? "-"}</td>
                </tr>
              ))}
              {(expanded.results ?? []).length === 0 && (
                <tr>
                  <td colSpan={8} className="dim">
                    no results yet
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </section>
      )}
    </section>
  );
}
