import { useCallback, useEffect, useState } from "react";
import { getHttpEvents } from "../api";
import { fmtTime, parseJsonList } from "../format";
import type { HttpPage } from "../types";

interface Props {
  captureId: string;
}

const PAGE_SIZE = 200;

export default function HttpView({ captureId }: Props) {
  const [page, setPage] = useState<HttpPage | null>(null);
  const [host, setHost] = useState("");
  const [method, setMethod] = useState("");
  const [status, setStatus] = useState("");
  const [kind, setKind] = useState("");
  const [offset, setOffset] = useState(0);
  const [error, setError] = useState("");

  const load = useCallback(
    async (nextOffset = offset) => {
      try {
        const data = await getHttpEvents(captureId, {
          host: host || undefined,
          method: method || undefined,
          status: status ? Number(status) : undefined,
          kind: kind || undefined,
          limit: PAGE_SIZE,
          offset: nextOffset,
        });
        setPage(data);
        setError("");
      } catch (err) {
        setError(err instanceof Error ? err.message : "failed to load http events");
      }
    },
    [captureId, host, method, status, kind, offset],
  );

  useEffect(() => {
    void load(offset);
  }, [load, offset]);

  const totalPages = page ? Math.max(1, Math.ceil(page.total / PAGE_SIZE)) : 1;
  const currentPage = Math.floor(offset / PAGE_SIZE) + 1;

  return (
    <>
      <h2>HTTP ({page?.total ?? 0})</h2>
      <p className="dim">
        Paths and query parameter names are retained; query values, cookies and
        authorization headers are never stored.
      </p>
      <div className="filterbar">
        <input
          placeholder="host contains"
          value={host}
          onChange={(event) => setHost(event.target.value)}
        />
        <select value={method} onChange={(event) => setMethod(event.target.value)}>
          <option value="">method: any</option>
          {["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"].map((item) => (
            <option key={item} value={item}>
              {item}
            </option>
          ))}
        </select>
        <input
          placeholder="status"
          value={status}
          onChange={(event) => setStatus(event.target.value.replace(/\D/g, ""))}
        />
        <select value={kind} onChange={(event) => setKind(event.target.value)}>
          <option value="">kind: any</option>
          <option value="request">request</option>
          <option value="response">response</option>
        </select>
        <button
          className="btn btn-small"
          onClick={() => {
            setOffset(0);
            void load(0);
          }}
        >
          [ APPLY ]
        </button>
      </div>

      <table className="tbl">
        <thead>
          <tr>
            <th>TIME</th>
            <th>KIND</th>
            <th>HOST</th>
            <th>METHOD</th>
            <th>PATH</th>
            <th>PARAMS</th>
            <th>STATUS</th>
            <th>SERVER / UA</th>
          </tr>
        </thead>
        <tbody>
          {page?.events.map((event) => (
            <tr key={event.id}>
              <td className="mono-small">{fmtTime(event.ts)}</td>
              <td>{event.kind}</td>
              <td className="accent">{event.host ?? "-"}</td>
              <td>{event.method ?? "-"}</td>
              <td className="dim">{event.path ?? "-"}</td>
              <td className="dim">{parseJsonList(event.query_names).join(", ") || "-"}</td>
              <td className={event.status && event.status >= 400 ? "warn" : ""}>
                {event.status ?? "-"}
              </td>
              <td className="dim">{event.server ?? event.user_agent ?? "-"}</td>
            </tr>
          ))}
          {page && page.events.length === 0 && (
            <tr>
              <td colSpan={8} className="dim">
                no http events (only unencrypted HTTP is visible)
              </td>
            </tr>
          )}
        </tbody>
      </table>
      {page && page.total > PAGE_SIZE && (
        <div className="pager">
          <button
            className="btn btn-small"
            disabled={offset === 0}
            onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
          >
            [ PREV ]
          </button>
          <span className="dim">
            page {currentPage}/{totalPages} · {page.total} events
          </span>
          <button
            className="btn btn-small"
            disabled={offset + PAGE_SIZE >= page.total}
            onClick={() => setOffset(offset + PAGE_SIZE)}
          >
            [ NEXT ]
          </button>
        </div>
      )}
      {error && <div className="error-bar">!! {error}</div>}
    </>
  );
}
