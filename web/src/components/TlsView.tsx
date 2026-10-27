import { useCallback, useEffect, useState } from "react";
import { getTlsSessions } from "../api";
import { parseJsonList } from "../format";
import type { TlsPage } from "../types";

interface Props {
  captureId: string;
}

const PAGE_SIZE = 200;

export default function TlsView({ captureId }: Props) {
  const [page, setPage] = useState<TlsPage | null>(null);
  const [sni, setSni] = useState("");
  const [version, setVersion] = useState("");
  const [offset, setOffset] = useState(0);
  const [error, setError] = useState("");

  const load = useCallback(
    async (nextOffset = offset) => {
      try {
        const data = await getTlsSessions(captureId, {
          sni: sni || undefined,
          version: version || undefined,
          limit: PAGE_SIZE,
          offset: nextOffset,
        });
        setPage(data);
        setError("");
      } catch (err) {
        setError(err instanceof Error ? err.message : "failed to load tls sessions");
      }
    },
    [captureId, sni, version, offset],
  );

  useEffect(() => {
    void load(offset);
  }, [load, offset]);

  const totalPages = page ? Math.max(1, Math.ceil(page.total / PAGE_SIZE)) : 1;
  const currentPage = Math.floor(offset / PAGE_SIZE) + 1;

  return (
    <>
      <h2>TLS ({page?.total ?? 0})</h2>
      <p className="dim">
        Sessions presented by handshake metadata; encrypted payloads are never
        decrypted. Certificate subject/issuer are shown as SANs and name hints only.
      </p>
      <div className="filterbar">
        <input
          placeholder="SNI contains"
          value={sni}
          onChange={(event) => setSni(event.target.value)}
        />
        <select value={version} onChange={(event) => setVersion(event.target.value)}>
          <option value="">version: any</option>
          {["TLS1.3", "TLS1.2", "TLS1.1", "TLS1.0", "SSLv3"].map((item) => (
            <option key={item} value={item}>
              {item}
            </option>
          ))}
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
            <th>STREAM</th>
            <th>CLIENT</th>
            <th>SERVER</th>
            <th>VERSION</th>
            <th>SNI</th>
            <th>ALPN</th>
            <th>CIPHER</th>
            <th>CERT VALID</th>
            <th>SANS</th>
          </tr>
        </thead>
        <tbody>
          {page?.sessions.map((session) => (
            <tr key={session.stream}>
              <td>{session.stream}</td>
              <td>
                {session.client}
                {session.sport ? `:${session.sport}` : ""}
              </td>
              <td>
                {session.server}
                {session.dport ? `:${session.dport}` : ""}
              </td>
              <td className="accent">{session.version ?? "-"}</td>
              <td>{session.sni ?? "-"}</td>
              <td className="dim">{session.alpn ?? "-"}</td>
              <td className="mono-small">{session.cipher ?? "-"}</td>
              <td className="mono-small">
                {session.cert_not_before
                  ? `${session.cert_not_before} .. ${session.cert_not_after ?? "?"}`
                  : "-"}
              </td>
              <td className="dim">
                {parseJsonList(session.cert_sans).join(", ") || "-"}
              </td>
            </tr>
          ))}
          {page && page.sessions.length === 0 && (
            <tr>
              <td colSpan={9} className="dim">
                no tls sessions
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
            page {currentPage}/{totalPages} · {page.total} sessions
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
