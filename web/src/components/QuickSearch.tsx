import { useState } from "react";
import { searchPackets } from "../api";
import { fmtTime } from "../format";
import type { PacketPage } from "../types";

interface Props {
  captureId: string;
  onAdvanced: (query: string) => void;
}

const RESULT_LIMIT = 100;

export default function QuickSearch({ captureId, onAdvanced }: Props) {
  const [query, setQuery] = useState("");
  const [page, setPage] = useState<PacketPage | null>(null);
  const [error, setError] = useState("");

  async function run() {
    if (!query.trim()) {
      setPage(null);
      setError("");
      return;
    }
    try {
      const data = await searchPackets(captureId, query, {
        limit: RESULT_LIMIT,
        offset: 0,
      });
      setPage(data);
      setError("");
    } catch (err) {
      setPage(null);
      setError(err instanceof Error ? err.message : "search failed");
    }
  }

  function clear() {
    setQuery("");
    setPage(null);
    setError("");
  }

  const shown = page ? Math.min(RESULT_LIMIT, page.packets.length) : 0;

  return (
    <div className="quick-search">
      <div className="filterbar">
        <input
          className="query-input"
          placeholder="search packets: ip = 10.0.0.5 AND port = 443"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") void run();
          }}
        />
        <button className="btn btn-small" onClick={() => void run()}>
          [ RUN ]
        </button>
        <button className="btn btn-small" onClick={clear}>
          [ CLEAR ]
        </button>
        <button
          className="btn btn-small"
          title="open the full SEARCH tab with the filter builder and paging"
          onClick={() => onAdvanced(query)}
        >
          [ ADVANCED &gt;&gt; ]
        </button>
      </div>
      {error && <div className="error-bar">!! {error}</div>}
      {page && (
        <>
          <table className="tbl">
            <thead>
              <tr>
                <th>#</th>
                <th>TIME</th>
                <th>SRC</th>
                <th>DST</th>
                <th>PROTO</th>
                <th>ENC</th>
                <th>LEN</th>
                <th>INFO</th>
              </tr>
            </thead>
            <tbody>
              {page.packets.map((packet) => (
                <tr key={packet.id}>
                  <td>{packet.num}</td>
                  <td className="mono-small">{fmtTime(packet.ts)}</td>
                  <td>
                    {packet.src}
                    {packet.sport ? `:${packet.sport}` : ""}
                  </td>
                  <td>
                    {packet.dst}
                    {packet.dport ? `:${packet.dport}` : ""}
                  </td>
                  <td className="accent">{packet.app_proto ?? packet.proto}</td>
                  <td className="dim">{packet.encryption ?? "-"}</td>
                  <td>{packet.length}</td>
                  <td className="dim">{packet.info}</td>
                </tr>
              ))}
              {page.packets.length === 0 && (
                <tr>
                  <td colSpan={8} className="dim">
                    no packets match
                  </td>
                </tr>
              )}
            </tbody>
          </table>
          <p className="dim">
            {page.total} packets match · showing {shown}
            {page.total > RESULT_LIMIT
              ? " · use ADVANCED >> for paging and the filter builder"
              : ""}
          </p>
        </>
      )}
    </div>
  );
}
