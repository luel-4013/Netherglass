import { useCallback, useEffect, useState } from "react";
import { getSearchFields, searchPackets } from "../api";
import { fmtTime } from "../format";
import type { PacketPage, SearchFieldInfo } from "../types";

interface Props {
  captureId: string;
  initialQuery?: string;
}

const PAGE_SIZE = 200;

const NUMBER_FIELDS = new Set([
  "src.port",
  "dst.port",
  "port",
  "http.status",
  "stream",
]);

function quoteValue(value: string): string {
  if (value === "") return '""';
  return /^[A-Za-z0-9_.:\-]+$/.test(value) ? value : `"${value.replace(/"/g, '\\"')}"`;
}

export default function SearchView({ captureId, initialQuery }: Props) {
  const [info, setInfo] = useState<SearchFieldInfo | null>(null);
  const [query, setQuery] = useState(initialQuery ?? "");
  const [field, setField] = useState("ip");
  const [op, setOp] = useState("=");
  const [value, setValue] = useState("");
  const [joiner, setJoiner] = useState("AND");
  const [page, setPage] = useState<PacketPage | null>(null);
  const [error, setError] = useState("");
  const [offset, setOffset] = useState(0);

  useEffect(() => {
    getSearchFields()
      .then(setInfo)
      .catch(() => setInfo(null));
  }, []);

  useEffect(() => {
    if (initialQuery !== undefined) setQuery(initialQuery);
  }, [initialQuery]);

  const run = useCallback(
    async (nextOffset = offset) => {
      if (!query.trim()) {
        setPage(null);
        setError("");
        return;
      }
      try {
        const data = await searchPackets(captureId, query, {
          limit: PAGE_SIZE,
          offset: nextOffset,
        });
        setPage(data);
        setError("");
      } catch (err) {
        setPage(null);
        setError(err instanceof Error ? err.message : "search failed");
      }
    },
    [captureId, query, offset],
  );

  useEffect(() => {
    void run(offset);
  }, [run, offset]);

  function appendCondition() {
    if (!value.trim()) return;
    const condition = `${field} ${op} ${quoteValue(value.trim())}`;
    setQuery((current) =>
      current.trim() ? `${current.trim()} ${joiner} ${condition}` : condition,
    );
    setValue("");
  }

  const totalPages = page ? Math.max(1, Math.ceil(page.total / PAGE_SIZE)) : 1;
  const currentPage = Math.floor(offset / PAGE_SIZE) + 1;

  return (
    <>
      <h2>SEARCH</h2>
      <p className="dim">
        Query language: field operator value, combined with AND / OR / NOT and
        parentheses. Add conditions below or edit the query directly.
      </p>
      <div className="builder">
        <select value={field} onChange={(event) => setField(event.target.value)}>
          {(info?.fields ?? ["ip", "port", "protocol"]).map((item) => (
            <option key={item} value={item}>
              {item}
            </option>
          ))}
        </select>
        <select value={op} onChange={(event) => setOp(event.target.value)}>
          {(info?.operators ?? ["=", "~"])
            .filter((item) => !NUMBER_FIELDS.has(field) || !["~", "contains"].includes(item))
            .map((item) => (
              <option key={item} value={item}>
                {item}
              </option>
            ))}
        </select>
        <input
          placeholder="value"
          value={value}
          onChange={(event) => setValue(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") appendCondition();
          }}
        />
        <select value={joiner} onChange={(event) => setJoiner(event.target.value)}>
          <option value="AND">AND</option>
          <option value="OR">OR</option>
        </select>
        <button className="btn btn-small" onClick={appendCondition}>
          [ ADD ]
        </button>
      </div>
      <div className="builder">
        <input
          className="query-input"
          placeholder="ip = 10.0.0.5 AND port = 443"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") {
              setOffset(0);
              void run(0);
            }
          }}
        />
        <button
          className="btn btn-small"
          onClick={() => {
            setOffset(0);
            void run(0);
          }}
        >
          [ RUN ]
        </button>
        <button
          className="btn btn-small"
          onClick={() => {
            setQuery("");
            setPage(null);
            setError("");
            setOffset(0);
          }}
        >
          [ CLEAR ]
        </button>
      </div>
      {info && Object.keys(info.deferred).length > 0 && (
        <p className="dim">
          deferred fields:{" "}
          {Object.entries(info.deferred)
            .map(([name, note]) => `${name} (${note})`)
            .join(" · ")}
        </p>
      )}
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
          <div className="pager">
            <button
              className="btn btn-small"
              disabled={offset === 0}
              onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
            >
              [ PREV ]
            </button>
            <span className="dim">
              page {currentPage}/{totalPages} · {page.total} packets
            </span>
            <button
              className="btn btn-small"
              disabled={offset + PAGE_SIZE >= page.total}
              onClick={() => setOffset(offset + PAGE_SIZE)}
            >
              [ NEXT ]
            </button>
          </div>
        </>
      )}
    </>
  );
}
