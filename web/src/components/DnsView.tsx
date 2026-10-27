import { useCallback, useEffect, useState } from "react";
import { getDnsEvents } from "../api";
import { fmtTime, parseJsonList } from "../format";
import type { DnsPage } from "../types";

interface Props {
  captureId: string;
}

const PAGE_SIZE = 200;

export default function DnsView({ captureId }: Props) {
  const [page, setPage] = useState<DnsPage | null>(null);
  const [qname, setQname] = useState("");
  const [qtype, setQtype] = useState("");
  const [rcode, setRcode] = useState("");
  const [offset, setOffset] = useState(0);
  const [error, setError] = useState("");

  const load = useCallback(
    async (nextOffset = offset) => {
      try {
        const data = await getDnsEvents(captureId, {
          qname: qname || undefined,
          qtype: qtype || undefined,
          rcode: rcode || undefined,
          limit: PAGE_SIZE,
          offset: nextOffset,
        });
        setPage(data);
        setError("");
      } catch (err) {
        setError(err instanceof Error ? err.message : "failed to load dns events");
      }
    },
    [captureId, qname, qtype, rcode, offset],
  );

  useEffect(() => {
    void load(offset);
  }, [load, offset]);

  const totalPages = page ? Math.max(1, Math.ceil(page.total / PAGE_SIZE)) : 1;
  const currentPage = Math.floor(offset / PAGE_SIZE) + 1;

  return (
    <>
      <h2>DNS ({page?.total ?? 0})</h2>
      <div className="filterbar">
        <input
          placeholder="qname contains"
          value={qname}
          onChange={(event) => setQname(event.target.value)}
        />
        <select value={qtype} onChange={(event) => setQtype(event.target.value)}>
          <option value="">qtype: any</option>
          {["A", "AAAA", "CNAME", "MX", "TXT", "NS", "PTR", "SOA", "SRV", "HTTPS"].map(
            (item) => (
              <option key={item} value={item}>
                {item}
              </option>
            ),
          )}
        </select>
        <select value={rcode} onChange={(event) => setRcode(event.target.value)}>
          <option value="">rcode: any</option>
          {["NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED", "FORMERR"].map((item) => (
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
            <th>TIME</th>
            <th>CLIENT</th>
            <th>QNAME</th>
            <th>QTYPE</th>
            <th>RCODE</th>
            <th>ANSWERS</th>
            <th>TTL</th>
            <th>MATCH</th>
          </tr>
        </thead>
        <tbody>
          {page?.events.map((event) => (
            <tr key={event.id}>
              <td className="mono-small">{fmtTime(event.ts)}</td>
              <td>{event.client ?? "-"}</td>
              <td>{event.qname}</td>
              <td>{event.qtype ?? "-"}</td>
              <td className={event.rcode === "NXDOMAIN" ? "warn" : ""}>
                {event.rcode ?? "-"}
              </td>
              <td className="dim">{parseJsonList(event.answers).join(", ") || "-"}</td>
              <td>{event.ttl_min ?? "-"}</td>
              <td className={event.matched === 2 ? "warn" : "dim"}>
                {event.matched === 1 ? "query+resp" : event.matched === 2 ? "orphan resp" : "query"}
              </td>
            </tr>
          ))}
          {page && page.events.length === 0 && (
            <tr>
              <td colSpan={8} className="dim">
                no dns events
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
