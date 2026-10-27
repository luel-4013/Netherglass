import { useCallback, useEffect, useRef, useState } from "react";
import { getCapture, getFlows, getPackets, reportUrl } from "../api";
import { fmtBytes, fmtTime } from "../format";
import type { CaptureSummary, FlowRow, PacketPage, SessionInfo } from "../types";
import CasesView from "./CasesView";
import DnsView from "./DnsView";
import EvidenceView from "./EvidenceView";
import FindingsView from "./FindingsView";
import GraphView from "./GraphView";
import HostsView from "./HostsView";
import HttpView from "./HttpView";
import QuickSearch from "./QuickSearch";
import SearchView from "./SearchView";
import K8sView from "./K8sView";
import StatsView from "./StatsView";
import TimelineView from "./TimelineView";
import TlsView from "./TlsView";
import TunnelsView from "./TunnelsView";
import WebView from "./WebView";

interface Props {
  captureId: string;
  session: SessionInfo;
  onBack: () => void;
}

const PAGE_SIZE = 200;

const TABS = [
  "packets",
  "flows",
  "hosts",
  "dns",
  "http",
  "tls",
  "web",
  "tunnels",
  "findings",
  "evidence",
  "timeline",
  "graph",
  "cases",
  "k8s",
  "stats",
  "search",
] as const;

type Tab = (typeof TABS)[number];

const VISIBILITY: Record<string, string> = {
  A: "metadata only — payloads and raw PCAP files are not retained",
  B: "packet-level — raw frames retained; sensitive values encrypted at rest",
  C: "packet-level — full authorized evidence capture; may hold credentials and personal data",
};

export default function CaptureWorkspace({ captureId, session, onBack }: Props) {
  const [detail, setDetail] = useState<CaptureSummary | null>(null);
  const [page, setPage] = useState<PacketPage | null>(null);
  const [flows, setFlows] = useState<FlowRow[]>([]);
  const [tab, setTab] = useState<Tab>("packets");
  const [searchSeed, setSearchSeed] = useState("");
  const [offset, setOffset] = useState(0);
  const [proto, setProto] = useState("");
  const [addr, setAddr] = useState("");
  const [port, setPort] = useState("");
  const [error, setError] = useState("");
  const timer = useRef<number | null>(null);

  const load = useCallback(async () => {
    try {
      const filters = {
        limit: PAGE_SIZE,
        offset,
        proto: proto || undefined,
        addr: addr || undefined,
        port: port ? Number(port) : undefined,
      };
      const [capture, packets, flowData] = await Promise.all([
        getCapture(captureId),
        getPackets(captureId, filters),
        getFlows(captureId, 200),
      ]);
      setDetail(capture);
      setPage(packets);
      setFlows(flowData.flows);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed to load packets");
    }
  }, [captureId, offset, proto, addr, port]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (detail && (detail.status === "decoding" || detail.status === "running")) {
      timer.current = window.setInterval(() => void load(), 3000);
    }
    return () => {
      if (timer.current !== null) window.clearInterval(timer.current);
    };
  }, [detail, load]);

  function applyFilters() {
    setOffset(0);
    void load();
  }

  const totalPages = page ? Math.max(1, Math.ceil(page.total / PAGE_SIZE)) : 1;
  const currentPage = Math.floor(offset / PAGE_SIZE) + 1;

  return (
    <div className="shell">
      <header className="topbar">
        <div className="brand">
          <span className="brand-name">NETHERGLASS</span>
          <span className="brand-sub">capture :: {captureId}</span>
        </div>
        <div className="topbar-right">
          <button className="btn" onClick={onBack}>
            [ BACK TO DASHBOARD ]
          </button>
        </div>
      </header>

      {error && <div className="error-bar">!! {error}</div>}

      <main className="grid">
        <section className="panel panel-wide">
          <h2>CAPTURE DETAIL</h2>
          {detail && (
            <table className="tbl">
              <tbody>
                <tr>
                  <td>status</td>
                  <td className={detail.status === "error" ? "warn" : "up"}>
                    {detail.status}
                  </td>
                  <td>source</td>
                  <td>
                    {detail.source}
                    {detail.original_filename ? ` (${detail.original_filename})` : ""}
                  </td>
                  <td>interface</td>
                  <td>{detail.interface ?? "-"}</td>
                </tr>
                <tr>
                  <td>packets captured</td>
                  <td>{detail.packets_captured}</td>
                  <td>kernel drops</td>
                  <td className={detail.packets_dropped ? "warn" : ""}>
                    {detail.packets_dropped}
                  </td>
                  <td>decode drops</td>
                  <td className={detail.decode_drops ? "warn" : ""}>
                    {detail.decode_drops}
                  </td>
                </tr>
                <tr>
                  <td>decoded</td>
                  <td>{detail.decoded_packets ?? 0}</td>
                  <td>flows</td>
                  <td>{detail.flows ?? 0}</td>
                  <td>hosts</td>
                  <td>{detail.hosts ?? 0}</td>
                </tr>
                <tr>
                  <td>size</td>
                  <td>{fmtBytes(detail.bytes_written)}</td>
                  <td>bpf</td>
                  <td colSpan={3} className="dim">
                    {detail.bpf ?? "(none — no scope filter configured)"}
                  </td>
                </tr>
                <tr>
                  <td>profile</td>
                  <td>{detail.profile ?? "-"}</td>
                  <td>visibility</td>
                  <td className="dim">
                    {detail.profile
                      ? VISIBILITY[detail.profile] ??
                        `unknown profile ${detail.profile} — treat visibility as undetermined`
                      : "undetermined — the source did not declare a visibility level"}
                  </td>
                  <td>export</td>
                  <td>
                    {detail.status === "running" ? (
                      <span className="dim">stop capture to export</span>
                    ) : (
                      <>
                        <a
                          className="btn btn-small"
                          href={`/api/captures/${encodeURIComponent(captureId)}/export?format=pcapng`}
                        >
                          [ PCAPNG ]
                        </a>{" "}
                        <a
                          className="btn btn-small"
                          href={`/api/captures/${encodeURIComponent(captureId)}/export?format=pcap`}
                        >
                          [ PCAP ]
                        </a>{" "}
                        <a
                          className="btn btn-small"
                          href={reportUrl(captureId, "html")}
                        >
                          [ REPORT ]
                        </a>
                        {session.permissions.includes(
                          "EXPORT_SENSITIVE_EVIDENCE",
                        ) && (
                          <>
                            {" "}
                            <a
                              className="btn btn-small btn-panic"
                              href={reportUrl(captureId, "html", true)}
                            >
                              [ RESTRICTED REPORT ]
                            </a>
                          </>
                        )}
                      </>
                    )}
                  </td>
                </tr>
                {detail.error && (
                  <tr>
                    <td>error</td>
                    <td colSpan={5} className="warn">
                      {detail.error}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          )}
          <p className="dim">
            {detail?.status === "decoding"
              ? "decoding in progress — refreshing every 3s ..."
              : "sha256 hashes and original filenames live in manifest.json inside the capture directory."}
          </p>
        </section>

        <section className="panel panel-wide">
          <div className="tabs">
            {TABS.map((name) => (
              <button
                key={name}
                className={`btn btn-small ${tab === name ? "btn-active" : ""}`}
                onClick={() => setTab(name)}
              >
                [ {name.toUpperCase()} ]
              </button>
            ))}
          </div>

          {tab !== "search" && (
            <QuickSearch
              captureId={captureId}
              onAdvanced={(query) => {
                setSearchSeed(query);
                setTab("search");
              }}
            />
          )}

          {tab === "packets" && (
            <>
              <h2>PACKETS</h2>
              <div className="filterbar">
                <input
                  placeholder="proto (dns, http, tls ...)"
                  value={proto}
                  onChange={(event) => setProto(event.target.value)}
                />
                <input
                  placeholder="host (src or dst)"
                  value={addr}
                  onChange={(event) => setAddr(event.target.value)}
                />
                <input
                  placeholder="port"
                  value={port}
                  onChange={(event) => setPort(event.target.value.replace(/\D/g, ""))}
                />
                <button className="btn btn-small" onClick={applyFilters}>
                  [ APPLY ]
                </button>
              </div>
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
                        <th>SECURITY</th>
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
                          <td
                            className={
                              packet.security === "insecure" ||
                              packet.security === "weak"
                                ? "warn"
                                : "dim"
                            }
                          >
                            {packet.security ?? packet.encryption ?? "-"}
                          </td>
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
          )}

          {tab === "flows" && (
            <>
              <h2>FLOWS</h2>
              <table className="tbl">
                <thead>
                  <tr>
                    <th>SRC</th>
                    <th>DST</th>
                    <th>PROTO</th>
                    <th>DPORT</th>
                    <th>PACKETS</th>
                    <th>BYTES</th>
                    <th>LAST</th>
                  </tr>
                </thead>
                <tbody>
                  {flows.map((flow, index) => (
                    <tr
                      key={`${flow.src}-${flow.dst}-${flow.proto}-${flow.dport}-${index}`}
                    >
                      <td>{flow.src}</td>
                      <td>{flow.dst}</td>
                      <td className="accent">{flow.proto}</td>
                      <td>{flow.dport}</td>
                      <td>{flow.packets}</td>
                      <td>{flow.bytes}</td>
                      <td className="mono-small">{fmtTime(flow.last_ts)}</td>
                    </tr>
                  ))}
                  {flows.length === 0 && (
                    <tr>
                      <td colSpan={7} className="dim">
                        no flows yet
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </>
          )}

          {tab === "hosts" && <HostsView captureId={captureId} />}
          {tab === "dns" && <DnsView captureId={captureId} />}
          {tab === "http" && <HttpView captureId={captureId} />}
          {tab === "tls" && <TlsView captureId={captureId} />}
          {tab === "web" && <WebView captureId={captureId} session={session} />}
          {tab === "tunnels" && <TunnelsView captureId={captureId} />}
          {tab === "k8s" && <K8sView captureId={captureId} />}
          {tab === "findings" && <FindingsView captureId={captureId} />}
          {tab === "evidence" && (
            <EvidenceView
              captureId={captureId}
              canReveal={session.permissions.includes("VIEW_SENSITIVE_VALUES")}
              canDelete={session.permissions.includes("DELETE_EVIDENCE")}
            />
          )}
          {tab === "timeline" && <TimelineView captureId={captureId} />}
          {tab === "graph" && <GraphView captureId={captureId} />}
          {tab === "cases" && <CasesView captureId={captureId} session={session} />}
          {tab === "stats" && <StatsView captureId={captureId} />}
          {tab === "search" && (
            <SearchView captureId={captureId} initialQuery={searchSeed} />
          )}
        </section>
      </main>
    </div>
  );
}
