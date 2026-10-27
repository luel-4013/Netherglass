import type {
  AuditPage,
  CaptureStatus,
  ControlledTestRow,
  TestingScope,
  CaptureSummary,
  CaseRow,
  ConfigInfo,
  DataFlowRow,
  DnsPage,
  EmergencyStatus,
  EvidencePage,
  FindingsPage,
  FlowlogImportResult,
  FlowRow,
  GraphPage,
  HostDetail,
  HostRow,
  HttpPage,
  ImportResult,
  InterfaceInfo,
  K8sCorrelation,
  K8sEntity,
  K8sImportResult,
  PacketPage,
  Readiness,
  RevealResult,
  SearchFieldInfo,
  SessionInfo,
  StatsData,
  StopSummary,
  SystemStatus,
  TimelinePage,
  TlsPage,
  TunnelRow,
  WebApp,
  WebCookieRow,
  WebHeaderRow,
  WebTokenRow,
} from "./types";

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

let csrfToken = "";

export function setCsrf(token: string): void {
  csrfToken = token;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    ...(init.headers as Record<string, string> | undefined),
  };
  if (init.body) {
    headers["Content-Type"] = "application/json";
  }
  const method = (init.method ?? "GET").toUpperCase();
  if (csrfToken && method !== "GET" && method !== "HEAD") {
    headers["X-CSRF-Token"] = csrfToken;
  }
  const response = await fetch(path, { ...init, headers });
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = (await response.json()) as { detail?: string };
      if (body.detail) {
        detail = body.detail;
      }
    } catch {
      // keep status text
    }
    throw new ApiError(response.status, detail);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

export const getSession = () => request<SessionInfo>("/api/auth/session");

export const login = (username: string, password: string) =>
  request<SessionInfo>("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });

export const logout = () => request<{ ok: boolean }>("/api/auth/logout", { method: "POST" });

export const getStatus = () => request<SystemStatus>("/api/system/status");

export const getInterfaces = () =>
  request<{ interfaces: InterfaceInfo[] }>("/api/system/interfaces");

export const getReadiness = () => request<Readiness>("/api/system/readiness");

export const getConfig = () => request<ConfigInfo>("/api/system/config");

export const getAudit = (limit = 100) => request<AuditPage>(`/api/audit?limit=${limit}`);

export const emergencyStop = (reason: string) =>
  request<EmergencyStatus>("/api/system/emergency-stop", {
    method: "POST",
    body: JSON.stringify({ confirm: "EMERGENCY STOP", reason }),
  });

export const emergencyRecover = (reason: string) =>
  request<EmergencyStatus>("/api/system/emergency-recover", {
    method: "POST",
    body: JSON.stringify({ reason }),
  });

export const getCaptureStatus = () => request<CaptureStatus>("/api/capture/status");

export const captureStart = (iface: string, bpf?: string) =>
  request<CaptureStatus>("/api/capture/start", {
    method: "POST",
    body: JSON.stringify({ interface: iface, bpf: bpf?.trim() ? bpf.trim() : null }),
  });

export const captureStop = (reason?: string) =>
  request<StopSummary>("/api/capture/stop", {
    method: "POST",
    body: JSON.stringify({ reason: reason?.trim() ? reason.trim() : null }),
  });

export const importPcap = (path: string) =>
  request<ImportResult>("/api/capture/import", {
    method: "POST",
    body: JSON.stringify({ path }),
  });

export const getCaptures = (limit = 50) =>
  request<{ captures: CaptureSummary[] }>(`/api/captures?limit=${limit}`);

export const getCapture = (id: string) =>
  request<CaptureSummary>(`/api/captures/${encodeURIComponent(id)}`);

export const getPackets = (
  captureId: string,
  options: { limit?: number; offset?: number; proto?: string; addr?: string; port?: number } = {},
) => {
  const params = new URLSearchParams({ capture_id: captureId });
  if (options.limit) params.set("limit", String(options.limit));
  if (options.offset) params.set("offset", String(options.offset));
  if (options.proto?.trim()) params.set("proto", options.proto.trim());
  if (options.addr?.trim()) params.set("addr", options.addr.trim());
  if (options.port) params.set("port", String(options.port));
  return request<PacketPage>(`/api/packets?${params.toString()}`);
};

export const getFlows = (captureId: string, limit = 200) =>
  request<{ flows: FlowRow[] }>(
    `/api/flows?capture_id=${encodeURIComponent(captureId)}&limit=${limit}`,
  );

export const getHosts = (captureId: string, limit = 500) =>
  request<{ hosts: HostRow[] }>(
    `/api/captures/${encodeURIComponent(captureId)}/hosts?limit=${limit}`,
  );

export const getHost = (captureId: string, ip: string) =>
  request<HostDetail>(
    `/api/captures/${encodeURIComponent(captureId)}/hosts/${encodeURIComponent(ip)}`,
  );

export const getDnsEvents = (
  captureId: string,
  options: { qname?: string; qtype?: string; rcode?: string; limit?: number; offset?: number } = {},
) => {
  const params = new URLSearchParams();
  if (options.qname?.trim()) params.set("qname", options.qname.trim());
  if (options.qtype?.trim()) params.set("qtype", options.qtype.trim());
  if (options.rcode?.trim()) params.set("rcode", options.rcode.trim());
  params.set("limit", String(options.limit ?? 200));
  params.set("offset", String(options.offset ?? 0));
  return request<DnsPage>(
    `/api/captures/${encodeURIComponent(captureId)}/dns?${params.toString()}`,
  );
};

export const getHttpEvents = (
  captureId: string,
  options: { host?: string; method?: string; status?: number; kind?: string; limit?: number; offset?: number } = {},
) => {
  const params = new URLSearchParams();
  if (options.host?.trim()) params.set("host", options.host.trim());
  if (options.method?.trim()) params.set("method", options.method.trim());
  if (options.status) params.set("status", String(options.status));
  if (options.kind) params.set("kind", options.kind);
  params.set("limit", String(options.limit ?? 200));
  params.set("offset", String(options.offset ?? 0));
  return request<HttpPage>(
    `/api/captures/${encodeURIComponent(captureId)}/http?${params.toString()}`,
  );
};

export const getTlsSessions = (
  captureId: string,
  options: { sni?: string; version?: string; limit?: number; offset?: number } = {},
) => {
  const params = new URLSearchParams();
  if (options.sni?.trim()) params.set("sni", options.sni.trim());
  if (options.version?.trim()) params.set("version", options.version.trim());
  params.set("limit", String(options.limit ?? 200));
  params.set("offset", String(options.offset ?? 0));
  return request<TlsPage>(
    `/api/captures/${encodeURIComponent(captureId)}/tls?${params.toString()}`,
  );
};

export const getStats = (captureId: string) =>
  request<StatsData>(`/api/captures/${encodeURIComponent(captureId)}/stats`);

export const getFindings = (
  captureId: string,
  options: { severity?: string; confidence?: string; limit?: number; offset?: number } = {},
) => {
  const params = new URLSearchParams();
  if (options.severity) params.set("severity", options.severity);
  if (options.confidence) params.set("confidence", options.confidence);
  params.set("limit", String(options.limit ?? 200));
  params.set("offset", String(options.offset ?? 0));
  return request<FindingsPage>(
    `/api/captures/${encodeURIComponent(captureId)}/findings?${params.toString()}`,
  );
};

export const analyzeCapture = (captureId: string) =>
  request<{ capture_id: string; findings: number }>(
    `/api/captures/${encodeURIComponent(captureId)}/analyze`,
    { method: "POST" },
  );

export const getEvidence = (
  captureId: string,
  options: { artifactType?: string; limit?: number; offset?: number } = {},
) => {
  const params = new URLSearchParams();
  if (options.artifactType?.trim()) params.set("artifact_type", options.artifactType.trim());
  params.set("limit", String(options.limit ?? 200));
  params.set("offset", String(options.offset ?? 0));
  return request<EvidencePage>(
    `/api/captures/${encodeURIComponent(captureId)}/evidence?${params.toString()}`,
  );
};

export const revealEvidence = (evidenceId: string, reason: string) =>
  request<RevealResult>(`/api/evidence/${encodeURIComponent(evidenceId)}/reveal`, {
    method: "POST",
    body: JSON.stringify({ reason }),
  });

export const deleteEvidence = (evidenceId: string, reason: string) =>
  request<{ id: string; status: string }>(
    `/api/evidence/${encodeURIComponent(evidenceId)}`,
    {
      method: "DELETE",
      body: JSON.stringify({ reason }),
    },
  );

export const getSearchFields = () => request<SearchFieldInfo>("/api/search/fields");

export const searchPackets = (
  captureId: string,
  query: string,
  options: { limit?: number; offset?: number } = {},
) => {
  const params = new URLSearchParams({ capture_id: captureId, q: query });
  params.set("limit", String(options.limit ?? 200));
  params.set("offset", String(options.offset ?? 0));
  return request<PacketPage>(`/api/search?${params.toString()}`);
};

export const getWebApps = (captureId: string) =>
  request<{ applications: WebApp[] }>(
    `/api/captures/${encodeURIComponent(captureId)}/web/apps`,
  );

export const getWebCookies = (captureId: string) =>
  request<{ cookies: WebCookieRow[] }>(
    `/api/captures/${encodeURIComponent(captureId)}/web/cookies`,
  );

export const getWebHeaders = (captureId: string) =>
  request<{ hosts: WebHeaderRow[] }>(
    `/api/captures/${encodeURIComponent(captureId)}/web/headers`,
  );

export const getWebTokens = (captureId: string) =>
  request<{ tokens: WebTokenRow[] }>(
    `/api/captures/${encodeURIComponent(captureId)}/web/tokens`,
  );

export const getWebFlows = (captureId: string) =>
  request<{ flows: DataFlowRow[] }>(
    `/api/captures/${encodeURIComponent(captureId)}/web/flows`,
  );

export const getTimeline = (
  captureId: string,
  options: { kind?: string; severity?: string; host?: string; domain?: string; limit?: number } = {},
) => {
  const params = new URLSearchParams();
  if (options.kind) params.set("kind", options.kind);
  if (options.severity) params.set("severity", options.severity);
  if (options.host?.trim()) params.set("host", options.host.trim());
  if (options.domain?.trim()) params.set("domain", options.domain.trim());
  params.set("limit", String(options.limit ?? 300));
  return request<TimelinePage>(
    `/api/captures/${encodeURIComponent(captureId)}/timeline?${params.toString()}`,
  );
};

export const getGraph = (captureId: string, mode: "network" | "connection") =>
  request<GraphPage>(
    `/api/captures/${encodeURIComponent(captureId)}/graph?mode=${mode}`,
  );

export const getCases = (limit = 100) => request<{ cases: CaseRow[] }>(`/api/cases?limit=${limit}`);

export const getCase = (caseId: string) =>
  request<CaseRow>(`/api/cases/${encodeURIComponent(caseId)}`);

export const createCase = (title: string, summary: string) =>
  request<CaseRow>("/api/cases", {
    method: "POST",
    body: JSON.stringify({ title, summary }),
  });

export const updateCase = (
  caseId: string,
  patch: { title?: string; summary?: string; status?: string },
) =>
  request<CaseRow>(`/api/cases/${encodeURIComponent(caseId)}`, {
    method: "PATCH",
    body: JSON.stringify(patch),
  });

export const addCaseItem = (
  caseId: string,
  item: { item_type: string; item_id: string; capture_id?: string; note?: string },
) =>
  request<CaseRow>(`/api/cases/${encodeURIComponent(caseId)}/items`, {
    method: "POST",
    body: JSON.stringify(item),
  });

export const removeCaseItem = (caseId: string, itemId: number) =>
  request<CaseRow>(
    `/api/cases/${encodeURIComponent(caseId)}/items/${itemId}`,
    { method: "DELETE" },
  );

export const reportUrl = (captureId: string, format: "html" | "json", restricted = false) =>
  `/api/captures/${encodeURIComponent(captureId)}/report?format=${format}` +
  (restricted ? "&restricted=true" : "");

export const getTunnels = (captureId: string) =>
  request<{ capture_id: string; tunnels: TunnelRow[] }>(
    `/api/captures/${encodeURIComponent(captureId)}/tunnels`,
  );

export const getK8sEntities = (kind?: string) =>
  request<{ entities: K8sEntity[] }>(
    `/api/k8s/entities${kind ? `?kind=${encodeURIComponent(kind)}` : ""}`,
  );

export const getK8sCorrelation = (captureId: string) =>
  request<K8sCorrelation>(
    `/api/captures/${encodeURIComponent(captureId)}/k8s-correlation`,
  );

export const importFlowlogs = (path: string, format = "auto", label?: string) =>
  request<FlowlogImportResult>("/api/integrations/flowlogs", {
    method: "POST",
    body: JSON.stringify({ path, format, label: label ?? null }),
  });

export const importK8s = (payload: {
  path?: string;
  inventory?: unknown;
  label?: string;
}) =>
  request<K8sImportResult>("/api/integrations/k8s", {
    method: "POST",
    body: JSON.stringify(payload),
  });

export const getTestingScope = () => request<TestingScope>("/api/testing/scope");

export const getControlledTests = () =>
  request<{ tests: ControlledTestRow[] }>("/api/testing/tests");

export const getControlledTest = (testId: string) =>
  request<ControlledTestRow>(
    `/api/testing/tests/${encodeURIComponent(testId)}`,
  );

export const createControlledTest = (payload: {
  authorization_ref: string;
  target: string;
  test_type: string;
  port?: number | null;
  artifact_id?: string | null;
  case_id?: string | null;
  dry_run: boolean;
  rate_limit_ms: number;
  max_requests: number;
  timeout_ms: number;
}) =>
  request<ControlledTestRow>("/api/testing/tests", {
    method: "POST",
    body: JSON.stringify(payload),
  });

export const executeControlledTest = (testId: string, confirm: string) =>
  request<ControlledTestRow>(
    `/api/testing/tests/${encodeURIComponent(testId)}/execute`,
    { method: "POST", body: JSON.stringify({ confirm }) },
  );

export const abortControlledTest = (testId: string) =>
  request<ControlledTestRow>(
    `/api/testing/tests/${encodeURIComponent(testId)}/abort`,
    { method: "POST", body: JSON.stringify({}) },
  );
