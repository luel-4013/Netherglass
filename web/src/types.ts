export type Role = "admin" | "analyst" | "auditor";

export interface SessionUser {
  username: string;
  role: Role;
}

export interface SessionInfo {
  authenticated: boolean;
  user?: SessionUser;
  csrf_token?: string;
  permissions: string[];
}

export interface InterfaceInfo {
  name: string;
  kind: string;
  operstate: string;
  mac: string | null;
  mtu: number | null;
  addresses: string[];
  wireless: boolean;
  notes: string;
}

export interface CaptureSource {
  id: string;
  label: string;
  available: boolean;
  detail: string;
}

export interface Readiness {
  sources: CaptureSource[];
  packet_socket: boolean;
  hints: string[];
}

export interface ProfileInfo {
  id: string;
  name: string;
  description: string;
  store_pcap: boolean;
  store_payload: boolean;
  store_sensitive_values: boolean;
  retention_hours: number;
}

export interface ConfigInfo {
  profile: string;
  profiles: ProfileInfo[];
  scope: Record<string, unknown>;
  serve: { host: string; port: number; behind_tls: boolean };
  network_exposed: boolean;
  warnings: string[];
}

export interface EmergencyStatus {
  emergency_stopped: boolean;
  capture: string;
  processing: string;
  active_tests: string;
  exports: string;
  sensitive_evidence: string;
  recovery_required: boolean;
}

export interface SystemStatus {
  emergency: EmergencyStatus;
  profile: string;
  network_exposed: boolean;
}

export interface AuditEvent {
  id: number;
  ts: string;
  actor: string;
  action: string;
  target: string | null;
  details: Record<string, unknown>;
  hash: string;
}

export interface AuditPage {
  events: AuditEvent[];
  chain_valid: boolean;
  chain_length: number;
}

export interface CaptureSummary {
  id: string;
  created_at: string;
  interface: string | null;
  profile: string;
  status: string;
  source: string;
  bpf: string | null;
  started_at: string | null;
  stopped_at: string | null;
  packets_captured: number;
  packets_dropped: number;
  decode_drops: number;
  bytes_written: number;
  original_filename: string | null;
  error: string | null;
  decoded_packets?: number;
  decoded_bytes?: number;
  flows?: number;
  hosts?: number;
}

export interface CaptureStatus {
  active: boolean;
  last_capture: CaptureSummary | null;
  capture_id?: string;
  interface?: string;
  source?: string;
  started_at?: string;
  elapsed_seconds?: number;
  status?: string;
  queue_depth?: number;
  packets_captured?: number;
  packets_dropped?: number;
  packets_decoded?: number;
  decode_drops?: number;
  files_decoded?: number;
  bytes_written?: number;
  last_error?: string | null;
  stop_reason?: string | null;
}

export interface PacketRow {
  id: number;
  capture_id: string;
  num: number | null;
  ts: number | null;
  src: string | null;
  dst: string | null;
  sport: number | null;
  dport: number | null;
  proto: string | null;
  length: number | null;
  info: string | null;
  src_mac?: string | null;
  dst_mac?: string | null;
  app_proto?: string | null;
  encryption?: string | null;
  security?: string | null;
  stream?: string | null;
  dns_qname?: string | null;
  dns_qtype?: string | null;
  dns_rcode?: string | null;
  tls_sni?: string | null;
  tls_version?: string | null;
  http_host?: string | null;
  http_method?: string | null;
  http_status?: number | null;
}

export interface HostRow {
  capture_id: string;
  ip: string;
  mac: string | null;
  hostname: string | null;
  hostname_source: string | null;
  first_ts: number | null;
  last_ts: number | null;
  packets: number;
  bytes: number;
  sent_packets: number;
  sent_bytes: number;
  recv_packets: number;
  recv_bytes: number;
}

export interface HostNameRow {
  name: string;
  source: string;
  first_ts: number | null;
  last_ts: number | null;
}

export interface HostServiceRow {
  port: number;
  proto: string;
  app_proto: string | null;
  packets: number;
  bytes: number;
  first_ts: number | null;
  last_ts: number | null;
}

export interface HostDetail {
  host: HostRow;
  names: HostNameRow[];
  services: HostServiceRow[];
  flows: FlowRow[];
  dns: DnsEvent[];
  http: HttpEvent[];
  tls: TlsSession[];
}

export interface DnsEvent {
  id: number;
  ts: number | null;
  client: string | null;
  server: string | null;
  qname: string;
  qtype: string | null;
  rcode: string | null;
  answers: string | null;
  cname_chain: string | null;
  ttl_min: number | null;
  matched: number;
  response_ts: number | null;
}

export interface DnsPage {
  total: number;
  limit: number;
  offset: number;
  events: DnsEvent[];
}

export interface HttpEvent {
  id: number;
  ts: number | null;
  src: string | null;
  dst: string | null;
  sport: number | null;
  dport: number | null;
  stream: string | null;
  kind: string;
  method: string | null;
  host: string | null;
  path: string | null;
  query_names: string | null;
  status: number | null;
  user_agent: string | null;
  content_type: string | null;
  server: string | null;
  version: string | null;
  auth_scheme: string | null;
  set_cookie_count: number;
  cookie_count: number;
  length: number | null;
}

export interface HttpPage {
  total: number;
  limit: number;
  offset: number;
  events: HttpEvent[];
}

export interface TlsSession {
  capture_id?: string;
  stream: string;
  client: string | null;
  server: string | null;
  sport?: number | null;
  dport?: number | null;
  version: string | null;
  sni: string | null;
  alpn: string | null;
  cipher: string | null;
  ja3: string | null;
  ja4: string | null;
  cert_count?: number | null;
  cert_not_before: string | null;
  cert_not_after: string | null;
  cert_sans: string | null;
  first_ts?: number | null;
  last_ts?: number | null;
}

export interface TlsPage {
  total: number;
  limit: number;
  offset: number;
  sessions: TlsSession[];
}

export interface StatsBucket {
  [key: string]: string | number | null;
}

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type Confidence = "OBSERVED" | "LIKELY" | "POSSIBLE" | "NOT_DETERMINED";

export interface FindingsSummary {
  available: true;
  total: number;
  by_severity: Record<string, number>;
  by_confidence: Record<string, number>;
}

export interface EvidenceTypeSummary {
  artifact_type: string;
  count: number;
  sealed: number;
  metadata_only: number;
}

export interface SensitiveSummary {
  available: true;
  by_type: EvidenceTypeSummary[];
}

export interface StatsData {
  top_talkers: StatsBucket[];
  top_destinations: StatsBucket[];
  top_domains: StatsBucket[];
  top_ports: StatsBucket[];
  top_protocols: StatsBucket[];
  traffic_over_time: StatsBucket[];
  dns_volume: StatsBucket[];
  dns_summary: StatsBucket;
  tls_versions: StatsBucket[];
  encryption: StatsBucket[];
  security: StatsBucket[];
  findings: FindingsSummary | { available: false; note: string };
  sensitive_data: SensitiveSummary | { available: false; note: string };
}

export interface FindingRow {
  id: string;
  capture_id: string;
  rule_id: string;
  rule_version: number;
  title: string;
  description: string;
  explanation: string;
  remediation: string;
  severity: Severity;
  confidence: Confidence;
  status: string;
  asset: string | null;
  src: string | null;
  dst: string | null;
  protocol: string | null;
  first_ts: number | null;
  last_ts: number | null;
  evidence_ids: string | null;
  packet_refs: string | null;
  related: string | null;
  case_id: string | null;
  created_at: string;
}

export interface FindingsPage {
  total: number;
  limit: number;
  offset: number;
  findings: FindingRow[];
  summary: FindingsSummary;
}

export interface EvidenceRow {
  id: string;
  capture_id: string;
  artifact_type: string;
  field: string | null;
  src: string | null;
  sport: number | null;
  dst: string | null;
  dport: number | null;
  domain: string | null;
  host: string | null;
  protocol: string | null;
  app_proto: string | null;
  http_method: string | null;
  path: string | null;
  ts: number | null;
  stream: string | null;
  frame: number | null;
  confidence: Confidence;
  transport_security: string | null;
  meta: string | null;
  sha256: string | null;
  size: number | null;
  status: "SEALED" | "METADATA_ONLY" | string;
  case_id: string | null;
  created_at: string;
}

export interface EvidencePage {
  total: number;
  limit: number;
  offset: number;
  artifacts: EvidenceRow[];
  summary: EvidenceTypeSummary[];
}

export interface RevealResult {
  value: string;
  source?: string | null;
  evidence_id: string;
  auto_hide_seconds: number;
}

export interface SearchFieldInfo {
  fields: string[];
  operators: string[];
  deferred: Record<string, string>;
}

export interface PacketPage {
  total: number;
  limit: number;
  offset: number;
  packets: PacketRow[];
}

export interface FlowRow {
  src: string;
  dst: string;
  proto: string;
  dport: number;
  packets: number;
  bytes: number;
  first_ts: number | null;
  last_ts: number | null;
}

export interface StopSummary {
  capture_id: string;
  status: string;
  reason: string;
  packets_captured: number;
  packets_dropped: number;
  packets_decoded: number;
  decode_drops: number;
  files: number;
  total_bytes: number;
}

export interface ImportResult {
  capture_id: string;
  status: string;
  sha256: string;
}

export interface WebCookieRow {
  name: string;
  host: string;
  kind: string;
  set_observed: number;
  secure: number;
  http_only: number;
  same_site: string | null;
  domain: string | null;
  path: string | null;
  max_age: number | null;
  plaintext: number;
  seen_count: number;
  first_ts: number | null;
  last_ts: number | null;
}

export interface WebHeaderRow {
  host: string;
  responses: number;
  hsts: number;
  csp: number;
  x_content_type_options: number;
  x_frame_options: number;
  referrer_policy: number;
  permissions_policy: number;
  cache_control: string | null;
  server: string | null;
  first_ts: number | null;
  last_ts: number | null;
}

export interface WebTokenRow {
  fingerprint: string;
  kind: string;
  name: string | null;
  alg: string | null;
  claims: Record<string, unknown>;
  hosts: string[];
  clients: string[];
  plaintext: number;
  seen_count: number;
  first_ts: number | null;
  last_ts: number | null;
}

export interface WebAppTls {
  version: string | null;
  cipher: string | null;
  not_before: string | null;
  not_after: string | null;
  sans: string | null;
  security: string | null;
}

export interface WebApp {
  host: string;
  ips: string[];
  internal_ips: string[];
  external_ips: string[];
  ports: number[];
  dns_names: string[];
  tls: WebAppTls[];
  http_requests: number;
  http_responses: number;
  endpoints: string[];
  auth_schemes: string[];
  cookies: { name: string; kind: string }[];
  tokens: number;
  security_headers: Record<string, string | number | null> | null;
  findings: number;
}

export interface DataFlowRow {
  artifact_type: string;
  host: string | null;
  dst: string | null;
  transport_security: string | null;
  app_proto: string | null;
  http_method: string | null;
  path: string | null;
  count: number;
  first_ts: number | null;
  last_ts: number | null;
  destination_internal: boolean | null;
  transport_risk: string;
}

export interface TimelineEvent {
  ts: number | null;
  kind: string;
  title: string;
  detail: string;
  ref: string | null;
  asset: string | null;
  severity: string | null;
}

export interface TimelinePage {
  total: number;
  events: TimelineEvent[];
}

export interface GraphNode {
  id: string;
  label: string;
  kind: string;
  internal?: boolean | null;
  mac?: string | null;
  hostname_source?: string | null;
  packets?: number;
  bytes?: number;
  security?: string | null;
  severity?: string | null;
}

export interface GraphEdge {
  source: string;
  target: string;
  kind: string;
  proto?: string;
  dport?: number;
  packets?: number;
  bytes?: number;
  version?: string | null;
}

export interface GraphPage {
  nodes: GraphNode[];
  edges: GraphEdge[];
  truncated?: boolean;
}

export interface CaseItem {
  id: number;
  item_type: string;
  item_id: string;
  capture_id: string | null;
  note: string | null;
  added_by: string;
  added_at: string;
}

export interface CaseRow {
  id: string;
  title: string;
  summary: string;
  status: string;
  created_by: string;
  created_at: string;
  closed_at: string | null;
  item_count?: number;
  items?: CaseItem[];
  timeline?: TimelineEvent[];
}

export interface TunnelRow {
  capture_id: string;
  tunnel_proto: string;
  src: string;
  dst: string;
  sport: number;
  dport: number;
  state: string;
  inner_visible: number;
  packets: number;
  bytes: number;
  first_ts: number | null;
  last_ts: number | null;
  duration: number | null;
}

export interface K8sEntity {
  id: number;
  kind: string;
  namespace: string;
  name: string;
  node: string | null;
  ip: string | null;
  labels: string | null;
  ports: string | null;
  first_ts: number | null;
  last_ts: number | null;
}

export interface K8sPodInfo {
  name: string;
  namespace: string;
  node: string | null;
}

export interface K8sServiceRef {
  name: string;
  namespace: string;
}

export interface K8sCorrelationFlow {
  src: string;
  dst: string;
  proto: string;
  dport: number;
  packets: number;
  bytes: number;
  first_ts: number | null;
  last_ts: number | null;
  src_pod: K8sPodInfo | null;
  dst_pod: K8sPodInfo | null;
  src_services: K8sServiceRef[];
  dst_services: K8sServiceRef[];
}

export interface K8sCorrelation {
  capture_id: string;
  pods_known: number;
  matched: number;
  total: number;
  flows: K8sCorrelationFlow[];
}

export interface FlowlogImportResult {
  capture_id: string;
  format: string;
  records: number;
  flows: number;
  hosts: number;
  packets: number;
  bytes: number;
}

export interface K8sImportResult {
  entities: number;
  node: number;
  pod: number;
  service: number;
  namespace: number;
}

export interface AssessmentScope {
  id: string;
  name: string;
  authorization_ref: string;
  authorized_by: string;
  domains: string[];
  cidrs: string[];
  excluded_cidrs: string[];
  ports: number[];
  window_start: string | null;
  window_end: string | null;
  active: boolean;
}

export interface TestingScope {
  configured: boolean;
  error: string | null;
  assessments: AssessmentScope[];
}

export interface ControlledTestResult {
  id: number;
  test_id: string;
  seq: number;
  ts: string;
  request_kind: string;
  method: string | null;
  url: string | null;
  status_code: number | null;
  outcome: string;
  detail: string | null;
  duration_ms: number | null;
  dry_run: number;
}

export interface ControlledTestRow {
  id: string;
  created_by: string;
  created_at: string;
  authorization_ref: string;
  assessment_id: string | null;
  target: string;
  domain: string | null;
  port: number | null;
  protocol: string | null;
  test_type: string;
  artifact_type: string | null;
  artifact_id: string | null;
  case_id: string | null;
  status: string;
  dry_run: number;
  rate_limit_ms: number;
  max_requests: number;
  timeout_ms: number;
  request_count: number;
  started_at: string | null;
  ended_at: string | null;
  error: string | null;
  results?: ControlledTestResult[];
}
