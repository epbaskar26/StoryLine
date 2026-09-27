export type NodeType = 'user' | 'host' | 'ip' | 'application' | 'file' | 'process' | 'domain' | 'alert';

export type EdgeType =
  | 'AUTH_FAIL'
  | 'AUTH_SUCCESS'
  | 'FROM_IP'
  | 'CONNECTED_TO'
  | 'ACCESSED'
  | 'EXECUTED'
  | 'RAN_ON'
  | 'MEMBER_CHANGE'
  | 'UPLOADED'
  | 'TRIGGERED';

export type RiskBand = 'LOW' | 'MEDIUM' | 'HIGH';

export type DataSource = 'demo' | 'splunk' | 'snapshot';

export interface ContributingFactor {
  indicator: string;
  weight: number;
  mitreTactic: string;
  eventIds: string[];
  description: string;
  edgeIds?: string[];
}

export interface SecurityNode {
  id: string;
  name: string;
  type: NodeType;
  riskScore: number; // 0 - 100
  riskBand: RiskBand;
  compromised: boolean; // true = involved in a high-risk (critical) edge
  classification?: string;
  firstSeenHour: number; // hours before T-0 (windowHours -> 0)
  firstSeen?: string; // ISO timestamp of first activity in window
  lastSeen?: string; // ISO timestamp of last activity in window
  firstSeenInBaseline?: boolean; // false = not seen in baseline period; undefined = no baseline available
  isCrownJewel?: boolean;
  isVip?: boolean;
  isPrivileged?: boolean;
  isServiceAccount?: boolean;
  isLeaver?: boolean;
  aliases?: string[];
  details: Record<string, string>;
  contributingFactors?: ContributingFactor[];
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
  pinned?: boolean;
  annotation?: string;
}

export interface SecurityEdge {
  id: string;
  source: string;
  target: string;
  action: string;
  type: EdgeType;
  protocol: string;
  hour: number; // hours before T-0 of the first event on this edge
  firstSeen?: string;
  lastSeen?: string;
  eventCount: number;
  status: 'allowed' | 'blocked' | 'anomalous' | 'critical';
  details: string;
  firstSeenInBaseline?: boolean; // false = dashed edge
  ttp?: string[];
  eventIds?: string[];
  rawSourceLink?: string;
  // Separate visits on this edge (events more than 30 min apart); absent for demo data (one visit at firstSeen)
  visits?: { start: string; end: string; count: number; status?: 'critical' | 'anomalous'; ttp?: string[] }[];
}

export interface SecurityMilestone {
  hour: number;
  timeLabel: string;
  title: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  mitreTactic: string;
  edgeId?: string;
}

export interface UserProfile {
  id: string;
  canonicalId: string;
  username: string;
  fullName: string;
  role: string;
  department: string;
  baselineLocation: string;
  device: string;
  riskScore: number;
  riskBand: RiskBand;
  isVip?: boolean;
  isPrivileged?: boolean;
  isLeaver?: boolean;
  isServiceAccount?: boolean;
  alertSummary: string;
  triggerEvent: string;
  aliases: string[];
  nodes: SecurityNode[];
  edges: SecurityEdge[];
  milestones: SecurityMilestone[];
  contributingFactors: ContributingFactor[];
  // Provenance and window metadata
  dataSource?: DataSource;
  t0?: string; // ISO timestamp of T-0
  windowHours?: number;
  truncated?: boolean;
  totalEventCount?: number;
  totalNodeCount?: number;
  totalEdgeCount?: number;
  baselineAvailable?: boolean;
  notes?: string[]; // limitations / warnings to show the analyst
}

export interface EntitySummary {
  id: string; // entity key used in /api/graph/:id
  username: string;
  fullName: string;
  riskScore: number;
  triggerEvent: string;
}

export interface WatchlistItem {
  id: string;
  entityId: string;
  canonicalName: string;
  entityType: NodeType;
  riskScore: number;
  riskBand: RiskBand;
  owner: string;
  reason: string;
  expiry: string;
  sparkline: number[];
  addedAt: string;
}

export interface EvidenceRecord {
  kind: 'REPLAY_VIDEO' | 'GRAPH_PNG' | 'SNAPSHOT';
  fileName: string;
  mimeType: string;
  sizeBytes: number;
  sha256: string;
  analyst: string;
  createdAt: string;
}

export interface CaseRecord {
  id: string;
  caseRef: string;
  title: string;
  rootEntity: string;
  entityKey?: string;
  analyst: string;
  status: 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'CLOSED';
  severity: 'P1' | 'P2' | 'P3';
  windowHours: number;
  nodeCount: number;
  compromisedCount: number;
  sha256?: string; // SHA-256 of the saved graph snapshot JSON
  createdAt: string;
  notes?: string;
  verdict?: 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS';
  pushedTo?: string[];
  evidence?: EvidenceRecord[];
  dataSource?: DataSource;
  hasSnapshot?: boolean; // false for seeded demo cases
}

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  analyst: string;
  action: string;
  entityId: string;
  details: string;
  sha256?: string;
}

export interface CitationAudit {
  totalCitations: number;
  validCitations: number;
  invalidCitations: string[];
  uncitedLines: number;
}

export interface SystemStatus {
  dataSource: 'demo' | 'splunk';
  splunkConfigured: boolean;
  storage: 'postgres' | 'memory';
  aiConfigured: boolean;
  analyst: string;
  lastGraphBuildMs: number | null;
}

export type ViewTab = 'watchlist' | 'investigation' | 'replay' | 'cases' | 'integrations' | 'admin';
