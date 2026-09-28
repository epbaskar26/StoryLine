export type NodeType = 'user' | 'host' | 'ip' | 'application' | 'file' | 'process' | 'domain' | 'alert' | 'query'
  | 'software' | 'service' | 'task' | 'registry' | 'device' | 'event';

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
  | 'TRIGGERED'
  | 'SPAWNED' // parent process started a child process
  | 'WROTE' // process created or modified a file
  | 'MATCHED' // log search matched this identity (search graphs)
  | 'INSTALLED' // installed software
  | 'UNINSTALLED' // removed software
  | 'SERVICE_INSTALL' // installed a Windows service
  | 'SCHEDULED_TASK' // created a scheduled task
  | 'REGISTRY_SET' // set an autorun / persistence registry value
  | 'ACCESSED_PROCESS' // opened another process (e.g. LSASS read)
  | 'DETECTED' // security product detection (Defender, EDR)
  | 'CONNECTED_DEVICE' // USB / removable device
  | 'OBSERVED'; // generic: an event WatchMe does not model as its own edge yet

export type RiskBand = 'LOW' | 'MEDIUM' | 'HIGH';

export type DataSource = 'demo' | 'splunk' | 'elastic' | 'snapshot';

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
  executions?: ProcessExecution[]; // process nodes: distinct command lines seen in the window
  isNew?: boolean; // live mode: appeared since the previous refresh
}

export interface ProcessExecution {
  ts: string; // first time this command line was seen
  lastTs?: string;
  commandLine: string;
  parent?: string;
  user?: string;
  eventId?: string;
  count: number;
  source?: string; // e.g. "Sysmon 1", "Security 4688", "PowerShell 4104 (script block)"
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
  rootId?: string; // node the investigation starts from (the user, or the query node for search graphs)
  kind?: 'entity' | 'search';
  query?: string; // search graphs: the analyst's query
  windowStart?: string; // ISO start of the window (t0 - windowHours)
  coverage?: Record<string, number>; // event count per category, for the coverage panel
  unmappedEventCount?: number; // events shown as generic activity
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
  assignee?: string;
  disposition?: Disposition;
  closureNotes?: string;
  closedAt?: string;
  closedBy?: string;
  storyline?: Storyline; // approved AI storyline, frozen with the case
}

export type Disposition = 'TRUE_POSITIVE_MALICIOUS' | 'TRUE_POSITIVE_BENIGN' | 'FALSE_POSITIVE' | 'INCONCLUSIVE' | 'DUPLICATE';

export type NoteKind = 'NOTE' | 'HYPOTHESIS' | 'VERDICT' | 'ASSIGNMENT' | 'CLOSURE' | 'AI_STORYLINE';

export interface InvestigationNote {
  id: string;
  entityKey: string;
  caseId?: string;
  nodeId?: string;
  nodeName?: string;
  kind: NoteKind;
  verdict?: 'BENIGN' | 'MALICIOUS';
  text: string;
  analyst: string;
  createdAt: string;
}

// AI Storyline: an interpretation layered on top of the evidence path. Every step cites a real edge.
export interface StoryStep {
  edgeId: string;
  nodeId: string;
  entity: string;
  time: string; // ISO time of the cited visit
  title: string;
  explanation: string;
  techniques: string[];
}

export interface StoryPhase {
  name: string;
  tactic: string;
  summary: string;
  confidence: 'high' | 'medium' | 'low';
  steps: StoryStep[];
}

export interface Storyline {
  verdict: 'attack' | 'suspicious' | 'no_pattern';
  headline: string;
  summary: string;
  phases: StoryPhase[];
  benignExplanations: string[];
  gaps: string[];
  engine: string;
  aiGenerated: boolean;
  generatedAt: string;
  sha256: string;
  droppedSteps: number; // steps the model returned with citations that do not exist
  injectionWarnings: string[]; // log fields that looked like instructions to the model
  approvedBy?: string;
  approvedAt?: string;
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
  dataSource: 'demo' | 'splunk' | 'elastic';
  liveConfigured: boolean;
  liveLabel: string | null; // e.g. "Splunk" or "Elastic"
  queryLanguage: string | null; // e.g. "SPL" or "Lucene"
  storage: 'postgres' | 'memory';
  aiConfigured: boolean;
  aiProvider: 'gemini' | 'ollama' | 'none';
  aiModel: string | null;
  analyst: string;
  lastGraphBuildMs: number | null;
}

export type ViewTab = 'watchlist' | 'investigation' | 'replay' | 'cases' | 'integrations' | 'admin';
