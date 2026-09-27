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

export interface ContributingFactor {
  indicator: string;
  weight: number;
  mitreTactic: string;
  eventIds: string[];
  description: string;
}

export interface SecurityNode {
  id: string;
  name: string;
  type: NodeType;
  riskScore: number; // 0 - 100
  riskBand: RiskBand;
  compromised: boolean;
  classification?: string;
  firstSeenHour: number; // hours before present (48 -> 0)
  firstSeenInBaseline?: boolean; // false = anomalous first seen
  isCrownJewel?: boolean;
  isVip?: boolean;
  isPrivileged?: boolean;
  isServiceAccount?: boolean;
  isLeaver?: boolean;
  aliases?: string[]; // Canonical alias resolution (e.g. jsmith, J.Smith@corp.com, SID S-1-5-21...)
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
  hour: number; // hours before present (48 -> 0)
  eventCount: number;
  status: 'allowed' | 'blocked' | 'anomalous' | 'critical';
  details: string;
  firstSeenInBaseline?: boolean; // false = dashed edge
  ttp?: string[]; // MITRE ATT&CK technique IDs e.g. ["T1110", "T1078"]
  eventIds?: string[];
  rawSourceLink?: string;
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

export interface CaseRecord {
  id: string;
  caseRef: string;
  title: string;
  rootEntity: string;
  analyst: string;
  status: 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'CLOSED';
  severity: 'P1' | 'P2' | 'P3';
  windowHours: number;
  nodeCount: number;
  compromisedCount: number;
  sha256?: string;
  createdAt: string;
  notes?: string;
  verdict?: 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS';
  pushedTo?: string[];
}

export type ViewTab = 'watchlist' | 'investigation' | 'replay' | 'cases' | 'integrations' | 'admin';
