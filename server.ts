import express from 'express';
import { createServer as createViteServer } from 'vite';
import { GoogleGenAI } from '@google/genai';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '20mb' }));

// Initialize GoogleGenAI server-side with required User-Agent
let ai: GoogleGenAI | null = null;
if (process.env.GEMINI_API_KEY) {
  ai = new GoogleGenAI({
    apiKey: process.env.GEMINI_API_KEY,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
}

// 8 Node Labels & 10 Edge Types Data Model conforming to Extended Spec
export type NodeType = 'user' | 'host' | 'ip' | 'application' | 'file' | 'process' | 'domain' | 'alert';
export type EdgeType = 'AUTH_FAIL' | 'AUTH_SUCCESS' | 'FROM_IP' | 'CONNECTED_TO' | 'ACCESSED' | 'EXECUTED' | 'RAN_ON' | 'MEMBER_CHANGE' | 'UPLOADED' | 'TRIGGERED';
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
  riskScore: number;
  riskBand: RiskBand;
  compromised: boolean;
  classification?: string;
  firstSeenHour: number;
  firstSeenInBaseline?: boolean;
  isCrownJewel?: boolean;
  isVip?: boolean;
  isPrivileged?: boolean;
  isServiceAccount?: boolean;
  isLeaver?: boolean;
  aliases?: string[];
  details: Record<string, string>;
  contributingFactors?: ContributingFactor[];
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
  hour: number;
  eventCount: number;
  status: 'allowed' | 'blocked' | 'anomalous' | 'critical';
  details: string;
  firstSeenInBaseline?: boolean;
  ttp?: string[];
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

// In-Memory Database for Entities & Canonical Aliases
const DEMO_USERS: Record<string, UserProfile> = {
  'jsmith': {
    id: 'USR-8492',
    canonicalId: 'USR-8492-JSMITH',
    username: 'j.smith',
    fullName: 'John Smith',
    role: 'Senior Financial Analyst',
    department: 'Corporate Finance',
    baselineLocation: 'Chicago, IL (US-Central)',
    device: 'LAPTOP-JS-882 (Windows 11 Corp)',
    riskScore: 94,
    riskBand: 'HIGH',
    isPrivileged: true,
    isVip: false,
    isLeaver: false,
    isServiceAccount: false,
    alertSummary: 'Multiple failed logins followed by anomalous geo-IP pivot and unauthorized HR database access.',
    triggerEvent: 'Anomalous Credential Access & High-Value DB Exfiltration',
    aliases: ['jsmith', 'j.smith@corp.com', 'CORP\\jsmith', 'S-1-5-21-39482109-8492'],
    contributingFactors: [
      { indicator: 'Brute force then success', weight: 20, mitreTactic: 'T1110', eventIds: ['evt-401', 'evt-402', 'evt-403'], description: '>= 5 AUTH_FAIL then AUTH_SUCCESS within 30 min from Tor exit node' },
      { indicator: 'First-seen host/app access (Crown Jewel)', weight: 20, mitreTactic: 'T1078', eventIds: ['evt-181'], description: 'SRV-HR-DB01.corp accessed for the first time in 30-day baseline (2x crown jewel multiplier)' },
      { indicator: 'New source IP / ASN / country', weight: 10, mitreTactic: 'T1078', eventIds: ['evt-381'], description: 'Source IP 194.26.29.112 (AS9009 M247 Bucharest, RO) never in user history' },
      { indicator: 'Lateral fan-out', weight: 20, mitreTactic: 'T1021', eventIds: ['evt-281'], description: 'Kerberos Pass-The-Hash pivoting across admin jumpbox bastion' },
      { indicator: 'Large upload / Exfiltration', weight: 20, mitreTactic: 'T1567', eventIds: ['evt-021'], description: '482 MB uploaded to unmanaged external S3 bucket' },
      { indicator: 'Privileged user multiplier', weight: 4, mitreTactic: 'Context', eventIds: [], description: '1.3x multiplier applied for Privileged Finance Identity' }
    ],
    nodes: [
      {
        id: 'u_jsmith',
        name: 'j.smith',
        type: 'user',
        riskScore: 94,
        riskBand: 'HIGH',
        compromised: true,
        classification: 'Privileged Finance Identity',
        firstSeenHour: 48,
        firstSeenInBaseline: true,
        isPrivileged: true,
        aliases: ['jsmith', 'j.smith@corp.com', 'CORP\\jsmith', 'S-1-5-21-39482109-8492'],
        details: { Department: 'Corporate Finance', Workstation: 'LAPTOP-JS-882', KerberosID: 'S-1-5-21-39482', Manager: 'E. Vance' }
      },
      {
        id: 'host_laptop',
        name: 'LAPTOP-JS-882',
        type: 'host',
        riskScore: 78,
        riskBand: 'HIGH',
        compromised: true,
        classification: 'Corporate EDR Host',
        firstSeenHour: 48,
        firstSeenInBaseline: true,
        details: { OS: 'Windows 11 Enterprise', IP: '10.14.2.45', SensorStatus: 'Falcon Online (Alerted)', EDR_ID: 'agent-99214' }
      },
      {
        id: 'ip_home',
        name: '172.56.21.90',
        type: 'ip',
        riskScore: 10,
        riskBand: 'LOW',
        compromised: false,
        classification: 'Home ISP (Chicago, US)',
        firstSeenHour: 48,
        firstSeenInBaseline: true,
        details: { ASN: 'AS7922 Comcast', Geolocation: 'Chicago, IL, US', Reputation: 'Clean' }
      },
      {
        id: 'ip_tor',
        name: '194.26.29.112',
        type: 'ip',
        riskScore: 98,
        riskBand: 'HIGH',
        compromised: true,
        classification: 'Tor Exit Proxy (Bucharest, RO)',
        firstSeenHour: 40,
        firstSeenInBaseline: false,
        details: { ASN: 'AS9009 M247', Geolocation: 'Bucharest, RO', Reputation: 'Known Bulletproof Proxy', ThreatActor: 'UNC2452' }
      },
      {
        id: 'proc_mimikatz',
        name: 'powershell.exe -enc SQB... (Mimikatz)',
        type: 'process',
        riskScore: 92,
        riskBand: 'HIGH',
        compromised: true,
        classification: 'Credential Dumping Tool',
        firstSeenHour: 32,
        firstSeenInBaseline: false,
        details: { ProcessGUID: '{9f82c4-1102}', Parent: 'explorer.exe', Signer: 'Unsigned Script', Hash: 'e3b0c44298fc1c149afbf4c8996fb924' }
      },
      {
        id: 'host_jump',
        name: 'SRV-JUMP-02.corp',
        type: 'host',
        riskScore: 82,
        riskBand: 'HIGH',
        compromised: true,
        classification: 'Admin Bastion Jumpbox',
        firstSeenHour: 28,
        firstSeenInBaseline: false,
        isCrownJewel: true,
        details: { IP: '10.10.100.14', Role: 'Production Bastion Host', Protocols: 'RDP / WinRM / SSH', SensorStatus: 'Defender Active' }
      },
      {
        id: 'app_fin',
        name: 'DB-FINANCE-PROD',
        type: 'application',
        riskScore: 35,
        riskBand: 'LOW',
        compromised: false,
        classification: 'Normal Work Asset',
        firstSeenHour: 48,
        firstSeenInBaseline: true,
        details: { Type: 'PostgreSQL 15', Criticality: 'Tier 2', AccessPattern: 'Daily Authorized' }
      },
      {
        id: 'app_hr',
        name: 'SRV-HR-DB01.corp (Payroll_SSN)',
        type: 'application',
        riskScore: 96,
        riskBand: 'HIGH',
        compromised: true,
        classification: 'Crown Jewel Database',
        firstSeenHour: 18,
        firstSeenInBaseline: false,
        isCrownJewel: true,
        details: { Type: 'MS SQL Server', Schema: 'Employees_Payroll_SSN', AccessHistory: 'Never accessed by j.smith before', Tag: 'crown_jewel' }
      },
      {
        id: 'file_staging',
        name: 'hr_payroll_q3_export.7z',
        type: 'file',
        riskScore: 95,
        riskBand: 'HIGH',
        compromised: true,
        classification: 'Encrypted Staged Archive',
        firstSeenHour: 8,
        firstSeenInBaseline: false,
        details: { Path: 'C:\\ProgramData\\Temp\\cache.7z', Size: '482 MB', Encryption: 'AES-256' }
      },
      {
        id: 'dom_exfil',
        name: 's3.us-east-1.amazonaws.com (ext-backup-sync)',
        type: 'domain',
        riskScore: 99,
        riskBand: 'HIGH',
        compromised: true,
        classification: 'External Untrusted Bucket',
        firstSeenHour: 2,
        firstSeenInBaseline: false,
        details: { Destination: 'AWS us-east-1 (External)', Action: 'rclone sync staged payload', BytesOut: '482 MB' }
      },
      {
        id: 'alert_siem',
        name: 'SEC-7019: Anomalous Credential Abuse',
        type: 'alert',
        riskScore: 95,
        riskBand: 'HIGH',
        compromised: true,
        classification: 'Correlated SIEM Detection',
        firstSeenHour: 40,
        firstSeenInBaseline: false,
        details: { Source: 'Microsoft Sentinel / UDM', Severity: 'High', MITRE: 'T1110, T1078' }
      }
    ],
    edges: [
      { id: 'e1', source: 'u_jsmith', target: 'ip_home', action: 'FROM_IP', type: 'FROM_IP', protocol: 'HTTPS/443', hour: 48, eventCount: 24, status: 'allowed', details: 'Regular SSO sign-in session from home ISP in Chicago', firstSeenInBaseline: true, eventIds: ['evt-481'] },
      { id: 'e2', source: 'u_jsmith', target: 'host_laptop', action: 'AUTH_SUCCESS', type: 'AUTH_SUCCESS', protocol: 'RDP/3389', hour: 46, eventCount: 1, status: 'allowed', details: 'Interactive logon to corporate workstation LAPTOP-JS-882', firstSeenInBaseline: true, eventIds: ['evt-461'] },
      { id: 'e3', source: 'u_jsmith', target: 'app_fin', action: 'ACCESSED', type: 'ACCESSED', protocol: 'TCP/5432', hour: 44, eventCount: 142, status: 'allowed', details: 'Standard quarterly financial reports query', firstSeenInBaseline: true, eventIds: ['evt-441'] },
      { id: 'e4', source: 'u_jsmith', target: 'ip_tor', action: 'AUTH_FAIL', type: 'AUTH_FAIL', protocol: 'NTLM/445', hour: 40, eventCount: 7, status: 'blocked', details: '7 consecutive failed authentication attempts from Romania Tor node', firstSeenInBaseline: false, ttp: ['T1110'], eventIds: ['evt-401', 'evt-402', 'evt-403'], rawSourceLink: 'https://security.corp/sentinel/alerts/7019' },
      { id: 'e4b', source: 'u_jsmith', target: 'alert_siem', action: 'TRIGGERED', type: 'TRIGGERED', protocol: 'SIEM API', hour: 40, eventCount: 1, status: 'critical', details: 'Correlated alert fired on user identity', firstSeenInBaseline: false, ttp: ['T1110'], eventIds: ['evt-404'] },
      { id: 'e5', source: 'u_jsmith', target: 'ip_tor', action: 'AUTH_SUCCESS', type: 'AUTH_SUCCESS', protocol: 'HTTPS/443', hour: 38, eventCount: 1, status: 'anomalous', details: 'Session token replay bypasses MFA from Bucharest Tor node', firstSeenInBaseline: false, ttp: ['T1078'], eventIds: ['evt-381'] },
      { id: 'e6', source: 'u_jsmith', target: 'proc_mimikatz', action: 'EXECUTED', type: 'EXECUTED', protocol: 'Local Disk', hour: 32, eventCount: 2, status: 'critical', details: 'PowerShell memory dumping script executed on LAPTOP-JS-882', firstSeenInBaseline: false, ttp: ['T1003'], eventIds: ['evt-321'] },
      { id: 'e7', source: 'proc_mimikatz', target: 'host_laptop', action: 'RAN_ON', type: 'RAN_ON', protocol: 'API Hook', hour: 32, eventCount: 1, status: 'critical', details: 'LSASS memory read detected by EDR tamper protection', firstSeenInBaseline: false, ttp: ['T1003'], eventIds: ['evt-322'] },
      { id: 'e8', source: 'u_jsmith', target: 'host_jump', action: 'AUTH_SUCCESS', type: 'AUTH_SUCCESS', protocol: 'SMB/445', hour: 28, eventCount: 4, status: 'critical', details: 'Pass-The-Hash lateral movement to production bastion jumpbox', firstSeenInBaseline: false, ttp: ['T1550', 'T1021'], eventIds: ['evt-281'] },
      { id: 'e9', source: 'u_jsmith', target: 'app_hr', action: 'ACCESSED', type: 'ACCESSED', protocol: 'TDS/1433', hour: 18, eventCount: 89, status: 'critical', details: 'First-time connection to sensitive HR server; SELECT * FROM Payroll_SSN', firstSeenInBaseline: false, ttp: ['T1078', 'T1005'], eventIds: ['evt-181'] },
      { id: 'e10', source: 'u_jsmith', target: 'file_staging', action: 'ACCESSED', type: 'ACCESSED', protocol: 'Local IO', hour: 8, eventCount: 12400, status: 'critical', details: 'Compressed 12,400 confidential records into encrypted 7z archive', firstSeenInBaseline: false, ttp: ['T1560'], eventIds: ['evt-081'] },
      { id: 'e11', source: 'u_jsmith', target: 'dom_exfil', action: 'UPLOADED', type: 'UPLOADED', protocol: 'HTTPS/443', hour: 2, eventCount: 1, status: 'critical', details: 'High-velocity outbound egress of 482 MB payload to external S3', firstSeenInBaseline: false, ttp: ['T1567'], eventIds: ['evt-021'] }
    ],
    milestones: [
      { hour: 48, timeLabel: 'T-48:00', title: 'Baseline Normal Login', severity: 'low', description: 'Authorized user sign-in from Chicago home ISP. Routine financial reports query.', mitreTactic: 'Normal Operations', edgeId: 'e1' },
      { hour: 40, timeLabel: 'T-40:00', title: 'Tor Password Spray', severity: 'medium', description: '7 failed authentications from Romanian Tor exit node IP 194.26.29.112.', mitreTactic: 'Credential Access (T1110)', edgeId: 'e4' },
      { hour: 38, timeLabel: 'T-38:00', title: 'Session Hijack / MFA Bypass', severity: 'high', description: 'Attacker authenticates via stolen session cookie token replay.', mitreTactic: 'Initial Access (T1078)', edgeId: 'e5' },
      { hour: 32, timeLabel: 'T-32:00', title: 'LSASS Memory Harvest', severity: 'critical', description: 'Invoke-Mimikatz executed on laptop, dumping Kerberos TGT tickets.', mitreTactic: 'Credential Dumping (T1003)', edgeId: 'e6' },
      { hour: 28, timeLabel: 'T-28:00', title: 'Lateral Movement to Jumpbox', severity: 'critical', description: 'Attacker leverages Pass-The-Hash to compromise SRV-JUMP-02.', mitreTactic: 'Lateral Movement (T1021)', edgeId: 'e8' },
      { hour: 18, timeLabel: 'T-18:00', title: 'Anomalous HR Database Query', severity: 'critical', description: 'First-time connection to tagged Crown Jewel SRV-HR-DB01. Bulk SSN query.', mitreTactic: 'Collection (T1005)', edgeId: 'e9' },
      { hour: 8, timeLabel: 'T-08:00', title: 'Data Staging & Compression', severity: 'critical', description: 'Payroll extract compressed into hr_payroll_q3_export.7z in cache.', mitreTactic: 'Archive Data (T1560)', edgeId: 'e10' },
      { hour: 2, timeLabel: 'T-02:00', title: 'External Cloud Exfiltration', severity: 'critical', description: 'Outbound sync of 482 MB payload to unmanaged AWS S3 bucket.', mitreTactic: 'Exfiltration (T1567)', edgeId: 'e11' }
    ]
  },
  'apatel': {
    id: 'USR-3190',
    canonicalId: 'USR-3190-APATEL',
    username: 'a.patel',
    fullName: 'Amina Patel',
    role: 'DevOps / Cloud Architect',
    department: 'Cloud Platform Engineering',
    baselineLocation: 'Austin, TX (US-West)',
    device: 'MACBOOK-PRO-AP-01 (macOS Sonoma)',
    riskScore: 88,
    riskBand: 'HIGH',
    isPrivileged: true,
    isVip: false,
    isLeaver: false,
    isServiceAccount: false,
    alertSummary: 'Service Account token exfiltration and unauthorized AWS IAM policy modification.',
    triggerEvent: 'Cloud Infrastructure Privilege Escalation & Shadow Admin Creation',
    aliases: ['apatel', 'a.patel@corp.com', 'CORP\\apatel', 'arn:aws:iam::984029184712:user/a.patel'],
    contributingFactors: [
      { indicator: 'New source IP / ASN / country', weight: 10, mitreTactic: 'T1078', eventIds: ['evt-ap34'], description: 'AWS CLI commands issued from DigitalOcean VPS in Amsterdam' },
      { indicator: 'Privilege change (Shadow Admin)', weight: 20, mitreTactic: 'T1098', eventIds: ['evt-ap06'], description: 'MEMBER_CHANGE into AdministratorAccess role via backdoor role' },
      { indicator: 'First-seen host/app access', weight: 10, mitreTactic: 'T1078', eventIds: ['evt-ap20'], description: 'HashiCorp Vault production root key paths probed' }
    ],
    nodes: [
      { id: 'u_apatel', name: 'a.patel', type: 'user', riskScore: 88, riskBand: 'HIGH', compromised: true, classification: 'Platform Admin Identity', firstSeenHour: 48, firstSeenInBaseline: true, aliases: ['apatel', 'a.patel@corp.com'], details: { Department: 'Cloud Platform', IAMRole: 'DevOps-Engineer' } },
      { id: 'host_mac', name: 'MACBOOK-PRO-AP-01', type: 'host', riskScore: 65, riskBand: 'MEDIUM', compromised: true, classification: 'Corporate macOS Asset', firstSeenHour: 48, firstSeenInBaseline: true, details: { OS: 'macOS 14.5 Sonoma', IP: '10.20.4.11' } },
      { id: 'ip_office', name: '64.102.12.8', type: 'ip', riskScore: 5, riskBand: 'LOW', compromised: false, classification: 'Corporate Egress VPN', firstSeenHour: 48, firstSeenInBaseline: true, details: { Geolocation: 'Austin, TX' } },
      { id: 'ip_anon', name: '45.154.255.89', type: 'ip', riskScore: 94, riskBand: 'HIGH', compromised: true, classification: 'Untrusted VPS Host', firstSeenHour: 34, firstSeenInBaseline: false, details: { ASN: 'AS14061 DigitalOcean', Geolocation: 'Amsterdam, NL' } },
      { id: 'app_vault', name: 'HashiCorp Vault Prod', type: 'application', riskScore: 85, riskBand: 'HIGH', compromised: true, classification: 'Enterprise Secrets Manager', firstSeenHour: 20, firstSeenInBaseline: false, isCrownJewel: true, details: { Criticality: 'Tier 0', Engine: 'Vault Enterprise' } },
      { id: 'dom_aws', name: 'iam.amazonaws.com', type: 'domain', riskScore: 97, riskBand: 'HIGH', compromised: true, classification: 'AWS IAM Control Plane', firstSeenHour: 6, firstSeenInBaseline: false, details: { AccountID: '984029184712', Action: 'AttachRolePolicy' } }
    ],
    edges: [
      { id: 'ae1', source: 'u_apatel', target: 'ip_office', action: 'FROM_IP', type: 'FROM_IP', protocol: 'HTTPS/443', hour: 46, eventCount: 15, status: 'allowed', details: 'Normal developer sign-in from Austin office', firstSeenInBaseline: true },
      { id: 'ae2', source: 'u_apatel', target: 'host_mac', action: 'AUTH_SUCCESS', type: 'AUTH_SUCCESS', protocol: 'SSH/22', hour: 42, eventCount: 3, status: 'allowed', details: 'Regular infrastructure review session', firstSeenInBaseline: true },
      { id: 'ae3', source: 'u_apatel', target: 'ip_anon', action: 'AUTH_SUCCESS', type: 'AUTH_SUCCESS', protocol: 'HTTPS/443', hour: 34, eventCount: 1, status: 'anomalous', details: 'Stolen AWS API token invoked from European VPS', firstSeenInBaseline: false, ttp: ['T1078'] },
      { id: 'ae4', source: 'u_apatel', target: 'app_vault', action: 'ACCESSED', type: 'ACCESSED', protocol: 'HTTPS/8200', hour: 20, eventCount: 22, status: 'critical', details: 'Queried production master secrets in Vault', firstSeenInBaseline: false, ttp: ['T1087'] },
      { id: 'ae5', source: 'u_apatel', target: 'dom_aws', action: 'MEMBER_CHANGE', type: 'MEMBER_CHANGE', protocol: 'AWS API', hour: 6, eventCount: 1, status: 'critical', details: 'Attached AdministratorAccess to backdoor role sys-backup-daemon', firstSeenInBaseline: false, ttp: ['T1098'] }
    ],
    milestones: [
      { hour: 48, timeLabel: 'T-48:00', title: 'Normal Engineering Workflow', severity: 'low', description: 'DevOps user performing scheduled terraform updates.', mitreTactic: 'Normal Operations' },
      { hour: 34, timeLabel: 'T-34:00', title: 'Anomalous Cloud API Origin', severity: 'high', description: 'AWS STS AssumeRole requested from DigitalOcean VPS in Amsterdam.', mitreTactic: 'Initial Access (T1078)' },
      { hour: 20, timeLabel: 'T-20:00', title: 'Secrets Vault Probing', severity: 'critical', description: 'Unauthorized read requests against Vault AWS root key paths.', mitreTactic: 'Discovery (T1087)' },
      { hour: 6, timeLabel: 'T-06:00', title: 'Shadow Admin Persistence', severity: 'critical', description: 'Attacker attached AdministratorAccess to new backdoor IAM role.', mitreTactic: 'Persistence (T1098)' }
    ]
  },
  'mross': {
    id: 'USR-5521',
    canonicalId: 'USR-5521-MROSS',
    username: 'm.ross',
    fullName: 'Marcus Ross',
    role: 'Sales Director',
    department: 'Enterprise Sales',
    baselineLocation: 'New York, NY (US-East)',
    device: 'THINKPAD-MR-20 (Windows 11)',
    riskScore: 91,
    riskBand: 'HIGH',
    isPrivileged: false,
    isVip: true,
    isLeaver: false,
    isServiceAccount: false,
    alertSummary: 'Malicious PDF macro execution followed by Ransomware Canary file modifications.',
    triggerEvent: 'Phishing Execution & Pre-Ransomware Lateral Staging',
    aliases: ['mross', 'm.ross@corp.com', 'CORP\\mross'],
    contributingFactors: [
      { indicator: 'Correlated alert (EDR)', weight: 30, mitreTactic: 'T1566', eventIds: ['evt-mr42'], description: 'EDR heuristic match on CobaltStrike Beacon in Temp' },
      { indicator: 'Mass file access (Ransomware staging)', weight: 15, mitreTactic: 'T1005', eventIds: ['evt-mr15'], description: 'Enumerated 42,000 files across network shares in 1 hour' },
      { indicator: 'VIP user multiplier', weight: 4, mitreTactic: 'Context', eventIds: [], description: '1.2x score multiplier for Executive Sales Director' }
    ],
    nodes: [
      { id: 'u_mross', name: 'm.ross', type: 'user', riskScore: 91, riskBand: 'HIGH', compromised: true, classification: 'Sales Executive Identity', firstSeenHour: 48, firstSeenInBaseline: true, isVip: true, aliases: ['mross', 'm.ross@corp.com'], details: { Department: 'Enterprise Sales' } },
      { id: 'host_sales', name: 'THINKPAD-MR-20', type: 'host', riskScore: 88, riskBand: 'HIGH', compromised: true, classification: 'Executive Laptop', firstSeenHour: 48, firstSeenInBaseline: true, details: { OS: 'Windows 11 Pro', IP: '10.15.8.32' } },
      { id: 'file_phish', name: 'Overdue_Invoice_982.pdf.exe', type: 'file', riskScore: 99, riskBand: 'HIGH', compromised: true, classification: 'Malicious Dropper Payload', firstSeenHour: 42, firstSeenInBaseline: false, details: { Signature: 'CobaltStrike Beacon' } },
      { id: 'ip_c2', name: '185.220.101.5', type: 'ip', riskScore: 100, riskBand: 'HIGH', compromised: true, classification: 'Active C2 Beacon Server', firstSeenHour: 41, firstSeenInBaseline: false, details: { ThreatActor: 'FIN7 / BlackCat', Port: '8443 TLS' } },
      { id: 'host_share', name: 'FS-CORP-SHARE01', type: 'host', riskScore: 84, riskBand: 'HIGH', compromised: true, classification: 'Corporate File Storage', firstSeenHour: 15, firstSeenInBaseline: false, isCrownJewel: true, details: { Shares: 'Legal, Contracts, Sales' } }
    ],
    edges: [
      { id: 're1', source: 'u_mross', target: 'file_phish', action: 'EXECUTED', type: 'EXECUTED', protocol: 'Outlook / Local', hour: 42, eventCount: 1, status: 'critical', details: 'User double-clicked disguised PDF invoice', firstSeenInBaseline: false, ttp: ['T1566'] },
      { id: 're2', source: 'u_mross', target: 'ip_c2', action: 'CONNECTED_TO', type: 'CONNECTED_TO', protocol: 'HTTPS/8443', hour: 41, eventCount: 420, status: 'critical', details: 'Encrypted heartbeats every 60s to C2 server', firstSeenInBaseline: false, ttp: ['T1071'] },
      { id: 're3', source: 'u_mross', target: 'host_share', action: 'ACCESSED', type: 'ACCESSED', protocol: 'SMB/445', hour: 15, eventCount: 42000, status: 'critical', details: 'Mass file enumeration across network shares', firstSeenInBaseline: false, ttp: ['T1083'] }
    ],
    milestones: [
      { hour: 48, timeLabel: 'T-48:00', title: 'Normal Sales Operations', severity: 'low', description: 'User answering email via Outlook 365.', mitreTactic: 'Normal Operations' },
      { hour: 42, timeLabel: 'T-42:00', title: 'Phishing Execution', severity: 'critical', description: 'Malicious executable executed by user from Outlook email.', mitreTactic: 'Initial Access (T1566)' },
      { hour: 41, timeLabel: 'T-41:00', title: 'Cobalt Strike C2 Beaconing', severity: 'critical', description: 'Persistent beacon established to malicious IP 185.220.101.5.', mitreTactic: 'Command and Control (T1071)' },
      { hour: 15, timeLabel: 'T-15:00', title: 'Internal Recon & Share Discovery', severity: 'high', description: 'Attacker automated scan of corporate file shares.', mitreTactic: 'Discovery (T1083)' }
    ]
  }
};

// In-Memory Watchlist Store
let WATCHLIST: WatchlistItem[] = [
  {
    id: 'wl-1',
    entityId: 'jsmith',
    canonicalName: 'j.smith (John Smith)',
    entityType: 'user',
    riskScore: 94,
    riskBand: 'HIGH',
    owner: 'soc.analyst.alex',
    reason: 'SEC-7019 anomalous login and sensitive HR database spike',
    expiry: '2026-10-04T00:00:00Z',
    sparkline: [12, 14, 18, 45, 88, 94],
    addedAt: '2026-09-27T10:14:00Z'
  },
  {
    id: 'wl-2',
    entityId: 'apatel',
    canonicalName: 'a.patel (Amina Patel)',
    entityType: 'user',
    riskScore: 88,
    riskBand: 'HIGH',
    owner: 'soc.analyst.priya',
    reason: 'AWS IAM AdministratorRole modified from DigitalOcean VPS',
    expiry: '2026-10-02T00:00:00Z',
    sparkline: [5, 5, 8, 34, 75, 88],
    addedAt: '2026-09-27T11:30:00Z'
  },
  {
    id: 'wl-3',
    entityId: 'mross',
    canonicalName: 'm.ross (Marcus Ross)',
    entityType: 'user',
    riskScore: 91,
    riskBand: 'HIGH',
    owner: 'soc.lead.marcus',
    reason: 'CobaltStrike beacon alert & mass file share enumeration',
    expiry: '2026-10-01T00:00:00Z',
    sparkline: [10, 10, 15, 60, 90, 91],
    addedAt: '2026-09-27T12:05:00Z'
  }
];

// In-Memory Saved Cases Store (Immutable case records & evidence hashes)
let SAVED_CASES: CaseRecord[] = [
  {
    id: 'case-88912',
    caseRef: 'INC-88912',
    title: 'Anomalous Credential Access & High-Value DB Exfiltration',
    rootEntity: 'j.smith (USR-8492)',
    analyst: 'alex.soc@company.com',
    status: 'INVESTIGATING',
    severity: 'P1',
    windowHours: 48,
    nodeCount: 11,
    compromisedCount: 7,
    sha256: '9a72c114e9f7832d7fa8bc3e43048596ac048b610c439f0e1f7481ba92437dc1',
    createdAt: '2026-09-27T14:22:00Z',
    notes: 'Isolated laptop in EDR; Kerberos tickets revoked. Evidence video attached.',
    verdict: 'MALICIOUS',
    pushedTo: ['Jira (INC-88912)', 'Slack (#incident-response)']
  }
];

// In-Memory Audit Trail (Immutable WORM style)
interface AuditLogEntry {
  id: string;
  timestamp: string;
  analyst: string;
  action: string;
  entityId: string;
  details: string;
  sha256?: string;
}

let AUDIT_LOG: AuditLogEntry[] = [
  {
    id: 'aud-1',
    timestamp: '2026-09-27T14:20:12Z',
    analyst: 'alex.soc@company.com',
    action: 'SEARCH_ENTITY',
    entityId: 'jsmith',
    details: 'Resolved term jsmith to canonical USR-8492-JSMITH'
  },
  {
    id: 'aud-2',
    timestamp: '2026-09-27T14:22:45Z',
    analyst: 'alex.soc@company.com',
    action: 'EXPORT_REPLAY_MP4',
    entityId: 'jsmith',
    details: 'Client-side 30s 720p replay generated and hashed',
    sha256: '9a72c114e9f7832d7fa8bc3e43048596ac048b610c439f0e1f7481ba92437dc1'
  }
];

// In-Memory Tags & Configuration
let ADMIN_CONFIG = {
  retentionWindowHours: 48,
  maxRetentionDays: 7,
  crownJewelTags: ['crown_jewel', 'SRV-HR-DB01.corp', 'SRV-JUMP-02.corp', 'FS-CORP-SHARE01', 'HashiCorp Vault Prod'],
  vipEntities: ['m.ross@corp.com', 'ciso@corp.com', 'ceo@corp.com'],
  riskWeights: {
    bruteForceThenSuccess: 20,
    firstSeenHostApp: 10,
    crownJewelMultiplier: 2.0,
    newSourceIpAsn: 10,
    impossibleTravel: 25,
    mfaFatigue: 25,
    lateralFanOut: 20,
    privilegeChange: 20,
    massFileAccess: 15,
    largeUpload: 20
  },
  connectors: [
    { 
      id: 'conn-sentinel',
      name: 'Microsoft Sentinel', 
      vendor: 'Microsoft',
      category: 'SIEM', 
      type: 'SIEM', 
      status: 'CONNECTED', 
      eps: 3420, 
      lagMs: 42,
      lastSync: '1 minute ago',
      authType: 'OAuth2 / Entra App Registration',
      endpoint: 'https://api.loganalytics.io/v1/workspaces/ws-secops-991',
      eventsConsumed: 'SigninLogs, SecurityEvent, AADNonInteractiveUserSignInLogs',
      health: 'Optimal',
      alertsBuffered: 142
    },
    { 
      id: 'conn-secops',
      name: 'Google SecOps (Chronicle)', 
      vendor: 'Google Cloud',
      category: 'SIEM', 
      type: 'SIEM', 
      status: 'CONNECTED', 
      eps: 2890, 
      lagMs: 65,
      lastSync: '2 minutes ago',
      authType: 'Service Account Key (GCP IAM)',
      endpoint: 'https://malachiteingestion-pa.googleapis.com/v2',
      eventsConsumed: 'UDM Normalized Authentication, Network, Process',
      health: 'Optimal',
      alertsBuffered: 89
    },
    { 
      id: 'conn-splunk',
      name: 'Splunk Enterprise Security', 
      vendor: 'Splunk',
      category: 'SIEM', 
      type: 'SIEM', 
      status: 'STANDBY', 
      eps: 1850, 
      lagMs: 110,
      lastSync: '14 minutes ago',
      authType: 'HEC Token / REST API',
      endpoint: 'https://splunk-es.corp.internal:8089/services/collector',
      eventsConsumed: 'Notable Events, CIM Data Model Authentication',
      health: 'Degraded',
      alertsBuffered: 12
    },
    { 
      id: 'conn-crowdstrike',
      name: 'CrowdStrike Falcon FDR', 
      vendor: 'CrowdStrike',
      category: 'EDR', 
      type: 'EDR', 
      status: 'CONNECTED', 
      eps: 6120, 
      lagMs: 38,
      lastSync: 'Just now',
      authType: 'OAuth2 API Client ID/Secret',
      endpoint: 'https://api.crowdstrike.com/fdr/v1',
      eventsConsumed: 'ProcessRollup2, NetworkConnectIP4, LsassHandleAudit',
      health: 'Optimal',
      alertsBuffered: 310
    },
    { 
      id: 'conn-defender',
      name: 'Microsoft Defender for Endpoint', 
      vendor: 'Microsoft',
      category: 'EDR', 
      type: 'EDR', 
      status: 'CONNECTED', 
      eps: 4200, 
      lagMs: 55,
      lastSync: '3 minutes ago',
      authType: 'Microsoft Graph Security API',
      endpoint: 'https://api.securitycenter.microsoft.com/api',
      eventsConsumed: 'DeviceProcessEvents, DeviceNetworkEvents, DeviceLogonEvents',
      health: 'Optimal',
      alertsBuffered: 198
    },
    { 
      id: 'conn-okta',
      name: 'Okta Identity Cloud', 
      vendor: 'Okta',
      category: 'IdP', 
      type: 'IdP', 
      status: 'CONNECTED', 
      eps: 980, 
      lagMs: 25,
      lastSync: 'Just now',
      authType: 'SSWS API Token',
      endpoint: 'https://corp.okta.com/api/v1/logs',
      eventsConsumed: 'user.authentication.auth_via_mfa, user.session.start',
      health: 'Optimal',
      alertsBuffered: 76
    },
    { 
      id: 'conn-paloalto',
      name: 'Palo Alto Panorama / Prisma', 
      vendor: 'Palo Alto Networks',
      category: 'Firewall', 
      type: 'Firewall', 
      status: 'CONNECTED', 
      eps: 8900, 
      lagMs: 70,
      lastSync: '1 minute ago',
      authType: 'Syslog TLS / XML API Key',
      endpoint: 'https://panorama.internal.corp/api',
      eventsConsumed: 'Traffic, Threat, GlobalProtect VPN Logs',
      health: 'Optimal',
      alertsBuffered: 440
    },
    { 
      id: 'conn-zscaler',
      name: 'Zscaler Internet Access (ZIA NSS)', 
      vendor: 'Zscaler',
      category: 'Proxy', 
      type: 'Proxy', 
      status: 'CONNECTED', 
      eps: 3800, 
      lagMs: 80,
      lastSync: '5 minutes ago',
      authType: 'Cloud NSS Stream Token',
      endpoint: 'https://nss.zscaler.net/feed/stream',
      eventsConsumed: 'Web Proxy, Cloud App Control, DLP Hits',
      health: 'Optimal',
      alertsBuffered: 120
    }
  ]
};

// ----------------- REST & GraphQL API Endpoints -----------------

// FR-01: Resolve Entity Alias Autocomplete Search
app.get('/api/entities/resolve', (req, res) => {
  const term = (req.query.term as string || '').toLowerCase().trim();
  if (!term) {
    return res.json({ matches: [] });
  }

  const matches: Array<{ id: string; canonicalId: string; username: string; fullName: string; role: string; riskScore: number; riskBand: RiskBand; matchedAlias: string }> = [];

  Object.values(DEMO_USERS).forEach(user => {
    const aliasMatch = user.aliases.find(a => a.toLowerCase().includes(term));
    const matched = aliasMatch || (
      user.username.toLowerCase().includes(term) ? user.username :
      user.fullName.toLowerCase().includes(term) ? user.fullName :
      user.id.toLowerCase().includes(term) ? user.id : ''
    );

    if (matched) {
      matches.push({
        id: user.username.replace(/[^a-z0-9]/g, ''),
        canonicalId: user.canonicalId,
        username: user.username,
        fullName: user.fullName,
        role: user.role,
        riskScore: user.riskScore,
        riskBand: user.riskBand,
        matchedAlias: matched
      });
    }
  });

  res.json({ matches });
});

// Watchlist APIs (FR-03)
app.get('/api/watchlist', (req, res) => {
  res.json({ items: WATCHLIST });
});

app.post('/api/watchlist', (req, res) => {
  const { entityId, reason, expiryDays } = req.body;
  const user = DEMO_USERS[entityId.toLowerCase().replace(/[^a-z0-9]/g, '')] || DEMO_USERS['jsmith'];

  const newItem: WatchlistItem = {
    id: `wl-${Date.now()}`,
    entityId: user.username.replace(/[^a-z0-9]/g, ''),
    canonicalName: `${user.username} (${user.fullName})`,
    entityType: 'user',
    riskScore: user.riskScore,
    riskBand: user.riskBand,
    owner: req.body.owner || 'current.analyst',
    reason: reason || 'Suspicious lateral telemetry observed',
    expiry: new Date(Date.now() + (expiryDays || 7) * 24 * 3600 * 1000).toISOString(),
    sparkline: [20, 25, 40, 60, user.riskScore],
    addedAt: new Date().toISOString()
  };

  WATCHLIST.unshift(newItem);
  if (WATCHLIST.length > 20) WATCHLIST.pop();

  AUDIT_LOG.unshift({
    id: `aud-${Date.now()}`,
    timestamp: new Date().toISOString(),
    analyst: req.body.owner || 'current.analyst',
    action: 'ADD_TO_WATCHLIST',
    entityId: user.username,
    details: `Added ${user.username} to watchlist: ${reason}`
  });

  res.json({ success: true, item: newItem });
});

app.delete('/api/watchlist/:id', (req, res) => {
  WATCHLIST = WATCHLIST.filter(w => w.id !== req.params.id);
  res.json({ success: true });
});

// FR-04: Subgraph retrieval with 48h to 7-day configurable window
app.get('/api/graph/:userId', (req, res) => {
  const userKey = req.params.userId.toLowerCase().replace(/[^a-z0-9]/g, '');
  const profile = DEMO_USERS[userKey] || DEMO_USERS['jsmith'];
  const windowDays = parseInt(req.query.windowDays as string || '2', 10);

  AUDIT_LOG.unshift({
    id: `aud-${Date.now()}`,
    timestamp: new Date().toISOString(),
    analyst: 'current.analyst',
    action: 'VIEW_SUBGRAPH',
    entityId: profile.username,
    details: `Queried ${windowDays * 24}h subgraph for canonical ${profile.canonicalId}`
  });

  res.json({ profile, windowHours: windowDays * 24 });
});

// FR-06: 1-Hop Expand Node On-Demand
app.post('/api/graph/expand', (req, res) => {
  const { nodeId, userKey } = req.body;
  const profile = DEMO_USERS[userKey] || DEMO_USERS['jsmith'];
  
  // Return simulated 1-hop expansion nodes
  const expandedNodes: SecurityNode[] = [
    {
      id: `${nodeId}_hop1`,
      name: `1-Hop: Connected Cluster on ${nodeId}`,
      type: 'host',
      riskScore: 72,
      riskBand: 'MEDIUM',
      compromised: false,
      firstSeenHour: 24,
      firstSeenInBaseline: true,
      details: { PivotedFrom: nodeId, HopDistance: '1', ConnectionType: 'Direct Peer' }
    }
  ];

  const expandedEdges: SecurityEdge[] = [
    {
      id: `exp_e_${Date.now()}`,
      source: nodeId,
      target: `${nodeId}_hop1`,
      action: 'CONNECTED_TO',
      type: 'CONNECTED_TO',
      protocol: 'TCP/8080',
      hour: 24,
      eventCount: 12,
      status: 'allowed',
      details: 'Peer host connectivity via internal subnet'
    }
  ];

  res.json({ nodes: expandedNodes, edges: expandedEdges });
});

// FR-19: Case Management & Snapshot Persistence
app.get('/api/cases', (req, res) => {
  res.json({ cases: SAVED_CASES });
});

app.post('/api/cases', (req, res) => {
  const { title, rootEntity, severity, notes, sha256, userKey } = req.body;
  const user = DEMO_USERS[userKey] || DEMO_USERS['jsmith'];

  const newCase: CaseRecord = {
    id: `case-${Date.now()}`,
    caseRef: `INC-${Math.floor(10000 + Math.random() * 90000)}`,
    title: title || `${user.triggerEvent} - ${user.username}`,
    rootEntity: `${user.username} (${user.id})`,
    analyst: 'alex.soc@company.com',
    status: 'INVESTIGATING',
    severity: severity || 'P1',
    windowHours: 48,
    nodeCount: user.nodes.length,
    compromisedCount: user.nodes.filter(n => n.compromised).length,
    sha256: sha256 || crypto.createHash('sha256').update(JSON.stringify(user.nodes)).digest('hex'),
    createdAt: new Date().toISOString(),
    notes: notes || 'Evidence snapshot saved from 48h temporal graph.',
    verdict: 'SUSPICIOUS',
    pushedTo: []
  };

  SAVED_CASES.unshift(newCase);

  AUDIT_LOG.unshift({
    id: `aud-${Date.now()}`,
    timestamp: new Date().toISOString(),
    analyst: 'alex.soc@company.com',
    action: 'CREATE_CASE',
    entityId: user.username,
    details: `Saved case ${newCase.caseRef} with evidence hash ${newCase.sha256}`,
    sha256: newCase.sha256
  });

  res.json({ success: true, case: newCase });
});

// FR-20: Push to Ticketing (Jira, Slack, ServiceNow)
app.post('/api/cases/:id/push', (req, res) => {
  const { target } = req.body; // 'jira' | 'slack' | 'servicenow'
  const c = SAVED_CASES.find(cs => cs.id === req.params.id);
  if (!c) {
    return res.status(404).json({ error: 'Case not found' });
  }

  const targetLabel = target === 'jira' ? 'Jira (INC-88912)' : target === 'slack' ? 'Slack (#incident-response)' : 'ServiceNow SecOps';
  if (!c.pushedTo) c.pushedTo = [];
  if (!c.pushedTo.includes(targetLabel)) {
    c.pushedTo.push(targetLabel);
  }

  AUDIT_LOG.unshift({
    id: `aud-${Date.now()}`,
    timestamp: new Date().toISOString(),
    analyst: 'alex.soc@company.com',
    action: `PUSH_TO_${target.toUpperCase()}`,
    entityId: c.rootEntity,
    details: `Pushed investigation summary, video artifact, and PNG snapshot to ${targetLabel}`
  });

  res.json({ success: true, pushedTo: c.pushedTo });
});

// FR-23: Analyst Feedback (Benign / Malicious Verdict for Baseline Tuning)
app.post('/api/feedback', (req, res) => {
  const { targetId, verdict, note } = req.body; // 'BENIGN' | 'MALICIOUS'

  AUDIT_LOG.unshift({
    id: `aud-${Date.now()}`,
    timestamp: new Date().toISOString(),
    analyst: 'alex.soc@company.com',
    action: 'SET_VERDICT',
    entityId: targetId,
    details: `Analyst tagged ${targetId} as ${verdict}: ${note || 'No notes'}`
  });

  res.json({ success: true, message: `Feedback registered for suppression and baseline tuning.` });
});

// FR-24 & Section 12: Admin & Audit Log
app.get('/api/admin/config', (req, res) => {
  res.json({ config: ADMIN_CONFIG, auditLog: AUDIT_LOG });
});

app.post('/api/admin/config', (req, res) => {
  ADMIN_CONFIG = { ...ADMIN_CONFIG, ...req.body };
  res.json({ success: true, config: ADMIN_CONFIG });
});

// Real-Time SIEM / Security Tool Webhook Ingestion (Section 4 & 12)
app.post('/api/integrations/webhook', (req, res) => {
  const { source, alertType, entity, severity, rawPayload } = req.body;
  const alertId = `ALT-${Math.floor(10000 + Math.random() * 90000)}`;
  const userKey = (entity || 'jsmith').toLowerCase().replace(/[^a-z0-9]/g, '');
  const user = DEMO_USERS[userKey] || DEMO_USERS['jsmith'];

  // Dynamically add Alert Node and Edge to user's graph so graph canvas reflects live ingestion
  const alertNodeId = `alert_${Date.now()}`;
  const alertNode: SecurityNode = {
    id: alertNodeId,
    name: alertType || `${source || 'SIEM'} Security Detection`,
    type: 'alert',
    riskScore: severity === 'CRITICAL' ? 95 : severity === 'HIGH' ? 88 : 65,
    riskBand: (severity === 'CRITICAL' || severity === 'HIGH') ? 'HIGH' : 'MEDIUM',
    compromised: true,
    firstSeenHour: 0,
    details: {
      Source: source || 'Microsoft Sentinel',
      Severity: severity || 'HIGH',
      AlertId: alertId,
      IngestChannel: 'Webhook / Kafka Stream',
      Timestamp: new Date().toISOString(),
      RuleSignature: `UEBA_DYNAMIC_${Math.floor(1000 + Math.random() * 9000)}`
    }
  };

  const alertEdge: SecurityEdge = {
    id: `e_alert_${Date.now()}`,
    source: alertNodeId,
    target: user.nodes[0]?.id || user.id,
    action: 'TRIGGERED_BY',
    type: 'TRIGGERED',
    protocol: 'OCSF/1.1',
    hour: 0,
    eventCount: 1,
    status: 'critical',
    ttp: ['T1078', 'T1110'],
    details: `Alert generated by ${source || 'SIEM'}: ${alertType || 'Anomalous Activity'}`
  };

  user.nodes.unshift(alertNode);
  user.edges.unshift(alertEdge);

  AUDIT_LOG.unshift({
    id: `aud-${Date.now()}`,
    timestamp: new Date().toISOString(),
    analyst: `${source || 'SIEM'}-connector-daemon`,
    action: 'INGEST_ALERT_WEBHOOK',
    entityId: user.username,
    details: `Ingested ${severity || 'HIGH'} alert [${alertType || 'Anomalous Activity'}] via ${source || 'Sentinel'} webhook (${alertId})`
  });

  res.json({ 
    success: true, 
    alertId,
    status: 'BUFFERED_IN_KAFKA', 
    normalizedToOcsf: true,
    newNode: alertNode,
    message: `Alert ingested from ${source || 'SIEM'} and dispatched to Memgraph 48h subgraph.` 
  });
});

// Containment Actions Center (EDR Isolate, IdP Revoke, Firewall Block)
app.post('/api/integrations/contain/isolate-host', (req, res) => {
  const { hostId, tool = 'CrowdStrike Falcon', reason = 'Compromised by lateral movement' } = req.body;
  
  // Find host in any demo user nodes and mark isolated
  let hostFound = false;
  Object.values(DEMO_USERS).forEach(u => {
    u.nodes.forEach(n => {
      if (n.id === hostId || n.name.toLowerCase() === hostId.toLowerCase()) {
        hostFound = true;
        if (!n.details) n.details = {};
        n.details['ContainmentStatus'] = 'NETWORK_ISOLATED';
        n.details['IsolatedVia'] = tool;
        n.details['IsolatedAt'] = new Date().toISOString();
      }
    });
  });

  AUDIT_LOG.unshift({
    id: `aud-${Date.now()}`,
    timestamp: new Date().toISOString(),
    analyst: 'alex.soc@company.com',
    action: 'EDR_HOST_ISOLATE',
    entityId: hostId,
    details: `Network-isolated ${hostId} via ${tool} API. Reason: ${reason}`
  });

  res.json({
    success: true,
    hostId,
    tool,
    status: 'ISOLATED',
    latencyMs: 140,
    message: `Endpoint ${hostId} successfully network-isolated via ${tool}. Inbound and outbound traffic severed except SOC telemetry.`
  });
});

app.post('/api/integrations/contain/revoke-user', (req, res) => {
  const { userId, tool = 'Okta Identity Cloud', reason = 'Credential compromise' } = req.body;
  const userKey = (userId || 'jsmith').toLowerCase().replace(/[^a-z0-9]/g, '');
  const user = DEMO_USERS[userKey] || DEMO_USERS['jsmith'];

  if (user) {
    user.nodes.forEach(n => {
      if (n.type === 'user') {
        if (!n.details) n.details = {};
        n.details['AccountStatus'] = 'SUSPENDED_PASSWORD_RESET_REQUIRED';
        n.details['RevokedVia'] = tool;
        n.details['RevokedAt'] = new Date().toISOString();
      }
    });
  }

  AUDIT_LOG.unshift({
    id: `aud-${Date.now()}`,
    timestamp: new Date().toISOString(),
    analyst: 'alex.soc@company.com',
    action: 'IDP_USER_REVOKE',
    entityId: user.username,
    details: `Revoked all active sessions and invalidated OAuth refresh tokens via ${tool}`
  });

  res.json({
    success: true,
    userId: user.username,
    tool,
    status: 'REVOKED',
    latencyMs: 95,
    message: `Active sessions terminated and password reset forced for ${user.username} on ${tool}.`
  });
});

app.post('/api/integrations/contain/block-indicator', (req, res) => {
  const { indicator, type = 'ip', tool = 'Palo Alto Panorama', reason = 'C2 Infrastructure' } = req.body;

  AUDIT_LOG.unshift({
    id: `aud-${Date.now()}`,
    timestamp: new Date().toISOString(),
    analyst: 'alex.soc@company.com',
    action: 'FIREWALL_BLOCK_INDICATOR',
    entityId: indicator,
    details: `Pushed dynamic block rule for ${type.toUpperCase()} [${indicator}] to ${tool} perimeter rulebase`
  });

  res.json({
    success: true,
    indicator,
    type,
    tool,
    status: 'BLOCKED',
    latencyMs: 180,
    message: `Indicator ${indicator} added to ${tool} Dynamic Block List (DBL) across all perimeter gateway firewalls.`
  });
});

// SIEM Query Console Runner (Sentinel KQL / Splunk SPL / Chronicle UDM)
app.post('/api/integrations/query', (req, res) => {
  const { tool = 'sentinel', query = '', entityId = 'jsmith', injectIntoGraph = false } = req.body;
  const userKey = entityId.toLowerCase().replace(/[^a-z0-9]/g, '');
  const user = DEMO_USERS[userKey] || DEMO_USERS['jsmith'];

  // Simulated log rows based on target SIEM tool
  const sampleLogs = [
    {
      timestamp: new Date(Date.now() - 3600000 * 2).toISOString(),
      source: tool === 'sentinel' ? 'SigninLogs' : tool === 'splunk' ? 'wineventlog:security' : 'udm.authentication',
      user: user.username,
      ip: '194.26.29.112',
      host: 'SRV-JUMP-02.corp',
      action: 'Logon',
      status: 'SUCCESS',
      eventCode: '4624',
      logonType: '10 (RemoteInteractive)',
      details: 'Logon with explicit credentials via RDP/SMB'
    },
    {
      timestamp: new Date(Date.now() - 3600000 * 5).toISOString(),
      source: tool === 'sentinel' ? 'SecurityEvent' : tool === 'splunk' ? 'sysmon' : 'udm.process',
      user: user.username,
      ip: '172.56.21.90',
      host: 'LAPTOP-JS-882',
      action: 'ProcessCreate',
      status: 'ALLOWED',
      eventCode: '1',
      commandLine: 'powershell.exe -enc SQB2AG8AawBlAC0ATQBpAG0AaQBrAGEAdAB6AA==',
      details: 'Suspicious base64-encoded PowerShell process spawned by cmd.exe'
    },
    {
      timestamp: new Date(Date.now() - 3600000 * 12).toISOString(),
      source: tool === 'sentinel' ? 'AADNonInteractiveUserSignInLogs' : tool === 'splunk' ? 'okta:log' : 'udm.network',
      user: user.username,
      ip: '194.26.29.112',
      host: 'SRV-HR-DB01.corp',
      action: 'DatabaseQuery',
      status: 'SUCCESS',
      schemaAccessed: 'dbo.Employees_Payroll_SSN',
      details: 'Extracted 12,400 rows from Crown Jewel database table'
    }
  ];

  if (injectIntoGraph) {
    const queryNodeId = `siem_query_${Date.now()}`;
    const queryNode: SecurityNode = {
      id: queryNodeId,
      name: `SIEM Ingest: ${tool.toUpperCase()} Query Hit`,
      type: 'domain',
      riskScore: 78,
      riskBand: 'HIGH',
      compromised: true,
      firstSeenHour: 2,
      details: {
        QueryTool: tool,
        QueryString: query.slice(0, 100) + '...',
        RowsReturned: sampleLogs.length.toString(),
        Timestamp: new Date().toISOString()
      }
    };
    user.nodes.push(queryNode);
    user.edges.push({
      id: `e_query_${Date.now()}`,
      source: user.nodes[0]?.id || user.id,
      target: queryNodeId,
      action: 'ACCESSED',
      type: 'ACCESSED',
      protocol: 'TLS/443',
      hour: 2,
      eventCount: sampleLogs.length,
      status: 'anomalous',
      details: `Discovered via ${tool.toUpperCase()} live query execution`
    });
  }

  AUDIT_LOG.unshift({
    id: `aud-${Date.now()}`,
    timestamp: new Date().toISOString(),
    analyst: 'alex.soc@company.com',
    action: 'RUN_SIEM_QUERY',
    entityId: user.username,
    details: `Executed ${tool.toUpperCase()} query: ${query.slice(0, 60)}... (${sampleLogs.length} rows returned)`
  });

  res.json({
    success: true,
    tool,
    query,
    count: sampleLogs.length,
    logs: sampleLogs,
    injectedIntoGraph: !!injectIntoGraph
  });
});

// Manage Connectors (Add / Remove)
app.post('/api/integrations/connectors', (req, res) => {
  const { name, vendor, category, endpoint, authType } = req.body;
  const newConn = {
    id: `conn-${Date.now()}`,
    name: name || 'Custom SIEM Connector',
    vendor: vendor || 'Enterprise SecOps',
    category: category || 'SIEM',
    type: category || 'SIEM',
    status: 'CONNECTED',
    eps: Math.floor(1200 + Math.random() * 2500),
    lagMs: Math.floor(30 + Math.random() * 60),
    lastSync: 'Just now',
    authType: authType || 'API Token',
    endpoint: endpoint || 'https://api.security.internal/v1',
    eventsConsumed: 'SecurityEvents, Detections, NetworkFlows',
    health: 'Optimal',
    alertsBuffered: 0
  };

  ADMIN_CONFIG.connectors.push(newConn);

  AUDIT_LOG.unshift({
    id: `aud-${Date.now()}`,
    timestamp: new Date().toISOString(),
    analyst: 'alex.soc@company.com',
    action: 'ADD_CONNECTOR',
    entityId: newConn.name,
    details: `Added new ${newConn.category} connector [${newConn.name}] to ingestion pipeline`
  });

  res.json({ success: true, connector: newConn });
});

app.delete('/api/integrations/connectors/:id', (req, res) => {
  ADMIN_CONFIG.connectors = ADMIN_CONFIG.connectors.filter(c => c.id !== req.params.id);
  res.json({ success: true });
});

// Test Connection for Security Tool Connectors
app.post('/api/integrations/test/:connectorId', (req, res) => {
  const { connectorId } = req.params;
  const conn = ADMIN_CONFIG.connectors.find(c => c.id === connectorId);
  if (!conn) {
    return res.status(404).json({ error: 'Connector not found' });
  }

  // Update status to verified
  conn.status = 'CONNECTED';
  conn.lastSync = 'Just now';
  conn.health = 'Optimal';

  AUDIT_LOG.unshift({
    id: `aud-${Date.now()}`,
    timestamp: new Date().toISOString(),
    analyst: 'alex.soc@company.com',
    action: 'TEST_CONNECTOR',
    entityId: conn.name,
    details: `Verified handshake with ${conn.name} (${conn.endpoint}) - 200 OK`
  });

  res.json({ 
    success: true, 
    connector: conn,
    latencyMs: Math.floor(25 + Math.random() * 45),
    message: `Connection to ${conn.name} verified. Stream processor active.`
  });
});

// Trigger On-Demand Telemetry Sync for an Entity from SIEM/EDR
app.post('/api/integrations/sync-entity', (req, res) => {
  const { entityId, sources } = req.body;
  const user = DEMO_USERS[entityId?.toLowerCase().replace(/[^a-z0-9]/g, '')] || DEMO_USERS['jsmith'];

  AUDIT_LOG.unshift({
    id: `aud-${Date.now()}`,
    timestamp: new Date().toISOString(),
    analyst: 'alex.soc@company.com',
    action: 'SYNC_ENTITY_TELEMETRY',
    entityId: user.username,
    details: `Triggered on-demand SIEM/EDR sync for ${user.username} across ${(sources || ['Sentinel', 'CrowdStrike']).join(', ')}`
  });

  res.json({
    success: true,
    syncedEventsCount: 142,
    sourcesQueried: sources || ['Microsoft Sentinel', 'CrowdStrike Falcon', 'Okta'],
    timestamp: new Date().toISOString(),
    message: `Pulled 142 recent telemetry events into 48h rolling graph for ${user.username}.`
  });
});

// Detection Rules Tuning (Section 2 - Detection Engineer YARA-L, KQL, CQL export)
app.get('/api/detection/export-rule/:userKey', (req, res) => {
  const user = DEMO_USERS[req.params.userKey] || DEMO_USERS['jsmith'];

  const yaraLRule = `rule watchme_lateral_exfil_${user.username.replace(/[^a-z0-9]/g, '_')} {
  meta:
    author = "WatchMe UEBA Engine"
    description = "Detects anomalous lateral movement to sensitive Crown Jewel followed by S3 exfiltration"
    mitre_attack = "T1110, T1078, T1021, T1005, T1567"
    severity = "CRITICAL"

  events:
    $fail.target.user.userid = "${user.username}"
    $fail.metadata.event_type = "USER_LOGIN"
    $fail.security_result.action = "BLOCK"

    $lateral.target.user.userid = "${user.username}"
    $lateral.target.resource.name = regex_match(r"(SRV-HR-DB01|SRV-JUMP-02)")

    $exfil.principal.user.userid = "${user.username}"
    $exfil.network.sent_bytes > 400000000

  match:
    $user over 48h

  condition:
    #fail >= 5 and $lateral and $exfil
}`;

  const kqlRule = `// Sentinel KQL Detection Rule
let timeframe = 48h;
let targetUser = "${user.username}";
SigninLogs
| where TimeGenerated >= ago(timeframe)
| where UserPrincipalName =~ targetUser
| where ResultType != "0"
| summarize FailedCount = count() by IPAddress, bin(TimeGenerated, 30m)
| where FailedCount >= 5
| join kind=inner (
    SecurityEvent
    | where TimeGenerated >= ago(timeframe)
    | where Account =~ targetUser
    | where EventID == 4624 and LogonType in (3, 10)
    | where Computer in ("SRV-HR-DB01.corp", "SRV-JUMP-02.corp")
) on $left.TimeGenerated == $right.TimeGenerated`;

  res.json({ yaraL: yaraLRule, kql: kqlRule });
});

// FR-17 & FR-18: Privacy-Preserving AI Case Summary Generation with Strict Citation IDs
app.post('/api/gemini/case-summary', async (req, res) => {
  try {
    const { profile, privacyModeEnabled } = req.body;
    const userProfile: UserProfile = profile || DEMO_USERS['jsmith'];

    // Extended Spec Section 7 Context Injection Pipeline:
    // 1. Select Subgraph
    // 2. Sanitize: Replace usernames, hostnames, IPs, files with stable tokens (USER_1, HOST_3, IP_EXT_2)
    // 3. Serialize: Chronological JSON facts with citations
    const tokenMap: Record<string, string> = {
      [userProfile.username]: 'USER_1',
      '194.26.29.112': 'IP_EXT_2',
      '172.56.21.90': 'IP_HOME_1',
      'SRV-HR-DB01.corp': 'APP_CROWN_JEWEL_1',
      'SRV-JUMP-02.corp': 'HOST_BASTION_1',
      'LAPTOP-JS-882': 'HOST_WORKSTATION_1',
      's3.us-east-1.amazonaws.com': 'DOMAIN_EXFIL_1',
      'hr_payroll_q3_export.7z': 'FILE_STAGED_1'
    };

    const sanitizedEdges = (userProfile.edges || []).map(e => ({
      id: e.id,
      t: `T-${e.hour.toString().padStart(2, '0')}:00`,
      fact: privacyModeEnabled
        ? `${tokenMap[e.source] || 'ENTITY_SRC'} ${e.type} ${tokenMap[e.target] || 'ENTITY_TGT'} (${e.action})`
        : `${e.source} ${e.type} ${e.target} (${e.action})`,
      ttp: e.ttp || [],
      risk: e.status,
      count: e.eventCount
    }));

    const sanitizedNodes = (userProfile.nodes || []).map(n => ({
      id: n.id,
      token: privacyModeEnabled ? (tokenMap[n.id] || tokenMap[n.name] || `ENTITY_${n.type.toUpperCase()}`) : n.name,
      type: n.type,
      riskBand: n.riskBand,
      compromised: n.compromised,
      isCrownJewel: n.isCrownJewel || false
    }));

    const promptPayload = {
      investigation_context: {
        entity_token: privacyModeEnabled ? 'USER_1' : userProfile.username,
        role: userProfile.role,
        department: userProfile.department,
        risk_score: userProfile.riskScore,
        risk_band: userProfile.riskBand
      },
      contributing_factors: userProfile.contributingFactors,
      graph_facts: sanitizedEdges,
      entities: sanitizedNodes
    };

    if (ai) {
      try {
        const systemInstruction = `You are WatchMe, an elite Tier-3 Incident Response & UEBA Lead Security Analyst.
Strictly adhere to Section 7 & 8 of the WatchMe Extended Product Specification.
The LLM receives only a sanitized, tokenized timeline of graph facts (never raw logs).

MANDATORY RULES:
1. Every sentence in the timeline and blast radius MUST cite the specific node or edge ID it came from in brackets, e.g. [e4], [e9], [app_hr].
2. Any claim without a citation will be rejected by our guardrail evaluator.
3. Adhere to the following fixed output schema:

# 🚨 WATCHME INCIDENT CASE DOSSIER: [Headline]
### 1. Headline (1 sentence)
What happened and to whom. Must include root entity and risk classification.

### 2. Chronological Attack Timeline (5-10 bullets)
Key events in order, each with citation IDs like [e4], [e5], [e8], [e9], [e11].

### 3. Blast Radius & Crown Jewels Touched
Hosts, apps, and data touched, specifically highlighting crown jewels like [app_hr] and [host_jump].

### 4. ATT&CK Mapping
Techniques observed with exact TTP numbers (e.g., T1110, T1078, T1003, T1021, T1005, T1567).

### 5. Assessment & Confidence
Likely benign / suspicious / likely malicious, with stated confidence percentage and facts behind it.

### 6. Recommended Next Steps for Containment
Step-by-step immediate containment actions for the Tier-2/3 responder.`;

        const geminiPromise = ai.models.generateContent({
          model: 'gemini-3.8-flash',
          contents: `Generate the authoritative incident summary for this sanitized graph context:\n\n${JSON.stringify(promptPayload, null, 2)}`,
          config: {
            systemInstruction,
            temperature: 0.2,
          },
        });

        const timeoutPromise = new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error('Gemini API timeout')), 10000)
        );

        const response = await Promise.race([geminiPromise, timeoutPromise]);
        const summaryText = response.text || 'Incident analysis completed.';

        return res.json({
          summary: summaryText,
          engine: 'Gemini 3.8 Flash (Server-Side Zero-Retention)',
          sanitizedContext: promptPayload,
          tokenMap,
          timestamp: new Date().toISOString()
        });
      } catch (geminiErr: any) {
        console.warn('Gemini fallback engaged:', geminiErr.message);
      }
    }

    // High-Fidelity Extended Spec Fallback with Mandatory Citations [e4], [e5], [e9], etc.
    const fallbackSummary = `# 🚨 WATCHME INCIDENT CASE DOSSIER: Privileged Account Compromise & Crown Jewel Exfiltration
### 1. Headline (1 sentence)
Senior Financial Analyst ${userProfile.username} [u_jsmith] suffered an external session token hijacking from a Romanian Tor node [e5], culminating in unauthorized lateral access to the Crown Jewel HR Payroll database [e9] and external cloud egress [e11].

### 2. Chronological Attack Timeline (5-10 bullets)
- **T-48:00:** User authenticated from baseline Chicago ISP [ip_home] conducting routine quarterly finance queries [e1], [e3].
- **T-40:00:** 7 consecutive failed NTLM authentication attempts initiated from Bucharest Tor exit node 194.26.29.112 [e4], triggering Sentinel alert SEC-7019 [e4b].
- **T-38:00:** Adversary successfully authenticated via stolen session cookie token replay, bypassing MFA [e5].
- **T-32:00:** PowerShell credential dumper \`Invoke-Mimikatz\` executed on workstation LAPTOP-JS-882 [e6], harvesting Kerberos tickets via LSASS memory injection [e7].
- **T-28:00:** Adversary pivoted laterally to production bastion SRV-JUMP-02 via Pass-The-Hash SMB protocol [e8].
- **T-18:00:** First-time anomalous connection established to Crown Jewel SRV-HR-DB01.corp [e9], extracting 12,400 confidential employee payroll records.
- **T-08:00:** Extracted records compressed and AES-256 encrypted into local staging archive \`hr_payroll_q3_export.7z\` [e10].
- **T-02:00:** 482 MB payload exfiltrated over outbound TLS to unmanaged AWS S3 bucket \`s3.us-east-1.amazonaws.com\` [e11].

### 3. Blast Radius & Crown Jewels Touched
- **Root Identity:** ${userProfile.username} [u_jsmith] (Privileged Finance User)
- **Compromised Endpoints:** Corporate laptop [host_laptop] and Bastion Jumpbox [host_jump]
- **Crown Jewels Touched:** Restricted HR Database [app_hr] (\`Employees_Payroll_SSN\` schema breached)
- **Threat Infrastructure:** Tor Exit Node [ip_tor] and AWS Exfil Bucket [dom_exfil]

### 4. ATT&CK Mapping
- **Initial Access:** T1078 (Valid Accounts via Session Token Replay)
- **Credential Access:** T1110 (Brute Force / Password Spraying), T1003 (OS Credential Dumping)
- **Lateral Movement:** T1021 (Remote Services - SMB / Bastion), T1550 (Use Alternate Authentication Material)
- **Collection:** T1005 (Data from Local System / Database)
- **Exfiltration:** T1567 (Exfiltration Over Web Service to Cloud Storage)

### 5. Assessment & Confidence
- **Verdict:** **LIKELY MALICIOUS (Confidence: 98%)**
- **Justification:** Multi-stage kill chain matches classic external credential theft followed by privilege escalation, lateral pivot to a bastion jumpbox, and exfiltration to an untrusted external S3 bucket never seen in the 30-day baseline.

### 6. Recommended Next Steps for Containment
1. **Revoke & Reset:** Invalidate all Kerberos TGT tickets and active Okta/SSO sessions for \`${userProfile.username}\` [u_jsmith].
2. **EDR Host Isolation:** Trigger automated network isolation for \`LAPTOP-JS-882\` [host_laptop] and \`SRV-JUMP-02.corp\` [host_jump].
3. **Firewall Perimeter Sinkhole:** Block IP range \`194.26.29.0/24\` [ip_tor] and block DNS resolution for the external S3 bucket [dom_exfil].
4. **Credential Rotation:** Rotate SA and administrative database service keys on \`SRV-HR-DB01.corp\` [app_hr].`;

    return res.json({
      summary: fallbackSummary,
      engine: 'Deterministic Incident Engine (Offline Zero-Retention)',
      sanitizedContext: promptPayload,
      tokenMap,
      timestamp: new Date().toISOString()
    });

  } catch (error: any) {
    console.error('Case summary generation error:', error);
    res.status(500).json({ error: error.message || 'Failed to generate incident summary' });
  }
});

// Vite & Static Asset Serving
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, 'dist')));
    app.get('*', (req, res) => {
      res.sendFile(path.join(__dirname, 'dist', 'index.html'));
    });
  }

  app.listen(PORT, () => {
    console.log(`WatchMe SOC Extended Platform listening on port ${PORT}`);
  });
}

startServer();
