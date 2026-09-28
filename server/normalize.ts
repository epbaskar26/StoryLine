// Maps Splunk rows (Windows Security, Sysmon, and CIM-style fields) to one normalized event shape.
import type { SplunkRow } from './splunk';

export type EventCategory =
  | 'auth' | 'process' | 'network' | 'file' | 'account_change' | 'web' | 'dns' | 'alert'
  | 'install' | 'uninstall' | 'service' | 'scheduled_task' | 'registry' | 'defender'
  | 'process_access' | 'lockout' | 'privilege' | 'usb' | 'cloud_auth' | 'generic' | 'other';

export interface NormalizedEvent {
  id: string;
  ts: string; // ISO
  tsMs: number;
  sourcetype: string;
  category: EventCategory;
  outcome: 'success' | 'failure' | 'unknown';
  user?: string;
  srcIp?: string;
  srcHost?: string;
  host?: string; // host where the event was recorded
  destHost?: string;
  destIp?: string;
  destPort?: string;
  process?: string;
  parentProcess?: string;
  commandLine?: string;
  filePath?: string;
  domain?: string;
  url?: string;
  bytesOut?: number;
  eventCode?: string;
  logonType?: string;
  group?: string;
  signature?: string;
  action?: string;
  scriptBlock?: boolean; // PowerShell 4104: commandLine holds script block text
  source?: string; // short provenance label, e.g. "Sysmon 1"
  // Software install / uninstall
  product?: string;
  version?: string;
  publisher?: string;
  // Service / scheduled task / registry persistence
  serviceName?: string;
  imagePath?: string; // service binary or task action
  taskName?: string;
  registryKey?: string;
  registryValue?: string;
  // Process access (e.g. LSASS read), security product detections, devices
  targetProcess?: string;
  threat?: string; // Defender / EDR threat name
  deviceName?: string;
  // Generic / unmapped events keep enough to show and to search
  provider?: string; // event provider / channel
  logName?: string; // Security | System | Application | ...
  message?: string; // short human-readable description
}

const EMPTY = new Set(['', '-', 'n/a', 'null', 'unknown', '::1', '127.0.0.1', '0.0.0.0', '::']);

function vals(row: SplunkRow, key: string): string[] {
  const v = row[key];
  if (v === undefined || v === null) return [];
  return (Array.isArray(v) ? v : [v]).map(String).map(s => s.trim()).filter(s => !EMPTY.has(s.toLowerCase()));
}

// Returns the last meaningful value across candidate fields. Windows 4624/4625 carry two Account_Name
// values (subject, then target); the target is the last one, which is the account that logged on.
function pick(row: SplunkRow, ...keys: string[]): string | undefined {
  for (const k of keys) {
    const list = vals(row, k);
    if (list.length) return list[list.length - 1];
  }
  return undefined;
}

export function bareUser(u?: string): string | undefined {
  if (!u) return undefined;
  let s = u.trim();
  if (s.includes('\\')) s = s.split('\\').pop() || s;
  return s.toLowerCase() || undefined;
}

function basename(p?: string): string | undefined {
  if (!p) return undefined;
  const parts = p.split(/[\\/]/);
  return parts[parts.length - 1] || p;
}

function isIp(s?: string): boolean {
  return !!s && (/^\d{1,3}(\.\d{1,3}){3}$/.test(s) || /^[0-9a-f:]+$/i.test(s) && s.includes(':'));
}

function domainFrom(url?: string, site?: string): string | undefined {
  const raw = site || url;
  if (!raw) return undefined;
  try {
    const u = raw.includes('://') ? new URL(raw) : new URL('http://' + raw);
    return u.hostname.toLowerCase();
  } catch {
    return raw.split('/')[0].toLowerCase();
  }
}

const AUTH_SUCCESS_CODES = new Set(['4624', '4648', '4768', '4769', '4776']);
const AUTH_FAIL_CODES = new Set(['4625', '4771']);
const GROUP_ADD_CODES = new Set(['4728', '4732', '4756', '4720', '4738']);
const MSI_INSTALL_CODES = new Set(['11707', '1033']);        // Application log, MsiInstaller: install completed
const MSI_UNINSTALL_CODES = new Set(['11724', '1034']);      // uninstall completed
const SERVICE_INSTALL_CODES = new Set(['7045', '4697']);     // new service installed (System / Security)
const SCHEDULED_TASK_CODES = new Set(['4698', '106']);       // scheduled task created
const DEFENDER_CODES = new Set(['1116', '1117', '1006', '1007']); // Defender malware detected / action taken
const LOCKOUT_CODES = new Set(['4740']);
const PRIVILEGE_CODES = new Set(['4672', '4673', '4674']);
const CLEARED_LOG_CODES = new Set(['1102', '104']);          // audit log cleared (defense evasion)

// Product name from MsiInstaller: the message or Param fields carry "Product: X -- ..."
function productName(row: SplunkRow): string | undefined {
  const direct = pick(row, 'Product_Name', 'Product', 'Name');
  if (direct) return direct;
  const msg = pick(row, 'Message', 'Param1', 'param1');
  if (!msg) return undefined;
  const m = msg.match(/Product:\s*([^-.\n]+?)(?:\s+--|\.|,|$)/i);
  return m ? m[1].trim() : undefined;
}

export function normalizeRow(row: SplunkRow, index: number): NormalizedEvent | null {
  const timeStr = pick(row, '_time');
  if (!timeStr) return null;
  const tsMs = Date.parse(timeStr) || Number(timeStr) * 1000;
  if (!Number.isFinite(tsMs)) return null;

  const sourcetype = (pick(row, 'sourcetype') || 'unknown').toLowerCase();
  const code = pick(row, 'EventCode');
  const isSysmon = sourcetype.includes('sysmon');
  const recordedOn = pick(row, 'ComputerName', 'Computer', 'host');

  const ev: NormalizedEvent = {
    id: `evt-${(pick(row, '_cd') || String(index)).replace(/[^A-Za-z0-9:-]/g, '')}`,
    ts: new Date(tsMs).toISOString(),
    tsMs,
    sourcetype,
    category: 'other',
    outcome: 'unknown',
    user: bareUser(pick(row, 'TargetUserName', 'Account_Name', 'user', 'User', 'src_user', 'SubjectUserName')),
    host: recordedOn?.toLowerCase(),
    srcIp: pick(row, 'src_ip', 'Source_Network_Address', 'IpAddress', 'src'),
    srcHost: pick(row, 'Workstation_Name', 'src_host')?.toLowerCase(),
    destHost: pick(row, 'DestinationHostname', 'dest_host')?.toLowerCase(),
    destIp: pick(row, 'DestinationIp', 'dest_ip'),
    destPort: pick(row, 'DestinationPort', 'dest_port'),
    eventCode: code,
    logonType: pick(row, 'Logon_Type', 'LogonType'),
    action: pick(row, 'action'),
    signature: pick(row, 'signature'),
  };
  if (ev.srcIp?.toLowerCase().startsWith('::ffff:')) ev.srcIp = ev.srcIp.slice(7);
  if (ev.srcIp && !isIp(ev.srcIp)) { ev.srcHost = ev.srcHost || ev.srcIp.toLowerCase(); ev.srcIp = undefined; }
  const dest = pick(row, 'dest');
  if (dest) {
    if (isIp(dest)) ev.destIp = ev.destIp || dest;
    else ev.destHost = ev.destHost || dest.toLowerCase();
  }

  if (isSysmon) {
    ev.process = pick(row, 'Image', 'process', 'process_name');
    ev.parentProcess = pick(row, 'ParentImage', 'parent_process');
    ev.commandLine = pick(row, 'CommandLine', 'process_command_line');
    if (code === '1') ev.category = 'process';
    else if (code === '3') ev.category = 'network';
    else if (code === '11' || code === '23' || code === '26') { ev.category = 'file'; ev.filePath = pick(row, 'TargetFilename', 'file_path'); }
    else if (code === '22') { ev.category = 'dns'; ev.domain = pick(row, 'QueryName', 'query')?.toLowerCase(); }
    else if (code === '10') { ev.category = 'process_access'; ev.targetProcess = pick(row, 'TargetImage'); ev.process = pick(row, 'SourceImage', 'Image'); ev.message = `Opened ${basename(ev.targetProcess) || 'process'} (access ${pick(row, 'GrantedAccess') || '?'})`; }
    else if (code === '12' || code === '13' || code === '14') { ev.category = 'registry'; ev.registryKey = pick(row, 'TargetObject', 'Target_Object'); ev.registryValue = pick(row, 'Details'); }
    else { ev.category = 'generic'; ev.provider = 'Sysmon'; ev.logName = 'Sysmon'; ev.message = `Sysmon event ${code}`; }
    ev.outcome = 'success';
    return ev;
  }

  if (code && AUTH_SUCCESS_CODES.has(code)) { ev.category = 'auth'; ev.outcome = 'success'; }
  else if (code && AUTH_FAIL_CODES.has(code)) { ev.category = 'auth'; ev.outcome = 'failure'; }
  else if (code === '4688') {
    ev.category = 'process';
    ev.outcome = 'success';
    ev.process = pick(row, 'New_Process_Name', 'process', 'process_name');
    ev.parentProcess = pick(row, 'Creator_Process_Name', 'parent_process');
    ev.commandLine = pick(row, 'Process_Command_Line', 'CommandLine', 'process_command_line');
  } else if (code && GROUP_ADD_CODES.has(code)) {
    ev.category = 'account_change';
    ev.outcome = 'success';
    ev.group = pick(row, 'Group_Name');
    // For group changes, the subject (first Account_Name) made the change; the target is the member.
    const names = vals(row, 'Account_Name');
    if (names.length >= 1) ev.user = bareUser(names[0]);
  } else if (code && MSI_INSTALL_CODES.has(code)) {
    ev.category = 'install'; ev.outcome = 'success';
    ev.product = productName(row); ev.publisher = pick(row, 'Vendor', 'Publisher'); ev.version = pick(row, 'Version');
    ev.message = `Installed ${ev.product || 'software'}`;
  } else if (code && MSI_UNINSTALL_CODES.has(code)) {
    ev.category = 'uninstall'; ev.outcome = 'success';
    ev.product = productName(row); ev.message = `Removed ${ev.product || 'software'}`;
  } else if (code && SERVICE_INSTALL_CODES.has(code)) {
    ev.category = 'service'; ev.outcome = 'success';
    ev.serviceName = pick(row, 'Service_Name', 'ServiceName'); ev.imagePath = pick(row, 'Service_File_Name', 'ImagePath', 'Image_Path');
    ev.message = `Service installed: ${ev.serviceName || '?'}`;
    if (code === '4697') { const names = vals(row, 'Account_Name'); if (names.length) ev.user = bareUser(names[0]); }
  } else if (code && SCHEDULED_TASK_CODES.has(code)) {
    ev.category = 'scheduled_task'; ev.outcome = 'success';
    ev.taskName = pick(row, 'Task_Name', 'TaskName'); ev.imagePath = pick(row, 'ImagePath', 'Image_Path');
    ev.message = `Scheduled task created: ${ev.taskName || '?'}`;
  } else if (code && DEFENDER_CODES.has(code)) {
    ev.category = 'defender'; ev.outcome = 'success';
    ev.threat = pick(row, 'Threat_Name', 'ThreatName', 'signature'); ev.filePath = pick(row, 'file_path', 'Object_Name');
    ev.signature = ev.threat; ev.message = `Defender: ${ev.threat || 'detection'}`;
  } else if (code && LOCKOUT_CODES.has(code)) {
    ev.category = 'lockout'; ev.outcome = 'failure';
    ev.user = bareUser(pick(row, 'TargetUserName', 'Account_Name')); ev.message = 'Account locked out';
  } else if (code && PRIVILEGE_CODES.has(code)) {
    ev.category = 'privilege'; ev.outcome = 'success'; ev.message = 'Special privileges assigned to new logon';
  } else if (code && CLEARED_LOG_CODES.has(code)) {
    ev.category = 'generic'; ev.outcome = 'success'; ev.provider = 'Windows'; ev.logName = pick(row, 'sourcetype'); ev.message = 'Audit log was cleared';
    ev.signature = 'Audit log cleared';
  } else if (code === '4663' || code === '5145') {
    ev.category = 'file';
    ev.outcome = 'success';
    ev.filePath = pick(row, 'Object_Name', 'file_path', 'file_name');
  } else if (pick(row, 'url', 'site', 'uri')) {
    ev.category = 'web';
    ev.url = pick(row, 'url', 'uri');
    ev.domain = domainFrom(pick(row, 'url'), pick(row, 'site'));
    const bytes = Number(pick(row, 'bytes_out'));
    if (Number.isFinite(bytes)) ev.bytesOut = bytes;
    ev.outcome = /block|deny|drop/i.test(ev.action || '') ? 'failure' : 'success';
  } else if (pick(row, 'signature') && /alert|ids|suricata|snort|detection|notable/i.test(sourcetype)) {
    ev.category = 'alert';
    ev.outcome = 'success';
  } else if (ev.destIp || ev.destHost) {
    ev.category = 'network';
    const bytes = Number(pick(row, 'bytes_out', 'bytes'));
    if (Number.isFinite(bytes)) ev.bytesOut = bytes;
    ev.outcome = /block|deny|drop|fail/i.test(ev.action || '') ? 'failure' : 'success';
  } else {
    ev.category = 'other';
    const act = (ev.action || pick(row, 'status', 'Status') || '').toLowerCase();
    if (/fail|denied|invalid/.test(act)) ev.outcome = 'failure';
    else if (/success|allowed|succeeded/.test(act)) ev.outcome = 'success';
  }

  // Generic CIM authentication data (e.g. Okta, VPN, Linux secure) without Windows event codes.
  if (ev.category === 'other' && /auth|login|logon|secure|okta|signin|vpn/.test(sourcetype) && ev.outcome !== 'unknown') {
    ev.category = 'auth';
  }
  // Cloud sign-ins (M365 / Entra ID / AWS) surfaced through CIM or add-on sourcetypes
  if (ev.category === 'other' && /azure|entra|office365|o365|aws|cloudtrail|gsuite|gws|okta/.test(sourcetype)) {
    if (pick(row, 'signature') && /assumerole|consolelogin|createuser|attach/i.test(pick(row, 'signature') || '')) { ev.category = 'cloud_auth'; ev.message = pick(row, 'signature'); }
    else if (ev.outcome !== 'unknown') { ev.category = 'cloud_auth'; ev.message = `Cloud sign-in (${sourcetype})`; }
  }
  // Nothing is dropped: anything still unmodelled becomes a generic event, kept for the graph and search.
  if (ev.category === 'other') {
    ev.category = 'generic';
    ev.provider = pick(row, 'SourceName', 'sourcetype') || sourcetype;
    ev.logName = sourcetype;
    ev.message = ev.message || pick(row, 'signature', 'Message', 'action') || (code ? `Event ${code} (${sourcetype})` : sourcetype);
  }
  return ev;
}

export function normalizeRows(rows: SplunkRow[]): NormalizedEvent[] {
  const out: NormalizedEvent[] = [];
  rows.forEach((r, i) => {
    const ev = normalizeRow(r, i);
    if (ev) out.push(ev);
  });
  // Stable, de-duplicated ids
  const seen = new Map<string, number>();
  for (const ev of out) {
    const n = seen.get(ev.id) || 0;
    if (n > 0) ev.id = `${ev.id}-${n}`;
    seen.set(ev.id, n + 1);
  }
  return out.sort((a, b) => a.tsMs - b.tsMs);
}

export { basename, isIp };
