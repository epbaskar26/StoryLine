// Maps Splunk rows (Windows Security, Sysmon, and CIM-style fields) to one normalized event shape.
import type { SplunkRow } from './splunk';

export type EventCategory = 'auth' | 'process' | 'network' | 'file' | 'account_change' | 'web' | 'dns' | 'alert' | 'other';

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
    else ev.category = 'other';
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
