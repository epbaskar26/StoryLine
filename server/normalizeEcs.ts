// Maps Elastic Common Schema documents (Winlogbeat: Windows Security + Sysmon; also generic ECS) to NormalizedEvent.
import type { NormalizedEvent } from './normalize';
import { bareUser } from './normalize';

export type EcsDoc = Record<string, any>;

const EMPTY = new Set(['', '-', 'n/a', 'null', 'unknown', '::1', '127.0.0.1', '0.0.0.0', '::']);

// Read a dotted path from an ECS document. Handles both nested objects and flattened "a.b.c" keys.
export function get(doc: EcsDoc, path: string): any {
  if (doc == null) return undefined;
  if (path in doc) return doc[path];
  const parts = path.split('.');
  let cur: any = doc;
  for (let i = 0; i < parts.length; i++) {
    if (cur == null) return undefined;
    const rest = parts.slice(i).join('.');
    if (typeof cur === 'object' && rest in cur) return cur[rest];
    cur = cur[parts[i]];
  }
  return cur;
}

function str(doc: EcsDoc, ...paths: string[]): string | undefined {
  for (const p of paths) {
    let v = get(doc, p);
    if (Array.isArray(v)) v = v[v.length - 1];
    if (v === undefined || v === null) continue;
    const s = String(v).trim();
    if (!EMPTY.has(s.toLowerCase())) return s;
  }
  return undefined;
}

function isIp(s?: string): boolean {
  return !!s && (/^\d{1,3}(\.\d{1,3}){3}$/.test(s) || (/^[0-9a-f:]+$/i.test(s) && s.includes(':')));
}

const AUTH_SUCCESS = new Set(['4624', '4648', '4768', '4769', '4776', '4778']);
const AUTH_FAIL = new Set(['4625', '4771']);
const GROUP_CHANGE = new Set(['4728', '4732', '4756', '4720', '4738']);
// Windows logon type names as ECS/Winlogbeat reports them in winlog.logon.type
const LOGON_TYPE_NUM: Record<string, string> = {
  interactive: '2', network: '3', batch: '4', service: '5', unlock: '7', networkcleartext: '8',
  newcredentials: '9', remoteinteractive: '10', cachedinteractive: '11',
};

export function normalizeEcsDoc(doc: EcsDoc, id: string): NormalizedEvent | null {
  const tsRaw = str(doc, '@timestamp');
  const tsMs = tsRaw ? Date.parse(tsRaw) : NaN;
  if (!Number.isFinite(tsMs)) return null;

  const code = str(doc, 'event.code', 'winlog.event_id');
  const channel = (str(doc, 'winlog.channel') || '').toLowerCase();
  const provider = (str(doc, 'event.provider', 'winlog.provider_name') || '').toLowerCase();
  const isSysmon = channel.includes('sysmon') || provider.includes('sysmon');
  const isPowerShell = channel.includes('powershell') || provider.includes('powershell');
  const dataset = str(doc, 'event.dataset', 'event.module') || (channel ? `winlog:${channel}` : 'ecs');

  let logonType = str(doc, 'winlog.event_data.LogonType');
  if (!logonType) {
    const t = str(doc, 'winlog.logon.type');
    if (t) logonType = LOGON_TYPE_NUM[t.toLowerCase().replace(/\s+/g, '')] || t;
  }

  const ev: NormalizedEvent = {
    id: `evt-${id}`,
    ts: new Date(tsMs).toISOString(),
    tsMs,
    sourcetype: isSysmon ? 'sysmon' : dataset,
    category: 'other',
    outcome: 'unknown',
    host: str(doc, 'host.name', 'winlog.computer_name', 'host.hostname')?.toLowerCase(),
    srcIp: str(doc, 'source.ip', 'winlog.event_data.IpAddress', 'client.ip'),
    srcHost: str(doc, 'winlog.event_data.WorkstationName', 'source.domain')?.toLowerCase(),
    destIp: str(doc, 'destination.ip', 'server.ip', 'winlog.event_data.DestinationIp'),
    destHost: str(doc, 'destination.domain', 'server.domain', 'winlog.event_data.DestinationHostname')?.toLowerCase(),
    destPort: str(doc, 'destination.port', 'winlog.event_data.DestinationPort'),
    eventCode: code,
    logonType,
    action: str(doc, 'event.action'),
    signature: str(doc, 'rule.name', 'signal.rule.name', 'kibana.alert.rule.name'),
  };
  if (ev.srcIp?.toLowerCase().startsWith('::ffff:')) ev.srcIp = ev.srcIp.slice(7);
  if (ev.srcIp && !isIp(ev.srcIp)) ev.srcIp = undefined;

  const outcome = (str(doc, 'event.outcome') || '').toLowerCase();

  if (isPowerShell) {
    // 4104 script block logging: the script text is the evidence. Other PowerShell events are ignored.
    const text = str(doc, 'powershell.file.script_block_text', 'winlog.event_data.ScriptBlockText');
    if (code !== '4104' || !text) return null;
    ev.category = 'process';
    ev.outcome = 'success';
    ev.scriptBlock = true;
    ev.source = 'PowerShell 4104 (script block)';
    ev.user = bareUser(str(doc, 'user.name', 'winlog.user.name'));
    ev.process = str(doc, 'process.executable') || 'powershell.exe';
    ev.commandLine = text.slice(0, 32768);
    return ev;
  }

  if (isSysmon) {
    ev.source = `Sysmon ${code}`;
    ev.user = bareUser(str(doc, 'user.name', 'winlog.event_data.User'));
    ev.process = str(doc, 'process.executable', 'winlog.event_data.Image');
    ev.parentProcess = str(doc, 'process.parent.executable', 'winlog.event_data.ParentImage');
    ev.commandLine = str(doc, 'process.command_line', 'winlog.event_data.CommandLine');
    ev.outcome = 'success';
    if (code === '1') ev.category = 'process';
    else if (code === '3') ev.category = 'network';
    else if (code === '11' || code === '23' || code === '26') { ev.category = 'file'; ev.filePath = str(doc, 'file.path', 'winlog.event_data.TargetFilename'); }
    else if (code === '22') { ev.category = 'dns'; ev.domain = str(doc, 'dns.question.name', 'winlog.event_data.QueryName')?.toLowerCase(); }
    return ev;
  }

  if (code && AUTH_SUCCESS.has(code)) {
    ev.category = 'auth';
    ev.outcome = 'success';
    ev.user = bareUser(str(doc, 'winlog.event_data.TargetUserName', 'user.name'));
  } else if (code && AUTH_FAIL.has(code)) {
    ev.category = 'auth';
    ev.outcome = 'failure';
    ev.user = bareUser(str(doc, 'winlog.event_data.TargetUserName', 'user.name'));
  } else if (code === '4688') {
    ev.source = 'Security 4688';
    ev.category = 'process';
    ev.outcome = 'success';
    ev.user = bareUser(str(doc, 'winlog.event_data.SubjectUserName', 'user.name', 'winlog.user.name'));
    ev.process = str(doc, 'process.executable', 'winlog.event_data.NewProcessName');
    ev.parentProcess = str(doc, 'process.parent.executable', 'winlog.event_data.ParentProcessName');
    ev.commandLine = str(doc, 'process.command_line', 'winlog.event_data.CommandLine');
  } else if (code && GROUP_CHANGE.has(code)) {
    // For group changes the subject made the change; TargetUserName is the group
    ev.category = 'account_change';
    ev.outcome = 'success';
    ev.user = bareUser(str(doc, 'winlog.event_data.SubjectUserName', 'user.name'));
    ev.group = str(doc, 'group.name', 'winlog.event_data.TargetUserName');
  } else if (code === '4663' || code === '5145') {
    ev.category = 'file';
    ev.outcome = 'success';
    ev.user = bareUser(str(doc, 'winlog.event_data.SubjectUserName', 'user.name'));
    ev.filePath = str(doc, 'file.path', 'winlog.event_data.ObjectName', 'winlog.event_data.RelativeTargetName');
  } else if (str(doc, 'url.full', 'url.domain')) {
    ev.category = 'web';
    ev.user = bareUser(str(doc, 'user.name'));
    ev.url = str(doc, 'url.full', 'url.original');
    ev.domain = str(doc, 'url.domain', 'destination.domain')?.toLowerCase();
    const bytes = Number(str(doc, 'http.request.bytes', 'source.bytes'));
    if (Number.isFinite(bytes)) ev.bytesOut = bytes;
    ev.outcome = outcome === 'failure' ? 'failure' : 'success';
  } else if (str(doc, 'event.kind') === 'alert' || ev.signature) {
    ev.category = 'alert';
    ev.user = bareUser(str(doc, 'user.name'));
    ev.outcome = 'success';
  } else if (ev.destIp || ev.destHost) {
    ev.category = 'network';
    ev.user = bareUser(str(doc, 'user.name'));
    const bytes = Number(str(doc, 'source.bytes', 'network.bytes'));
    if (Number.isFinite(bytes)) ev.bytesOut = bytes;
    ev.outcome = outcome === 'failure' ? 'failure' : 'success';
  } else {
    ev.user = bareUser(str(doc, 'user.name', 'winlog.event_data.TargetUserName'));
    const cats = ([] as string[]).concat(get(doc, 'event.category') || []);
    if (cats.includes('authentication') && outcome) {
      ev.category = 'auth';
      ev.outcome = outcome === 'failure' ? 'failure' : 'success';
    }
  }
  return ev;
}

export function normalizeEcsHits(hits: { _id: string; _source: EcsDoc }[]): NormalizedEvent[] {
  const out: NormalizedEvent[] = [];
  for (const h of hits) {
    const ev = normalizeEcsDoc(h._source, h._id.replace(/[^A-Za-z0-9_-]/g, ''));
    if (ev) out.push(ev);
  }
  return out.sort((a, b) => a.tsMs - b.tsMs);
}
