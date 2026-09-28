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
const MSI_INSTALL = new Set(['11707', '1033']);
const MSI_UNINSTALL = new Set(['11724', '1034']);
const SERVICE_INSTALL = new Set(['7045', '4697']);
const SCHEDULED_TASK = new Set(['4698', '106']);
const DEFENDER = new Set(['1116', '1117', '1006', '1007']);
const CLEARED_LOG = new Set(['1102', '104']);
function msiProduct(doc: EcsDoc): string | undefined {
  const direct = str(doc, 'winlog.event_data.ProductName', 'winlog.event_data.Product', 'package.name');
  if (direct) return direct;
  const p1 = str(doc, 'winlog.event_data.param1', 'message');
  const m = p1?.match(/Product:\s*([^-.\n]+?)(?:\s+--|\.|,|$)/i);
  return m ? m[1].trim() : undefined;
}
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
    else if (code === '10') { ev.category = 'process_access'; ev.process = str(doc, 'winlog.event_data.SourceImage') || ev.process; ev.targetProcess = str(doc, 'winlog.event_data.TargetImage'); ev.message = `Opened ${(ev.targetProcess || '').split(/[\\/]/).pop() || 'process'} (access ${str(doc, 'winlog.event_data.GrantedAccess') || '?'})`; }
    else if (code === '12' || code === '13' || code === '14') { ev.category = 'registry'; ev.registryKey = str(doc, 'winlog.event_data.TargetObject'); ev.registryValue = str(doc, 'winlog.event_data.Details'); }
    else if (code !== '1' && code !== '3' && !['11', '23', '26'].includes(code || '')) { ev.category = 'generic'; ev.provider = 'Sysmon'; ev.logName = 'Sysmon'; ev.message = `Sysmon event ${code}`; }
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
  } else if (code && MSI_INSTALL.has(code)) {
    ev.category = 'install'; ev.outcome = 'success';
    ev.product = msiProduct(doc); ev.publisher = str(doc, 'winlog.event_data.Manufacturer'); ev.version = str(doc, 'winlog.event_data.Version'); ev.message = `Installed ${ev.product || 'software'}`;
  } else if (code && MSI_UNINSTALL.has(code)) {
    ev.category = 'uninstall'; ev.outcome = 'success'; ev.product = msiProduct(doc); ev.message = `Removed ${ev.product || 'software'}`;
  } else if (code && SERVICE_INSTALL.has(code)) {
    ev.category = 'service'; ev.outcome = 'success';
    ev.serviceName = str(doc, 'winlog.event_data.ServiceName', 'service.name'); ev.imagePath = str(doc, 'winlog.event_data.ImagePath', 'winlog.event_data.ServiceFileName');
    ev.user = bareUser(str(doc, 'winlog.event_data.SubjectUserName', 'user.name')); ev.message = `Service installed: ${ev.serviceName || '?'}`;
  } else if (code && SCHEDULED_TASK.has(code)) {
    ev.category = 'scheduled_task'; ev.outcome = 'success';
    ev.taskName = str(doc, 'winlog.event_data.TaskName'); ev.user = bareUser(str(doc, 'winlog.event_data.SubjectUserName', 'user.name')); ev.message = `Scheduled task created: ${ev.taskName || '?'}`;
  } else if (code && DEFENDER.has(code)) {
    ev.category = 'defender'; ev.outcome = 'success';
    ev.threat = str(doc, 'winlog.event_data.Threat Name', 'winlog.event_data.ThreatName', 'threat.technique.name'); ev.signature = ev.threat;
    ev.filePath = str(doc, 'winlog.event_data.Path', 'file.path'); ev.message = `Defender: ${ev.threat || 'detection'}`;
  } else if (code === '4740') {
    ev.category = 'lockout'; ev.outcome = 'failure'; ev.user = bareUser(str(doc, 'winlog.event_data.TargetUserName')); ev.message = 'Account locked out';
  } else if (code === '4672' || code === '4673') {
    ev.category = 'privilege'; ev.outcome = 'success'; ev.user = bareUser(str(doc, 'winlog.event_data.SubjectUserName')); ev.message = 'Special privileges assigned to new logon';
  } else if (code && CLEARED_LOG.has(code)) {
    ev.category = 'generic'; ev.outcome = 'success'; ev.provider = 'Windows'; ev.logName = channel; ev.signature = 'Audit log cleared'; ev.message = 'Audit log was cleared';
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
    const module = (str(doc, 'event.module', 'event.dataset') || '').toLowerCase();
    if (cats.includes('authentication') && outcome) {
      ev.category = 'auth';
      ev.outcome = outcome === 'failure' ? 'failure' : 'success';
    } else if (/o365|office365|azure|entra|aws|cloudtrail|okta|gsuite|gcp/.test(module)) {
      ev.category = 'cloud_auth';
      ev.message = str(doc, 'event.action') || `Cloud event (${module})`;
      ev.outcome = outcome === 'failure' ? 'failure' : 'success';
    }
    // Nothing is dropped: keep any remaining event as generic, with enough to show and search.
    if (ev.category === 'other') {
      ev.category = 'generic';
      ev.provider = str(doc, 'event.provider', 'winlog.provider_name') || dataset;
      ev.logName = channel || module || 'ecs';
      ev.message = str(doc, 'message', 'event.action') || (code ? `Event ${code} (${channel || module})` : dataset);
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
