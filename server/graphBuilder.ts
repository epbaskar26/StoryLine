// Turns normalized events into the UserProfile shape the frontend renders (nodes, edges, milestones, factors).
import crypto from 'node:crypto';
import type { NormalizedEvent } from './normalize';
import { basename } from './normalize';
import type { NodeType, EdgeType, SecurityNode, SecurityEdge, SecurityMilestone, UserProfile, ContributingFactor, ProcessExecution } from '../src/types';
import { analyzeCommand } from '../src/commandInsight';
import { evaluateIndicators, scoreEntity, bandFor, DEFAULT_THRESHOLDS, NOT_IMPLEMENTED_INDICATORS, type EdgeDraft, type RiskThresholds } from './risk';

export interface AlertRecord {
  id: string;
  ts: string;
  entityKey: string;
  source: string;
  alertType: string;
  severity: string;
  ttp?: string[];
}

export interface BuildInput {
  username: string;
  events: NormalizedEvent[];
  alerts: AlertRecord[];
  t0Ms: number;
  windowHours: number;
  baseline: Set<string> | null;
  crownJewelTags: string[];
  vipEntities: string[];
  riskWeights: Record<string, number>;
  thresholds?: RiskThresholds;
  maxNodes?: number;
  maxEdges?: number;
  dataSource?: 'splunk' | 'elastic';
  sourceLabel?: string;
  searchMode?: boolean; // graph of an analyst's log search: one node per matched identity instead of one root user
  query?: string;
}

interface NodeDraft {
  key: string;
  id: string;
  name: string;
  type: NodeType;
  firstMs: number;
  lastMs: number;
  details: Record<string, string>;
  classification?: string;
  isCrownJewel: boolean;
}

const PREFIX: Record<NodeType, string> = {
  user: 'u', host: 'host', ip: 'ip', application: 'app', file: 'file', process: 'proc', domain: 'dom', alert: 'alert', query: 'q',
};

const MAX_EXECUTIONS_PER_PROCESS = 50;
const MAX_COMMAND_CHARS = 32768;

const LOGON_TYPES: Record<string, string> = {
  '2': 'Interactive', '3': 'Network', '4': 'Batch', '5': 'Service', '7': 'Unlock', '8': 'NetworkCleartext',
  '9': 'NewCredentials', '10': 'RDP', '11': 'CachedInteractive',
};

const HOUR_MS = 3_600_000;
const VISIT_GAP_MS = 30 * 60_000; // a new visit starts after 30 minutes without activity on the same edge

type VisitOut = { start: string; end: string; count: number; status?: 'critical' | 'anomalous'; ttp?: string[] };

// Group an edge's events into separate visits (used by the Attack Path view to show revisits).
// Each visit gets the severity and techniques of the indicators whose events fall inside it, so a normal
// login and a later malicious login on the same edge are coloured differently.
function splitVisits(edgeKey: string, samples: [number, string][], eventRisk: Map<string, { severity: 'critical' | 'anomalous'; ttp: string }>): VisitOut[] {
  const sorted = [...samples].sort((a, b) => a[0] - b[0]);
  const visits: { start: number; end: number; count: number; ids: string[] }[] = [];
  for (const [t, id] of sorted) {
    const last = visits[visits.length - 1];
    if (last && t - last.end <= VISIT_GAP_MS) { last.end = t; last.count++; last.ids.push(id); }
    else visits.push({ start: t, end: t, count: 1, ids: [id] });
  }
  return visits.slice(0, 20).map(v => {
    const risks = v.ids.map(id => eventRisk.get(`${edgeKey}|${id}`)).filter((r): r is { severity: 'critical' | 'anomalous'; ttp: string } => !!r);
    const status = risks.some(r => r.severity === 'critical') ? 'critical' : risks.length ? 'anomalous' : undefined;
    const ttp = Array.from(new Set(risks.map(r => r.ttp).filter(t => /^T\d/.test(t))));
    return { start: new Date(v.start).toISOString(), end: new Date(v.end).toISOString(), count: v.count, status, ttp: ttp.length ? ttp : undefined };
  });
}

// Opaque ids: a hash, not the entity name, so ids can be shown to the LLM as citations without leaking names.
export function opaqueId(type: NodeType, key: string): string {
  return `${PREFIX[type]}_${crypto.createHash('sha1').update(key).digest('hex').slice(0, 8)}`;
}

function isPrivateIp(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|fe80:|fc|fd)/i.test(ip);
}

export function buildProfile(input: BuildInput): UserProfile {
  const { username, events, alerts, t0Ms, windowHours, baseline } = input;
  const maxNodes = input.maxNodes ?? 400;
  const maxEdges = input.maxEdges ?? 1500;
  const crownTags = input.crownJewelTags.map(t => t.toLowerCase());
  const isCrown = (name: string) => crownTags.some(t => t && name.toLowerCase().includes(t));

  const nodes = new Map<string, NodeDraft>();
  const edges = new Map<string, EdgeDraft>();
  const edgeKeysByEvent = new Map<string, string[]>();
  const edgeSamples = new Map<string, string>();

  const node = (type: NodeType, name: string, ts: number, details: Record<string, string> = {}, classification?: string): NodeDraft => {
    const key = `${type}:${name.toLowerCase()}`;
    let n = nodes.get(key);
    if (!n) {
      n = { key, id: opaqueId(type, key), name, type, firstMs: ts, lastMs: ts, details: {}, classification, isCrownJewel: isCrown(name) };
      nodes.set(key, n);
    }
    n.firstMs = Math.min(n.firstMs, ts);
    n.lastMs = Math.max(n.lastMs, ts);
    for (const [k, v] of Object.entries(details)) if (v && !n.details[k]) n.details[k] = v.slice(0, 4000);
    return n;
  };

  const edge = (type: EdgeType, src: NodeDraft, tgt: NodeDraft, ev: { id: string; tsMs: number }, meta: Record<string, string | undefined> = {}, bytes = 0, sample?: string) => {
    const key = `${type}|${src.key}|${tgt.key}`;
    let e = edges.get(key);
    if (!e) {
      e = {
        key, type, sourceKey: src.key, targetKey: tgt.key, targetName: tgt.name, targetIsCrownJewel: tgt.isCrownJewel,
        firstMs: ev.tsMs, lastMs: ev.tsMs, count: 0, eventIds: [], bytesOut: 0, meta: {},
      };
      edges.set(key, e);
    }
    e.count++;
    if ((e.samples ||= []).length < 2000) e.samples.push([ev.tsMs, ev.id]);
    e.firstMs = Math.min(e.firstMs, ev.tsMs);
    e.lastMs = Math.max(e.lastMs, ev.tsMs);
    e.bytesOut += bytes;
    if (e.eventIds.length < 25) e.eventIds.push(ev.id);
    for (const [k, v] of Object.entries(meta)) {
      if (!v) continue;
      (e.meta[k] ||= new Set()).add(v);
    }
    if (sample && !edgeSamples.has(key)) edgeSamples.set(key, sample.slice(0, 300));
    edgeKeysByEvent.set(ev.id, [...(edgeKeysByEvent.get(ev.id) || []), key]);
  };

  const rootTs = events[0]?.tsMs ?? t0Ms - windowHours * HOUR_MS;
  const searchMode = !!input.searchMode;
  const root = searchMode
    ? node('query', `Search: ${(input.query || '*').replace(/\s+/g, ' ').slice(0, 60)}`, t0Ms - windowHours * HOUR_MS, { Query: (input.query || '*').slice(0, 2000) }, 'Log search')
    : node('user', username, rootTs, {}, 'Investigated identity');
  const authHostCounts = new Map<string, number>();
  const privilegedGroups = new Set<string>();
  const executions = new Map<string, Map<string, ProcessExecution>>();
  let skippedScriptBlocks = 0;

  // Who performed the event: the investigated user, or (search graphs) the identity in the event
  const actor = (ev: NormalizedEvent): NodeDraft => {
    if (!searchMode) return root;
    if (!ev.user) return root;
    const u = node('user', ev.user, ev.tsMs, {}, 'Matched identity');
    edge('MATCHED', root, u, ev, { protocol: 'Search match' });
    return u;
  };

  const addExecution = (p: NodeDraft, ev: NormalizedEvent) => {
    if (!ev.commandLine) return;
    const list = executions.get(p.key) || executions.set(p.key, new Map()).get(p.key)!;
    const cmd = ev.commandLine.slice(0, MAX_COMMAND_CHARS);
    const prev = list.get(cmd);
    if (prev) {
      prev.count++;
      prev.lastTs = ev.ts;
    } else if (list.size < MAX_EXECUTIONS_PER_PROCESS) {
      list.set(cmd, { ts: ev.ts, commandLine: cmd, parent: ev.parentProcess, user: ev.user, eventId: ev.id, count: 1, source: ev.source });
    }
  };

  const processKey = (image: string, host: string) => `process:${`${basename(image)} @ ${host}`.toLowerCase()}`;
  const processNode = (image: string, host: string, ts: number) =>
    node('process', `${basename(image)} @ ${host}`, ts, { Image: image, Host: host });

  for (const ev of events) {
    const actorHost = ev.host ? node('host', ev.host, ev.tsMs, { Host: ev.host }) : undefined;
    const who = actor(ev);
    switch (ev.category) {
      case 'auth': {
        const targetName = ev.destHost || ev.host;
        if (targetName) {
          const h = node('host', targetName, ev.tsMs, { Host: targetName });
          const lt = ev.logonType ? LOGON_TYPES[ev.logonType] || `Type ${ev.logonType}` : ev.sourcetype;
          edge(ev.outcome === 'failure' ? 'AUTH_FAIL' : 'AUTH_SUCCESS', who, h, ev, { protocol: lt, logonType: ev.logonType, srcIp: ev.srcIp, code: ev.eventCode });
          if (ev.outcome === 'success') authHostCounts.set(targetName, (authHostCounts.get(targetName) || 0) + 1);
        }
        if (ev.srcIp) {
          const ip = node('ip', ev.srcIp, ev.tsMs, { Scope: isPrivateIp(ev.srcIp) ? 'Internal' : 'External' });
          edge('FROM_IP', who, ip, ev, { protocol: ev.sourcetype, outcome: ev.outcome });
        }
        break;
      }
      case 'process': {
        if (!ev.process) break;
        const hostName = ev.host || 'unknown-host';
        if (ev.scriptBlock) {
          // Script blocks enrich the PowerShell process already in the graph; alone they only count when suspicious
          const existing = nodes.get(processKey(ev.process, hostName));
          if (existing) { addExecution(existing, ev); break; }
          if (analyzeCommand(ev.commandLine || '', { scriptBlock: true }).severity === 'info' || analyzeCommand(ev.commandLine || '', { scriptBlock: true }).severity === 'low') { skippedScriptBlocks++; break; }
        }
        const p = processNode(ev.process, hostName, ev.tsMs);
        if (ev.parentProcess) p.details.Parent ||= ev.parentProcess;
        addExecution(p, ev);
        // Child of a process already in the graph: draw the parent -> child chain, so the path continues
        // from the malicious process instead of stopping at the first executable.
        const parent = ev.parentProcess ? nodes.get(processKey(ev.parentProcess, hostName)) : undefined;
        if (parent && parent !== p) {
          edge('SPAWNED', parent, p, ev, { protocol: 'Child process' }, 0, ev.commandLine);
        } else {
          edge('EXECUTED', who, p, ev, { protocol: ev.scriptBlock ? 'Script block' : 'Process start' }, 0, ev.commandLine);
          if (actorHost) edge('RAN_ON', p, actorHost, ev, { protocol: 'Host' });
        }
        break;
      }
      case 'network':
      case 'dns': {
        const destName = ev.category === 'dns' ? ev.domain : ev.destHost || ev.destIp;
        if (!destName) break;
        const tgt = ev.category === 'dns' || (!ev.destIp && ev.destHost)
          ? node('domain', destName, ev.tsMs, { Domain: destName })
          : node('ip', destName, ev.tsMs, { Scope: isPrivateIp(destName) ? 'Internal' : 'External' });
        // Attribute the connection to the process that made it when the log says which one (Sysmon 3/22)
        const from = ev.process && ev.host ? processNode(ev.process, ev.host, ev.tsMs) : actorHost || who;
        edge('CONNECTED_TO', from, tgt, ev, { protocol: ev.category === 'dns' ? 'DNS' : ev.destPort ? `TCP/${ev.destPort}` : ev.sourcetype, action: ev.action }, ev.bytesOut || 0);
        break;
      }
      case 'web': {
        if (!ev.domain) break;
        const d = node('domain', ev.domain, ev.tsMs, { Domain: ev.domain });
        const bytes = ev.bytesOut || 0;
        const isUpload = bytes >= 1024 * 1024;
        edge(isUpload ? 'UPLOADED' : 'CONNECTED_TO', isUpload ? who : actorHost || who, d, ev, { protocol: 'HTTP(S)', action: ev.action }, bytes, ev.url);
        break;
      }
      case 'file': {
        if (!ev.filePath) break;
        const f = node('file', basename(ev.filePath) || ev.filePath, ev.tsMs, { Path: ev.filePath, Host: ev.host || '' });
        if (ev.process && ev.host) edge('WROTE', processNode(ev.process, ev.host, ev.tsMs), f, ev, { protocol: ev.source || ev.sourcetype });
        else edge('ACCESSED', who, f, ev, { protocol: ev.sourcetype });
        break;
      }
      case 'account_change': {
        const g = node('user', ev.group || `group-change-${ev.eventCode}`, ev.tsMs, { EventCode: ev.eventCode || '' }, 'Group');
        edge('MEMBER_CHANGE', who, g, ev, { protocol: `EventCode ${ev.eventCode}` });
        if (ev.group && /admin/i.test(ev.group)) privilegedGroups.add(ev.group);
        break;
      }
      case 'alert': {
        const a = node('alert', ev.signature || 'Alert', ev.tsMs, { Source: ev.sourcetype });
        edge('TRIGGERED', who, a, ev, { protocol: ev.sourcetype, severity: 'MEDIUM' });
        break;
      }
      default:
        break;
    }
  }

  // Alerts delivered by webhook
  for (const al of alerts) {
    const ts = Date.parse(al.ts) || t0Ms;
    const a = node('alert', `${al.alertType} (${al.id})`, ts, { Source: al.source, Severity: al.severity, AlertId: al.id });
    edge('TRIGGERED', root, a, { id: `alert-${al.id}`, tsMs: ts }, { protocol: `${al.source} webhook`, severity: al.severity.toUpperCase(), ttp: al.ttp?.join(',') });
  }

  // Baseline comparison for hosts, IPs and domains
  const baselineAvailable = !!baseline;
  for (const e of edges.values()) {
    if (!baseline) continue;
    if (['AUTH_SUCCESS', 'AUTH_FAIL', 'FROM_IP', 'CONNECTED_TO', 'UPLOADED'].includes(e.type)) {
      e.firstSeenInBaseline = baseline.has(e.targetName.toLowerCase());
    }
  }

  // Risk indicators
  const thresholds = input.thresholds || DEFAULT_THRESHOLDS;
  let indicators: ReturnType<typeof evaluateIndicators>;
  let score: number;
  let band: 'LOW' | 'MEDIUM' | 'HIGH';
  const vip = !searchMode && input.vipEntities.some(v => v.toLowerCase().split('@')[0] === username.toLowerCase());
  if (!searchMode) {
    indicators = evaluateIndicators(events, Array.from(edges.values()), edgeKeysByEvent, input.riskWeights, thresholds);
    ({ score, band } = scoreEntity(indicators, { vip, privileged: privilegedGroups.size > 0 }));
  } else {
    // Search graphs: score each matched identity on its own events, so one user's failures and another's
    // success are never read as a brute force. The graph score is the highest identity score.
    indicators = [];
    score = 0;
    const byUser = new Map<string, NormalizedEvent[]>();
    for (const ev of events) if (ev.user) byUser.set(ev.user, [...(byUser.get(ev.user) || []), ev]);
    for (const [user, evs] of Array.from(byUser.entries()).slice(0, 50)) {
      const ids = new Set(evs.map(e => e.id));
      const userEdges = Array.from(edges.values()).filter(e => e.type !== 'MATCHED' && (e.samples || []).some(([, id]) => ids.has(id)));
      const found = evaluateIndicators(evs, userEdges, edgeKeysByEvent, input.riskWeights, thresholds).map(i => ({ ...i, description: `${user}: ${i.description}` }));
      indicators.push(...found);
      score = Math.max(score, scoreEntity(found, {}).score);
    }
    band = bandFor(score);
  }

  // Which events fired which indicator (for per-visit colouring in the Attack Path view)
  const eventRisk = new Map<string, { severity: 'critical' | 'anomalous'; ttp: string }>();
  // keyed by edge + event, and only for the edges the indicator applies to
  for (const ind of indicators) {
    for (const edgeKey of ind.edgeKeys) {
      for (const id of ind.eventIds) {
        const k = `${edgeKey}|${id}`;
        const prev = eventRisk.get(k);
        if (!prev || (ind.severity === 'critical' && prev.severity !== 'critical')) eventRisk.set(k, { severity: ind.severity, ttp: ind.mitreTactic });
      }
    }
  }

  const edgeSeverity = new Map<string, 'critical' | 'anomalous'>();
  const edgeTtps = new Map<string, Set<string>>();
  for (const ind of indicators) {
    for (const k of ind.edgeKeys) {
      if (ind.severity === 'critical' || !edgeSeverity.has(k)) edgeSeverity.set(k, ind.severity);
      if (/^T\d/.test(ind.mitreTactic)) (edgeTtps.get(k) || edgeTtps.set(k, new Set()).get(k)!).add(ind.mitreTactic);
    }
  }

  // Truncation: keep the riskiest, then most recent, edges within the node budget
  const rank = (e: EdgeDraft) => (edgeSeverity.get(e.key) === 'critical' ? 3 : edgeSeverity.get(e.key) === 'anomalous' || e.firstSeenInBaseline === false ? 2 : e.type === 'AUTH_FAIL' ? 1 : 0);
  const allEdges = Array.from(edges.values()).sort((a, b) => rank(b) - rank(a) || b.lastMs - a.lastMs);
  const keptEdges: EdgeDraft[] = [];
  const keptNodeKeys = new Set<string>([root.key]);
  for (const e of allEdges) {
    if (keptEdges.length >= maxEdges) break;
    const newNodes = [e.sourceKey, e.targetKey].filter(k => !keptNodeKeys.has(k));
    if (keptNodeKeys.size + newNodes.length > maxNodes) continue;
    newNodes.forEach(k => keptNodeKeys.add(k));
    keptEdges.push(e);
  }
  const truncated = keptEdges.length < edges.size;

  const hourOf = (ms: number) => Math.max(0, Math.min(windowHours, Math.ceil((t0Ms - ms) / HOUR_MS)));

  // Edge ids ordered by time: e1 is the earliest activity
  keptEdges.sort((a, b) => a.firstMs - b.firstMs);
  const edgeIdByKey = new Map<string, string>();
  keptEdges.forEach((e, i) => edgeIdByKey.set(e.key, `e${i + 1}`));

  const nodeRisk = new Map<string, number>();
  const nodeCritical = new Set<string>();
  const outEdges: SecurityEdge[] = keptEdges.map(e => {
    const sev = edgeSeverity.get(e.key);
    const status: SecurityEdge['status'] = sev === 'critical' ? 'critical' : sev === 'anomalous' || e.firstSeenInBaseline === false ? 'anomalous' : e.type === 'AUTH_FAIL' ? 'blocked' : 'allowed';
    const r = status === 'critical' ? 85 : status === 'anomalous' ? 55 : status === 'blocked' ? 30 : 10;
    for (const k of [e.sourceKey, e.targetKey]) {
      nodeRisk.set(k, Math.max(nodeRisk.get(k) || 0, r));
      if (status === 'critical') nodeCritical.add(k);
    }
    const protocols = Array.from(e.meta.protocol || []);
    const srcIps = Array.from(e.meta.srcIp || []);
    const mb = e.bytesOut ? ` · ${(e.bytesOut / 1048576).toFixed(1)} MB out` : '';
    const detailParts = [
      `${e.count} event(s) ${e.type} ${e.targetName}`,
      protocols.length ? `via ${protocols.slice(0, 3).join(', ')}` : '',
      srcIps.length ? `from ${srcIps.slice(0, 3).join(', ')}` : '',
    ].filter(Boolean);
    const sample = edgeSamples.get(e.key);
    return {
      id: edgeIdByKey.get(e.key)!,
      source: nodes.get(e.sourceKey)!.id,
      target: nodes.get(e.targetKey)!.id,
      action: e.type,
      type: e.type as EdgeType,
      protocol: protocols[0] || '-',
      hour: hourOf(e.firstMs),
      firstSeen: new Date(e.firstMs).toISOString(),
      lastSeen: new Date(e.lastMs).toISOString(),
      eventCount: e.count,
      status,
      details: detailParts.join(' ') + mb + (sample ? ` · e.g. ${sample}` : ''),
      firstSeenInBaseline: e.firstSeenInBaseline,
      ttp: Array.from(edgeTtps.get(e.key) || []),
      eventIds: e.eventIds,
      visits: splitVisits(e.key, e.samples || [[e.firstMs, '']], eventRisk),
    };
  });

  const outNodes: SecurityNode[] = Array.from(nodes.values())
    .filter(n => keptNodeKeys.has(n.key))
    .map(n => {
      const isRoot = n.key === root.key;
      const baseRisk = isRoot ? score : Math.min(100, (nodeRisk.get(n.key) || 10) + (n.isCrownJewel ? 10 : 0));
      const inBaseline = baseline && ['host', 'ip', 'domain'].includes(n.type) ? baseline.has(n.name.toLowerCase()) : undefined;
      return {
        id: n.id,
        name: n.name,
        type: n.type,
        riskScore: baseRisk,
        riskBand: bandFor(baseRisk),
        compromised: isRoot ? band === 'HIGH' : nodeCritical.has(n.key),
        classification: n.classification || (n.isCrownJewel ? 'Crown jewel' : undefined),
        firstSeenHour: isRoot ? windowHours : hourOf(n.firstMs),
        firstSeen: new Date(n.firstMs).toISOString(),
        lastSeen: new Date(n.lastMs).toISOString(),
        firstSeenInBaseline: isRoot ? true : inBaseline,
        isCrownJewel: n.isCrownJewel,
        isVip: isRoot ? vip : undefined,
        details: n.details,
        executions: executions.has(n.key) ? Array.from(executions.get(n.key)!.values()).sort((a, b) => a.ts.localeCompare(b.ts)) : undefined,
      };
    });

  const factors: ContributingFactor[] = indicators.map(i => ({
    indicator: i.indicator,
    weight: i.weight,
    mitreTactic: i.mitreTactic,
    eventIds: i.eventIds,
    description: i.description,
    edgeIds: i.edgeKeys.map(k => edgeIdByKey.get(k)).filter((x): x is string => !!x),
  }));
  const rootNode = outNodes.find(n => n.id === root.id);
  if (rootNode) rootNode.contributingFactors = factors;

  const fmt = (h: number) => `T-${String(h).padStart(2, '0')}:00`;
  // Milestone time = earliest event that fired the indicator (not the first activity on its edges)
  const eventTs = new Map<string, number>(events.map(e => [e.id, e.tsMs]));
  alerts.forEach(a => eventTs.set(`alert-${a.id}`, Date.parse(a.ts) || t0Ms));
  const milestones: SecurityMilestone[] = factors.map(f => {
    const times = f.eventIds.map(id => eventTs.get(id)).filter((x): x is number => x !== undefined);
    const hours = (f.edgeIds || []).map(id => outEdges.find(e => e.id === id)?.hour ?? 0);
    const h = times.length ? hourOf(Math.min(...times)) : hours.length ? Math.max(...hours) : 0;
    return {
      hour: h,
      timeLabel: fmt(h),
      title: f.indicator,
      severity: f.weight >= 20 ? 'critical' : f.weight >= 15 ? 'high' : f.weight >= 10 ? 'medium' : 'low',
      description: f.description,
      mitreTactic: f.mitreTactic,
      edgeId: f.edgeIds?.[0],
    };
  });
  if (outEdges.length) {
    const first = outEdges[0];
    milestones.push({ hour: first.hour, timeLabel: fmt(first.hour), title: 'First activity in window', severity: 'low', description: first.details, mitreTactic: 'Context', edgeId: first.id });
  }
  milestones.sort((a, b) => b.hour - a.hour);

  const device = Array.from(authHostCounts.entries()).sort((a, b) => b[1] - a[1])[0]?.[0] || 'Unknown';
  const top = [...factors].sort((a, b) => b.weight - a.weight);
  const notes = [
    `Built from ${events.length} ${input.sourceLabel || 'Splunk'} event(s) between ${new Date(t0Ms - windowHours * HOUR_MS).toISOString()} and ${new Date(t0Ms).toISOString()}.`,
    baselineAvailable ? 'Baseline: compared against the user\'s earlier history.' : 'Baseline unavailable (no earlier history found): first-seen indicators are disabled.',
    `Not yet implemented: ${NOT_IMPLEMENTED_INDICATORS.join('; ')}.`,
  ];
  if (skippedScriptBlocks) notes.push(`${skippedScriptBlocks} PowerShell script block(s) with no suspicious content were not drawn (no matching PowerShell process in the window).`);
  if (searchMode) notes.push('Search graph: every identity in the results is shown; risk is scored per identity and the highest score is used.');
  if (truncated) notes.push(`Graph truncated to ${outNodes.length} nodes / ${outEdges.length} edges (from ${nodes.size} / ${edges.size}); highest-risk edges kept.`);

  return {
    id: root.id,
    canonicalId: root.id.toUpperCase(),
    username,
    fullName: searchMode ? `Log search: ${input.query || '*'}` : username,
    role: searchMode ? 'Log search' : 'Unknown (no IdP context)',
    department: 'Unknown',
    baselineLocation: 'Unknown',
    device,
    riskScore: score,
    riskBand: band,
    isVip: vip,
    isPrivileged: privilegedGroups.size > 0,
    alertSummary: top.length ? top.slice(0, 3).map(f => f.indicator).join(' · ') : 'No risk indicators fired in this window',
    triggerEvent: top[0]?.indicator || (alerts[0]?.alertType ?? (searchMode ? 'Analyst log search' : 'Analyst-initiated investigation')),
    aliases: [username],
    nodes: outNodes,
    edges: outEdges,
    milestones,
    contributingFactors: factors,
    dataSource: input.dataSource || 'splunk',
    t0: new Date(t0Ms).toISOString(),
    windowHours,
    truncated,
    totalEventCount: events.length,
    totalNodeCount: nodes.size,
    totalEdgeCount: edges.size,
    baselineAvailable,
    notes,
    rootId: root.id,
    kind: searchMode ? 'search' : 'entity',
    query: searchMode ? input.query : undefined,
    windowStart: new Date(t0Ms - windowHours * HOUR_MS).toISOString(),
  };
}
