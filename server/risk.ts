// Explainable, additive risk scoring (Extended Spec section 6). Every indicator records the events
// and edges that fired it, so the UI and the AI summary can cite them.
import type { NormalizedEvent } from './normalize';

export interface EdgeDraft {
  key: string;
  type: string;
  sourceKey: string;
  targetKey: string;
  targetName: string;
  targetIsCrownJewel: boolean;
  firstMs: number;
  lastMs: number;
  count: number;
  eventIds: string[];
  bytesOut: number;
  firstSeenInBaseline?: boolean;
  meta: Record<string, Set<string>>;
}

export interface Indicator {
  indicator: string;
  weight: number;
  mitreTactic: string;
  description: string;
  eventIds: string[];
  edgeKeys: string[];
  severity: 'critical' | 'anomalous';
}

export interface RiskThresholds {
  bruteForceFailures: number; // failures before a success
  bruteForceWindowMin: number;
  fanOutHosts: number;
  fanOutWindowMin: number;
  massFileMinPerHour: number;
  largeUploadBytes: number;
}

export const DEFAULT_THRESHOLDS: RiskThresholds = {
  bruteForceFailures: 5,
  bruteForceWindowMin: 30,
  fanOutHosts: 5,
  fanOutWindowMin: 60,
  massFileMinPerHour: 100,
  largeUploadBytes: 500 * 1024 * 1024,
};

export const NOT_IMPLEMENTED_INDICATORS = [
  'Impossible travel (needs GeoIP enrichment)',
  'MFA fatigue (needs IdP MFA logs)',
  'Off-hours activity (needs a 30-day activity profile)',
];

const REMOTE_LOGON_TYPES = new Set(['3', '10']);

function uniq<T>(arr: T[]): T[] {
  return Array.from(new Set(arr));
}

function cap<T>(arr: T[], n = 25): T[] {
  return arr.slice(0, n);
}

export function evaluateIndicators(
  events: NormalizedEvent[],
  edges: EdgeDraft[],
  edgeKeysByEvent: Map<string, string[]>,
  weights: Record<string, number>,
  thresholds: RiskThresholds = DEFAULT_THRESHOLDS,
): Indicator[] {
  const out: Indicator[] = [];
  const w = (key: string, fallback: number) => (typeof weights[key] === 'number' ? weights[key] : fallback);
  const edgeType = new Map(edges.map(e => [e.key, e.type]));
  // Edges carrying these events, limited to the edge types the indicator is about
  const edgesFor = (ids: string[], types: string[]) =>
    uniq(ids.flatMap(id => edgeKeysByEvent.get(id) || [])).filter(k => types.includes(edgeType.get(k) || ''));

  // 1. Brute force then success
  const auth = events.filter(e => e.category === 'auth');
  const windowMs = thresholds.bruteForceWindowMin * 60_000;
  const failQueue: NormalizedEvent[] = [];
  for (const ev of auth) {
    while (failQueue.length && ev.tsMs - failQueue[0].tsMs > windowMs) failQueue.shift();
    if (ev.outcome === 'failure') { failQueue.push(ev); continue; }
    if (ev.outcome === 'success' && failQueue.length >= thresholds.bruteForceFailures) {
      const ids = [...failQueue.map(f => f.id), ev.id];
      out.push({
        indicator: 'Brute force then success',
        weight: w('bruteForceThenSuccess', 20),
        mitreTactic: 'T1110',
        description: `${failQueue.length} failed logons followed by a successful logon on ${ev.host || ev.destHost || 'unknown host'} within ${thresholds.bruteForceWindowMin} min`,
        eventIds: cap(ids),
        edgeKeys: edgesFor(ids, ['AUTH_FAIL', 'AUTH_SUCCESS', 'FROM_IP']),
        severity: 'critical',
      });
      break; // additive score counts each indicator once
    }
  }

  // 2. First-seen host / app access
  const firstSeenAccess = edges.filter(e => (e.type === 'AUTH_SUCCESS' || e.type === 'ACCESSED') && e.firstSeenInBaseline === false);
  if (firstSeenAccess.length) {
    const crown = firstSeenAccess.some(e => e.targetIsCrownJewel);
    const base = w('firstSeenHostApp', 10);
    out.push({
      indicator: crown ? 'First-seen host/app access (crown jewel)' : 'First-seen host/app access',
      weight: crown ? Math.round(base * (weights.crownJewelMultiplier || 2)) : base,
      mitreTactic: 'T1078',
      description: `Accessed ${firstSeenAccess.length} host(s)/app(s) not seen in the baseline: ${firstSeenAccess.slice(0, 5).map(e => e.targetName).join(', ')}`,
      eventIds: cap(firstSeenAccess.flatMap(e => e.eventIds)),
      edgeKeys: firstSeenAccess.map(e => e.key),
      severity: crown ? 'critical' : 'anomalous',
    });
  }

  // 3. New source IP
  const newIps = edges.filter(e => e.type === 'FROM_IP' && e.firstSeenInBaseline === false);
  if (newIps.length) {
    out.push({
      indicator: 'New source IP',
      weight: w('newSourceIpAsn', 10),
      mitreTactic: 'T1078',
      description: `Sessions from ${newIps.length} source IP(s) not seen in the baseline: ${newIps.slice(0, 5).map(e => e.targetName).join(', ')}`,
      eventIds: cap(newIps.flatMap(e => e.eventIds)),
      edgeKeys: newIps.map(e => e.key),
      severity: 'anomalous',
    });
  }

  // 4. Lateral fan-out
  const remote = auth.filter(e => e.outcome === 'success' && (!e.logonType || REMOTE_LOGON_TYPES.has(e.logonType)) && (e.host || e.destHost));
  const fanWindow = thresholds.fanOutWindowMin * 60_000;
  const hostCounts = new Map<string, number>();
  let left = 0;
  for (let right = 0; right < remote.length; right++) {
    const h = (remote[right].destHost || remote[right].host)!;
    hostCounts.set(h, (hostCounts.get(h) || 0) + 1);
    while (remote[right].tsMs - remote[left].tsMs > fanWindow) {
      const lh = (remote[left].destHost || remote[left].host)!;
      const n = (hostCounts.get(lh) || 1) - 1;
      if (n === 0) hostCounts.delete(lh); else hostCounts.set(lh, n);
      left++;
    }
    if (hostCounts.size >= thresholds.fanOutHosts) {
      const ids = remote.slice(left, right + 1).map(e => e.id);
      out.push({
        indicator: 'Lateral fan-out',
        weight: w('lateralFanOut', 20),
        mitreTactic: 'T1021',
        description: `Successful remote logons to ${hostCounts.size} distinct hosts within ${thresholds.fanOutWindowMin} min`,
        eventIds: cap(ids),
        edgeKeys: edgesFor(ids, ['AUTH_SUCCESS']),
        severity: 'critical',
      });
      break;
    }
  }

  // 5. Privilege change
  const priv = edges.filter(e => e.type === 'MEMBER_CHANGE' && /admin|domain admins|enterprise admins|administrators|schema admins/i.test(e.targetName));
  if (priv.length) {
    out.push({
      indicator: 'Privilege change',
      weight: w('privilegeChange', 20),
      mitreTactic: 'T1098',
      description: `Membership change into privileged group(s): ${priv.map(e => e.targetName).join(', ')}`,
      eventIds: cap(priv.flatMap(e => e.eventIds)),
      edgeKeys: priv.map(e => e.key),
      severity: 'critical',
    });
  }

  // 6. Mass file access (within-window comparison; a 30-day p95 baseline is a later improvement)
  const fileEvents = events.filter(e => e.category === 'file');
  if (fileEvents.length) {
    const buckets = new Map<number, NormalizedEvent[]>();
    fileEvents.forEach(e => {
      const b = Math.floor(e.tsMs / 3_600_000);
      buckets.set(b, [...(buckets.get(b) || []), e]);
    });
    const counts = Array.from(buckets.values()).map(v => v.length).sort((a, b) => a - b);
    const median = counts[Math.floor(counts.length / 2)] || 0;
    const threshold = Math.max(thresholds.massFileMinPerHour, median * 3);
    const hot = Array.from(buckets.values()).filter(v => v.length > threshold);
    if (hot.length) {
      const ids = hot.flat().map(e => e.id);
      out.push({
        indicator: 'Mass file access',
        weight: w('massFileAccess', 15),
        mitreTactic: 'T1005',
        description: `${Math.max(...hot.map(h => h.length))} file events in one hour (threshold ${threshold})`,
        eventIds: cap(ids),
        edgeKeys: edgesFor(ids, ['ACCESSED']),
        severity: 'anomalous',
      });
    }
  }

  // 7. Large upload
  const uploads = edges.filter(e => (e.type === 'UPLOADED' || e.type === 'CONNECTED_TO') && e.bytesOut >= thresholds.largeUploadBytes);
  if (uploads.length) {
    out.push({
      indicator: 'Large upload',
      weight: w('largeUpload', 20),
      mitreTactic: 'T1567',
      description: `Outbound transfer over ${Math.round(thresholds.largeUploadBytes / 1048576)} MB to ${uploads.map(e => `${e.targetName} (${Math.round(e.bytesOut / 1048576)} MB)`).join(', ')}`,
      eventIds: cap(uploads.flatMap(e => e.eventIds)),
      edgeKeys: uploads.map(e => e.key),
      severity: 'critical',
    });
  }

  // 8. Encoded PowerShell (WatchMe extension beyond the spec's indicator list)
  const encoded = events.filter(e => e.category === 'process' && e.commandLine && /powershell|pwsh/i.test(e.commandLine) && /\s-(e|en|enc|enco|encod|encode|encoded|encodedcommand)\s/i.test(e.commandLine + ' '));
  if (encoded.length) {
    const ids = encoded.map(e => e.id);
    out.push({
      indicator: 'Encoded PowerShell',
      weight: w('encodedPowerShell', 15),
      mitreTactic: 'T1059.001',
      description: `${encoded.length} PowerShell execution(s) with an encoded command line`,
      eventIds: cap(ids),
      edgeKeys: edgesFor(ids, ['EXECUTED', 'RAN_ON']),
      severity: 'critical',
    });
  }

  // 9. Correlated alerts (from SIEM data or alert webhooks)
  const alertEdges = edges.filter(e => e.type === 'TRIGGERED');
  if (alertEdges.length) {
    const sevWeight = (s: string) => (s === 'CRITICAL' ? 30 : s === 'HIGH' ? 20 : s === 'MEDIUM' ? 10 : 5);
    const total = Math.min(30, alertEdges.reduce((sum, e) => sum + Math.max(...Array.from(e.meta.severity || ['LOW']).map(sevWeight)), 0));
    out.push({
      indicator: 'Correlated alert',
      weight: total,
      mitreTactic: uniq(alertEdges.flatMap(e => Array.from(e.meta.ttp || []))).join(', ') || 'per alert',
      description: `${alertEdges.length} alert(s) associated with this identity: ${alertEdges.slice(0, 3).map(e => e.targetName).join('; ')}`,
      eventIds: cap(alertEdges.flatMap(e => e.eventIds)),
      edgeKeys: alertEdges.map(e => e.key),
      severity: total >= 20 ? 'critical' : 'anomalous',
    });
  }

  return out;
}

export function scoreEntity(indicators: Indicator[], multipliers: { vip?: boolean; privileged?: boolean; leaver?: boolean }) {
  let score = indicators.reduce((s, i) => s + i.weight, 0);
  if (multipliers.vip) score *= 1.2;
  if (multipliers.privileged) score *= 1.3;
  if (multipliers.leaver) score *= 1.5;
  score = Math.min(100, Math.round(score));
  return { score, band: bandFor(score) };
}

export function bandFor(score: number): 'LOW' | 'MEDIUM' | 'HIGH' {
  return score >= 70 ? 'HIGH' : score >= 40 ? 'MEDIUM' : 'LOW';
}
