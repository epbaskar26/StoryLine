// Builds the linear "Attack Path": every visit to an entity, in time order, starting from the user's first login.
// Routine (low-risk, previously seen) steps are collapsed; returning to an entity already reached is a "revisit".
import type { SecurityEdge, SecurityNode, UserProfile } from './types';

const HOUR_MS = 3_600_000;

const TACTICS: Record<string, string> = {
  T1566: 'Initial Access', T1078: 'Initial Access', T1190: 'Initial Access', T1133: 'Initial Access',
  T1110: 'Credential Access', T1003: 'Credential Access', T1555: 'Credential Access', T1558: 'Credential Access',
  T1059: 'Execution', T1204: 'Execution', T1047: 'Execution',
  T1098: 'Persistence', T1547: 'Persistence', T1053: 'Persistence', T1136: 'Persistence', T1543: 'Persistence',
  T1027: 'Defense Evasion', T1140: 'Defense Evasion', T1218: 'Defense Evasion', T1562: 'Defense Evasion', T1564: 'Defense Evasion', T1055: 'Defense Evasion',
  T1087: 'Discovery', T1083: 'Discovery', T1082: 'Discovery', T1018: 'Discovery', T1135: 'Discovery',
  T1021: 'Lateral Movement', T1550: 'Lateral Movement', T1570: 'Lateral Movement',
  T1005: 'Collection', T1039: 'Collection', T1560: 'Collection', T1114: 'Collection',
  T1071: 'Command & Control', T1105: 'Command & Control', T1572: 'Command & Control', T1573: 'Command & Control',
  T1567: 'Exfiltration', T1048: 'Exfiltration', T1041: 'Exfiltration',
  T1486: 'Impact', T1490: 'Impact', T1489: 'Impact', T1485: 'Impact',
};

export function tacticFor(ttp?: string): string | undefined {
  if (!ttp) return undefined;
  return TACTICS[ttp.split('.')[0]];
}

export interface PathStep {
  key: string;
  edge: SecurityEdge;
  node: SecurityNode; // the entity reached in this step
  status: SecurityEdge['status']; // risk of this visit (can differ from the edge overall)
  startMs: number;
  endMs: number;
  count: number; // events in this visit
  hour: number; // hours before T-0 when this visit started
  routine: boolean;
  visitNo: number; // 1 = first time this entity is reached; 2+ = revisit
  firstVisitHour?: number;
  firstVisitMs?: number; // when this entity was first reached (for revisit notes)
  gapMs?: number; // time since the previous visit to this entity ended
  ttp?: string;
  tactic?: string;
  isFirstLogin: boolean;
}

export interface AttackPath {
  root: SecurityNode | undefined;
  steps: PathStep[]; // every step in time order
}

export function buildAttackPath(profile: UserProfile): AttackPath {
  const t0 = Date.parse(profile.t0 || '') || Date.now();
  const windowHours = profile.windowHours ?? 48;
  const byId = new Map(profile.nodes.map(n => [n.id, n]));
  const root =
    (profile.rootId && byId.get(profile.rootId)) ||
    profile.nodes.find(n => n.type === 'user' && n.name.toLowerCase() === profile.username.toLowerCase()) ||
    profile.nodes.find(n => n.type === 'user');
  const searchGraph = profile.kind === 'search';
  const hourOf = (ms: number) => Math.max(0, Math.min(windowHours, Math.ceil((t0 - ms) / HOUR_MS)));

  const raw: Omit<PathStep, 'visitNo' | 'firstVisitHour' | 'gapMs' | 'isFirstLogin'>[] = [];
  for (const edge of profile.edges) {
    const src = byId.get(edge.source);
    const node = byId.get(edge.target);
    if (!src || !node) continue;
    // Keep the investigated user's own activity; drop other identities added by 1-hop expansion
    if (!searchGraph && src.type === 'user' && root && src.id !== root.id) continue;

    const hasVisits = !!edge.visits?.length;
    const visits = hasVisits
      ? edge.visits!.map(v => ({ start: Date.parse(v.start), end: Date.parse(v.end), count: v.count, status: v.status, ttp: v.ttp }))
      : [{ start: Date.parse(edge.firstSeen || '') || t0 - edge.hour * HOUR_MS, end: Date.parse(edge.lastSeen || edge.firstSeen || '') || t0 - edge.hour * HOUR_MS, count: edge.eventCount, status: undefined, ttp: undefined }];
    // With per-visit risk (real data), a visit is only as risky as the events inside it
    const perVisitRisk = hasVisits && edge.visits!.some(v => v.status);

    visits.forEach((v, i) => {
      const status: SecurityEdge['status'] = perVisitRisk
        ? v.status || (edge.status === 'blocked' ? 'blocked' : edge.firstSeenInBaseline === false && i === 0 ? 'anomalous' : 'allowed')
        : edge.status;
      const ttp = perVisitRisk ? v.ttp?.[0] : edge.ttp?.[0];
      // What a risky process does next (children, files, connections) is part of the story, not routine
      const childOfRisky = ['SPAWNED', 'WROTE', 'CONNECTED_TO'].includes(edge.type) && src.type === 'process' && (src.compromised || src.riskScore >= 55);
      const routine = !(childOfRisky || status === 'critical' || status === 'anomalous' || status === 'blocked' || (edge.firstSeenInBaseline === false && i === 0) || edge.type === 'TRIGGERED' || edge.type === 'MATCHED');
      raw.push({
        key: `${edge.id}#${i}`,
        edge,
        node,
        status,
        startMs: v.start,
        endMs: Math.max(v.start, v.end),
        count: v.count,
        hour: hourOf(v.start),
        routine,
        ttp,
        tactic: tacticFor(ttp),
      });
    });
  }
  raw.sort((a, b) => a.startMs - b.startMs || a.edge.id.localeCompare(b.edge.id, undefined, { numeric: true }));

  const seen = new Map<string, { visits: number; lastEnd: number; firstHour: number; firstMs: number }>();
  let firstLoginMarked = false;
  const steps: PathStep[] = raw.map(r => {
    const prev = seen.get(r.node.id);
    const isLogin = r.edge.type === 'AUTH_SUCCESS' || r.edge.type === 'FROM_IP';
    const isFirstLogin = !firstLoginMarked && isLogin;
    if (isFirstLogin) firstLoginMarked = true;
    const step: PathStep = {
      ...r,
      visitNo: (prev?.visits || 0) + 1,
      firstVisitHour: prev?.firstHour,
      firstVisitMs: prev?.firstMs,
      gapMs: prev ? Math.max(0, r.startMs - prev.lastEnd) : undefined,
      isFirstLogin,
    };
    seen.set(r.node.id, { visits: step.visitNo, lastEnd: Math.max(prev?.lastEnd || 0, r.endMs), firstHour: prev?.firstHour ?? r.hour, firstMs: prev?.firstMs ?? r.startMs });
    return step;
  });

  return { root, steps };
}

export interface DisplayedStep extends PathStep {
  hiddenBefore: number; // routine steps collapsed between the previous shown step and this one
}

// Steps to draw: risky steps plus the first login; routine steps collapsed unless showRoutine.
export function displayedSteps(path: AttackPath, showRoutine: boolean, limit = 120): { shown: DisplayedStep[]; hiddenAfter: number; truncated: number } {
  const shown: DisplayedStep[] = [];
  let hidden = 0;
  for (const s of path.steps) {
    if (showRoutine || !s.routine || s.isFirstLogin) {
      shown.push({ ...s, hiddenBefore: hidden });
      hidden = 0;
    } else {
      hidden++;
    }
  }
  const truncated = Math.max(0, shown.length - limit);
  return { shown: shown.slice(0, limit), hiddenAfter: hidden, truncated };
}

export function formatGap(ms?: number): string {
  if (ms === undefined) return '';
  const h = ms / HOUR_MS;
  if (h >= 24) return `${Math.round(h / 24)}d`;
  if (h >= 1) return `${Math.round(h)}h`;
  return `${Math.max(1, Math.round(ms / 60_000))}m`;
}
