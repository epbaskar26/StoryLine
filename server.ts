import express, { type Request, type Response, type NextFunction } from 'express';
import { createServer as createViteServer } from 'vite';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';

import type { UserProfile, WatchlistItem, CaseRecord, EntitySummary, SecurityNode, SecurityEdge, SystemStatus, EvidenceRecord, InvestigationNote, NoteKind, Disposition, Storyline, SecurityMilestone, ContributingFactor } from './src/types';
import { DEMO_USERS, DEMO_WATCHLIST, DEMO_CASES, DEMO_AUDIT, DEFAULT_ADMIN_CONFIG, type AdminConfig, type ConnectorConfig } from './server/demoData';
import { assertSafeEntity } from './server/splunk';
import { loadLogSource } from './server/sources';
import { buildProfile, opaqueId, type AlertRecord } from './server/graphBuilder';
import { tokenizeProfile, rehydrate, auditCitations, deterministicSummary } from './server/sanitize';
import { loadAiProvider, type AiProvider } from './server/ai';
import { generateStoryline, storylineHash } from './server/storyline';
import { createStore } from './server/store';

dotenv.config({ path: ['.env.local', '.env'] });

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ----------------- Configuration -----------------
const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '127.0.0.1'; // local-only by default: there is no login yet
let loaded: ReturnType<typeof loadLogSource>;
try {
  loaded = loadLogSource();
} catch (err: any) {
  console.error(err.message);
  process.exit(1);
}
const DATA_SOURCE = loaded.dataSource; // 'demo' | 'splunk' | 'elastic'
const SOURCE = loaded.source; // live log source, or null in demo mode
const ANALYST = process.env.WATCHME_ANALYST || 'local.analyst';
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || '';
const BASELINE_DAYS = parseInt(process.env.BASELINE_DAYS || '30', 10);
const DEFAULT_T0 = process.env.DEFAULT_T0 || ''; // e.g. 2018-08-21T00:00:00Z for BOTS data
const CACHE_TTL_MS = parseInt(process.env.GRAPH_CACHE_TTL_MS || '300000', 10);
const HOUR_MS = 3_600_000;

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '5mb' }));

let ai: AiProvider | null = null;
try {
  ai = loadAiProvider();
} catch (err: any) {
  console.error(err.message);
  process.exit(1);
}
const aiLabel = () => (ai ? `${ai.kind === 'ollama' ? 'Ollama (local)' : 'Gemini'} ${ai.model}` : 'deterministic (no AI provider configured)');

const store = createStore();

// ----------------- Helpers -----------------
class HttpError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

const asyncRoute = (fn: (req: Request, res: Response) => Promise<unknown>) =>
  (req: Request, res: Response, next: NextFunction) => { fn(req, res).catch(next); };

const newId = (prefix: string) => `${prefix}-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
const sha256 = (s: string) => crypto.createHash('sha256').update(s).digest('hex');

async function audit(action: string, entityId: string, details: string, hash?: string, analyst = ANALYST) {
  await store.addAudit({ id: newId('aud'), timestamp: new Date().toISOString(), analyst, action, entityId, details, sha256: hash });
}

// Entity keys: demo keys are lower-case alphanumerics; Splunk keys are validated account names.
function entityKeyOf(raw: string): string {
  const v = String(raw || '').trim();
  if (!v) throw new HttpError(400, 'Entity is required');
  if (DATA_SOURCE === 'demo') return v.toLowerCase().replace(/[^a-z0-9]/g, '');
  try {
    return assertSafeEntity(v).toLowerCase();
  } catch (e: any) {
    throw new HttpError(400, e.message);
  }
}

const MAX_WINDOW_HOURS = 168;

// Window = [t0 - windowHours, t0]. t0 empty means "now". windowHours comes from windowHours, from, or windowDays.
// Notes and cases belong to an investigation: an entity key, or "search:<query>" for search graphs
function investigationKeyOf(raw: unknown): string {
  const v = String(raw || '').trim();
  if (v.startsWith('search:')) return v.slice(0, 300);
  return entityKeyOf(v);
}

function parseWindow(req: Request): { windowHours: number; t0Ms: number } {
  const param = (k: string) => String((req.query as any)[k] ?? req.body?.[k] ?? '');
  // Empty strings mean "not set": fall back to DEFAULT_T0, then to now
  const t0Raw = param('t0') || DEFAULT_T0;
  const t0Ms = t0Raw ? Date.parse(t0Raw) : Date.now();
  if (!Number.isFinite(t0Ms)) throw new HttpError(400, `Invalid t0 "${t0Raw}" (use ISO 8601, e.g. 2018-08-21T00:00:00Z)`);
  const clampHours = (h: number) => Math.min(MAX_WINDOW_HOURS, Math.max(1, Math.ceil(h)));
  const fromRaw = param('from');
  if (fromRaw) {
    const fromMs = Date.parse(fromRaw);
    if (!Number.isFinite(fromMs) || fromMs >= t0Ms) throw new HttpError(400, 'from must be an ISO time before the end of the window');
    return { windowHours: clampHours((t0Ms - fromMs) / HOUR_MS), t0Ms };
  }
  const hours = parseInt(param('windowHours'), 10);
  if (Number.isFinite(hours) && hours > 0) return { windowHours: clampHours(hours), t0Ms };
  const days = Math.min(7, Math.max(1, parseInt(param('windowDays') || '2', 10) || 2));
  return { windowHours: days * 24, t0Ms };
}

// ----------------- Profile building & cache -----------------
const profileCache = new Map<string, { profile: UserProfile; builtAt: number }>();
let lastGraphBuildMs: number | null = null;

function cacheKey(entityKey: string, windowHours: number, t0Ms: number) {
  // Round "now"-based T-0 to the minute so repeated loads hit the cache
  return `${entityKey}|${windowHours}|${Math.floor(t0Ms / 60000)}`;
}

function invalidateEntity(entityKey: string) {
  for (const k of profileCache.keys()) if (k.startsWith(`${entityKey}|`)) profileCache.delete(k);
}

function latestCachedProfile(entityKey: string): UserProfile | null {
  let best: { profile: UserProfile; builtAt: number } | null = null;
  for (const [k, v] of profileCache) if (k.startsWith(`${entityKey}|`) && (!best || v.builtAt > best.builtAt)) best = v;
  return best?.profile || null;
}

function alertToGraph(al: AlertRecord, rootId: string, t0Ms: number, windowHours: number): { node: SecurityNode; edge: SecurityEdge } {
  const ts = Date.parse(al.ts) || t0Ms;
  const hour = Math.max(0, Math.min(windowHours, Math.ceil((t0Ms - ts) / HOUR_MS)));
  const sev = al.severity.toUpperCase();
  const score = sev === 'CRITICAL' ? 95 : sev === 'HIGH' ? 85 : sev === 'MEDIUM' ? 60 : 30;
  const nodeId = `alert_${al.id.replace(/[^A-Za-z0-9]/g, '').slice(-10)}`;
  return {
    node: {
      id: nodeId, name: `${al.alertType} (${al.id})`, type: 'alert', riskScore: score,
      riskBand: score >= 70 ? 'HIGH' : score >= 40 ? 'MEDIUM' : 'LOW', compromised: score >= 85,
      classification: `${al.source} alert (webhook)`, firstSeenHour: hour, firstSeen: new Date(ts).toISOString(),
      details: { Source: al.source, Severity: sev, AlertId: al.id, ReceivedAt: al.ts },
    },
    edge: {
      id: `ea_${nodeId.slice(6)}`, source: rootId, target: nodeId, action: 'TRIGGERED', type: 'TRIGGERED',
      protocol: `${al.source} webhook`, hour, firstSeen: new Date(ts).toISOString(), eventCount: 1,
      status: score >= 85 ? 'critical' : 'anomalous', details: `Alert from ${al.source}: ${al.alertType}`, ttp: al.ttp || [],
      eventIds: [`alert-${al.id}`],
    },
  };
}

async function buildDemoProfile(entityKey: string, windowHours: number, t0Ms: number): Promise<UserProfile> {
  const p = demoProfileSync(entityKey, t0Ms);
  const demoHours = 48;
  if (windowHours !== demoHours) p.notes!.push('The demo dataset only covers 48 hours; the 7-day window applies to live data.');
  const rootId = p.rootId || p.id;
  for (const al of await store.listAlerts(entityKey)) {
    const { node, edge } = alertToGraph(al, rootId, t0Ms, demoHours);
    p.nodes.push(node);
    p.edges.push(edge);
  }
  return p;
}

function demoProfileSync(entityKey: string, t0Ms: number): UserProfile {
  const base = DEMO_USERS[entityKey];
  if (!base) throw new HttpError(404, `Unknown entity "${entityKey}". Demo mode only contains: ${Object.keys(DEMO_USERS).join(', ')}.`);
  const p: UserProfile = JSON.parse(JSON.stringify(base));
  const demoHours = 48; // the demo dataset only covers 48 h
  p.dataSource = 'demo';
  p.windowHours = demoHours;
  p.t0 = new Date(t0Ms).toISOString();
  // Demo times are stored as hour offsets ("H42" = 42 h before the end of the window)
  const demoTime = (v: string) => (/^H\d+(\.\d+)?$/.test(v) ? new Date(t0Ms - parseFloat(v.slice(1)) * HOUR_MS).toISOString() : v);
  p.nodes.forEach(n => {
    n.firstSeen = new Date(t0Ms - n.firstSeenHour * HOUR_MS).toISOString();
    n.executions?.forEach(x => { x.ts = demoTime(x.ts); if (x.lastTs) x.lastTs = demoTime(x.lastTs); });
  });
  p.edges.forEach(e => { e.firstSeen = new Date(t0Ms - e.hour * HOUR_MS).toISOString(); });
  p.windowStart = new Date(t0Ms - demoHours * HOUR_MS).toISOString();
  p.kind = 'entity';
  // Replace the readable demo ids (u_jsmith, app_hr...) with opaque ids, as real graphs use,
  // so ids can be cited to the AI model without revealing entity names.
  const idMap = new Map(p.nodes.map(n => [n.id, opaqueId(n.type, `${n.type}:${n.name.toLowerCase()}`)]));
  const rootOld = p.nodes.find(n => n.type === 'user')?.id;
  p.nodes.forEach(n => { n.id = idMap.get(n.id)!; });
  if (rootOld) p.rootId = idMap.get(rootOld);
  p.edges.forEach(e => { e.source = idMap.get(e.source) || e.source; e.target = idMap.get(e.target) || e.target; });
  // Link demo factors to the edges that carry their event ids
  p.contributingFactors.forEach(f => { f.edgeIds = p.edges.filter(e => (e.eventIds || []).some(id => f.eventIds.includes(id))).map(e => e.id); });
  p.notes = ['DEMO DATA: fictional users, hosts and events. Set DATA_SOURCE=splunk or elastic to investigate real logs.'];
  p.totalEventCount = p.edges.reduce((s, e) => s + e.eventCount, 0);
  return p;
}

async function buildLiveProfile(entityKey: string, windowHours: number, t0Ms: number): Promise<UserProfile> {
  const src = SOURCE!;
  const start = t0Ms - windowHours * HOUR_MS;
  const { events, rawCount } = await src.fetchUserEvents(entityKey, start, t0Ms);
  const alerts = (await store.listAlerts(entityKey)).filter(a => {
    const ts = Date.parse(a.ts);
    return ts >= start && ts <= t0Ms;
  });
  if (!events.length && !alerts.length) {
    throw new HttpError(404, `No ${src.label} events found for "${entityKey}" between ${new Date(start).toISOString()} and ${new Date(t0Ms).toISOString()} in ${src.location}. Check the username, the index, and T-0 (historical datasets such as BOTS need an explicit T-0).`);
  }
  let baseline: Set<string> | null = null;
  if (BASELINE_DAYS > 0) {
    try {
      baseline = await src.fetchBaseline(entityKey, start - BASELINE_DAYS * 24 * HOUR_MS, start);
    } catch (err: any) {
      console.warn('Baseline query failed:', err.message);
    }
  }
  const config = await store.getConfig();
  const profile = buildProfile({
    username: entityKey,
    events,
    alerts,
    t0Ms,
    windowHours,
    baseline,
    crownJewelTags: config.crownJewelTags,
    vipEntities: config.vipEntities,
    riskWeights: config.riskWeights,
    dataSource: src.kind,
    sourceLabel: src.label,
  });
  if (rawCount >= src.maxEvents) profile.notes?.push(`${src.label} returned the maximum of ${src.maxEvents} events; older activity may be missing (raise ${src.kind.toUpperCase()}_MAX_EVENTS).`);
  return profile;
}

async function getProfile(entityKey: string, windowHours: number, t0Ms: number, force = false): Promise<{ profile: UserProfile; buildMs: number; cached: boolean }> {
  const key = cacheKey(entityKey, windowHours, t0Ms);
  const hit = profileCache.get(key);
  if (!force && hit && Date.now() - hit.builtAt < CACHE_TTL_MS) {
    return { profile: await withAnnotations(entityKey, hit.profile), buildMs: 0, cached: true };
  }
  const started = Date.now();
  const profile = DATA_SOURCE === 'demo' ? await buildDemoProfile(entityKey, windowHours, t0Ms) : await buildLiveProfile(entityKey, windowHours, t0Ms);
  const buildMs = Date.now() - started;
  lastGraphBuildMs = buildMs;
  profileCache.set(key, { profile, builtAt: Date.now() });
  return { profile: await withAnnotations(entityKey, profile), buildMs, cached: false };
}

async function withAnnotations(entityKey: string, profile: UserProfile): Promise<UserProfile> {
  const notes = await store.listAnnotations(entityKey);
  if (!notes.length) return profile;
  const byNode = new Map(notes.map(a => [a.nodeId, a.text]));
  return { ...profile, nodes: profile.nodes.map(n => (byNode.has(n.id) ? { ...n, annotation: byNode.get(n.id) } : n)) };
}

function toSummary(p: UserProfile, key: string): EntitySummary {
  return { id: key, username: p.username, fullName: p.fullName, riskScore: p.riskScore, triggerEvent: p.triggerEvent };
}

// Cumulative risk across the window in 6 buckets (used for the watchlist sparkline).
function riskSparkline(p: UserProfile): number[] {
  const hours = p.windowHours ?? 48;
  const buckets = 6;
  const out: number[] = [];
  for (let b = 1; b <= buckets; b++) {
    const cutoff = hours - (hours / buckets) * b; // hour offset reached at end of bucket
    const score = p.milestones
      .filter(m => m.hour >= cutoff && m.mitreTactic !== 'Context')
      .reduce((s, m) => s + (p.contributingFactors.find(f => f.indicator === m.title)?.weight || 0), 0);
    out.push(Math.min(100, Math.max(4, score)));
  }
  return out;
}

// ----------------- API: status & entities -----------------
app.get('/api/status', asyncRoute(async (_req, res) => {
  const status: SystemStatus = {
    dataSource: DATA_SOURCE,
    liveConfigured: !!SOURCE,
    liveLabel: SOURCE?.label ?? null,
    queryLanguage: SOURCE?.queryLanguage ?? null,
    storage: store.kind,
    aiConfigured: !!ai,
    aiProvider: ai ? ai.kind : 'none',
    aiModel: ai ? ai.model : null,
    analyst: ANALYST,
    lastGraphBuildMs,
  };
  res.json(status);
}));

app.get('/api/users', asyncRoute(async (_req, res) => {
  const users = new Map<string, EntitySummary>();
  if (DATA_SOURCE === 'demo') {
    for (const [key, p] of Object.entries(DEMO_USERS)) users.set(key, toSummary(p, key));
  }
  for (const w of await store.listWatchlist()) {
    if (!users.has(w.entityId)) {
      users.set(w.entityId, { id: w.entityId, username: w.entityId, fullName: w.canonicalName, riskScore: w.riskScore, triggerEvent: w.reason });
    }
  }
  res.json({ users: Array.from(users.values()) });
}));

// FR-01: Resolve entity / alias search
app.get('/api/entities/resolve', asyncRoute(async (req, res) => {
  const term = String(req.query.term || '').toLowerCase().trim();
  if (!term) return res.json({ matches: [] });

  if (DATA_SOURCE === 'demo') {
    const matches = Object.entries(DEMO_USERS).flatMap(([key, user]) => {
      const aliasMatch = user.aliases.find(a => a.toLowerCase().includes(term));
      const matched = aliasMatch || (user.username.toLowerCase().includes(term) ? user.username : user.fullName.toLowerCase().includes(term) ? user.fullName : user.id.toLowerCase().includes(term) ? user.id : '');
      return matched ? [{ id: key, canonicalId: user.canonicalId, username: user.username, fullName: user.fullName, role: user.role, riskScore: user.riskScore, riskBand: user.riskBand, matchedAlias: matched }] : [];
    });
    return res.json({ matches });
  }

  let safeTerm: string;
  try { safeTerm = assertSafeEntity(term); } catch { return res.json({ matches: [] }); }
  const { windowHours, t0Ms } = parseWindow(req);
  const found = await SOURCE!.searchUsers(safeTerm, t0Ms - windowHours * HOUR_MS, t0Ms);
  res.json({
    matches: found.map(f => ({
      id: f.user, canonicalId: f.user, username: f.user, fullName: f.user, role: `${f.count} events in window`,
      riskScore: latestCachedProfile(f.user)?.riskScore ?? 0, riskBand: latestCachedProfile(f.user)?.riskBand ?? 'LOW', matchedAlias: f.user,
    })),
  });
}));

// ----------------- API: watchlist (FR-03) -----------------
app.get('/api/watchlist', asyncRoute(async (_req, res) => {
  res.json({ items: await store.listWatchlist() });
}));

app.post('/api/watchlist', asyncRoute(async (req, res) => {
  const entityKey = entityKeyOf(req.body.entityId);
  const reason = String(req.body.reason || 'Added by analyst').slice(0, 300);
  const expiryDays = Math.min(30, Math.max(1, Number(req.body.expiryDays) || 7));
  let profile: UserProfile | null = latestCachedProfile(entityKey);
  if (!profile) {
    const { windowHours, t0Ms } = parseWindow(req);
    profile = (await getProfile(entityKey, windowHours, t0Ms)).profile; // throws 404 for unknown entities
  }
  const item: WatchlistItem = {
    id: newId('wl'),
    entityId: entityKey,
    canonicalName: profile.fullName !== profile.username ? `${profile.username} (${profile.fullName})` : profile.username,
    entityType: 'user',
    riskScore: profile.riskScore,
    riskBand: profile.riskBand,
    owner: ANALYST,
    reason,
    expiry: new Date(Date.now() + expiryDays * 24 * HOUR_MS).toISOString(),
    sparkline: riskSparkline(profile),
    addedAt: new Date().toISOString(),
  };
  await store.addWatchlist(item);
  await audit('ADD_TO_WATCHLIST', entityKey, `Added ${entityKey} to watchlist: ${reason}`);
  res.json({ success: true, item });
}));

app.delete('/api/watchlist/:id', asyncRoute(async (req, res) => {
  await store.removeWatchlist(req.params.id);
  await audit('REMOVE_FROM_WATCHLIST', req.params.id, `Removed watchlist item ${req.params.id}`);
  res.json({ success: true });
}));

// ----------------- API: graph (FR-04, FR-06) -----------------
// ----------------- API: graph from an analyst's log search -----------------
const searchKey = (query: string) => `search:${crypto.createHash('sha1').update(query).digest('hex').slice(0, 12)}`;

// Demo mode: search the demo graphs' entities, edges and command lines for every query term
function buildDemoSearchProfile(query: string, t0Ms: number): UserProfile {
  const terms = query
    .split(/\s+(?:AND|&&)\s+|\s+/i)
    .map(t => t.replace(/^[\w.]+:/, '').replace(/^["'(]+|["')]+$/g, '').toLowerCase())
    .filter(t => t && !['and', 'or', 'not', '*'].includes(t));
  const rootId = opaqueId('query', `query:${query.toLowerCase()}`);
  const nodes = new Map<string, SecurityNode>();
  const edges: SecurityEdge[] = [];
  const milestones: SecurityMilestone[] = [];
  const factors: ContributingFactor[] = [];
  let riskScore = 0;
  const demoHours = 48;
  nodes.set(rootId, {
    id: rootId, name: `Search: ${query.slice(0, 60)}`, type: 'query', riskScore: 0, riskBand: 'LOW', compromised: false,
    classification: 'Log search', firstSeenHour: demoHours, firstSeen: new Date(t0Ms - demoHours * HOUR_MS).toISOString(), details: { Query: query },
  });
  for (const key of Object.keys(DEMO_USERS)) {
    const p = demoProfileSync(key, t0Ms);
    const byId = new Map(p.nodes.map(n => [n.id, n]));
    const text = (n?: SecurityNode) => (n ? [n.name, n.classification || '', ...Object.values(n.details || {}), ...(n.executions || []).map(x => x.commandLine)].join(' ') : '');
    const hits = p.edges.filter(e => {
      const hay = `${e.type} ${e.protocol} ${e.details} ${text(byId.get(e.source))} ${text(byId.get(e.target))}`.toLowerCase();
      return terms.length === 0 || terms.every(t => hay.includes(t));
    });
    if (!hits.length) continue;
    const root = byId.get(p.rootId!)!;
    for (const e of hits) {
      for (const id of [e.source, e.target]) if (!nodes.has(id)) nodes.set(id, byId.get(id)!);
      edges.push(e);
    }
    if (!nodes.has(root.id)) nodes.set(root.id, root);
    const firstHour = Math.max(...hits.map(e => e.hour));
    edges.push({
      id: `m_${root.id}`, source: rootId, target: root.id, action: 'MATCHED', type: 'MATCHED', protocol: 'Search match', hour: firstHour,
      firstSeen: new Date(t0Ms - firstHour * HOUR_MS).toISOString(), eventCount: hits.reduce((n, e) => n + e.eventCount, 0), status: 'allowed',
      details: `${hits.length} matching edge(s) for ${root.name}`,
    });
    const hitIds = new Set(hits.map(e => e.id));
    factors.push(...p.contributingFactors.filter(f => (f.edgeIds || []).some(id => hitIds.has(id))).map(f => ({ ...f, description: `${root.name}: ${f.description}` })));
    milestones.push(...p.milestones.filter(m => !m.edgeId || hitIds.has(m.edgeId)));
    riskScore = Math.max(riskScore, p.riskScore);
  }
  if (edges.length === 0) throw new HttpError(404, `No demo events match "${query}". Try a host, user, process or domain name, e.g. powershell or THINKPAD-MR-20.`);
  const band = riskScore >= 70 ? 'HIGH' : riskScore >= 40 ? 'MEDIUM' : 'LOW';
  return {
    id: rootId, canonicalId: rootId.toUpperCase(), username: `search`, fullName: `Log search: ${query}`, role: 'Log search', department: '-',
    baselineLocation: '-', device: '-', riskScore, riskBand: band, alertSummary: factors.slice(0, 3).map(f => f.indicator).join(' · ') || 'No risk indicators in the results',
    triggerEvent: 'Analyst log search', aliases: [], nodes: Array.from(nodes.values()), edges: edges.sort((a, b) => b.hour - a.hour), milestones: milestones.sort((a, b) => b.hour - a.hour), contributingFactors: factors,
    dataSource: 'demo', t0: new Date(t0Ms).toISOString(), windowHours: demoHours, windowStart: new Date(t0Ms - demoHours * HOUR_MS).toISOString(),
    totalEventCount: edges.reduce((n, e) => n + e.eventCount, 0), rootId, kind: 'search', query,
    notes: ['DEMO DATA: search runs over the fictional demo graphs.', 'Search graph: every matching identity is shown.'],
  };
}

async function getSearchProfile(query: string, windowHours: number, t0Ms: number, force = false): Promise<{ profile: UserProfile; buildMs: number; cached: boolean }> {
  const key = cacheKey(searchKey(query), windowHours, t0Ms);
  const hit = profileCache.get(key);
  if (!force && hit && Date.now() - hit.builtAt < CACHE_TTL_MS) return { profile: hit.profile, buildMs: 0, cached: true };
  const started = Date.now();
  let profile: UserProfile;
  if (DATA_SOURCE === 'demo') {
    profile = buildDemoSearchProfile(query, t0Ms);
  } else {
    const src = SOURCE!;
    const start = t0Ms - windowHours * HOUR_MS;
    const limit = Math.min(src.maxEvents, 10000);
    const events = await src.searchEvents(query, start, t0Ms, limit);
    if (!events.length) throw new HttpError(404, `No ${src.label} events match "${query}" between ${new Date(start).toISOString()} and ${new Date(t0Ms).toISOString()}.`);
    const config = await store.getConfig();
    profile = buildProfile({
      username: 'search', events, alerts: [], t0Ms, windowHours, baseline: null, crownJewelTags: config.crownJewelTags,
      vipEntities: config.vipEntities, riskWeights: config.riskWeights, dataSource: src.kind, sourceLabel: src.label, searchMode: true, query,
    });
    if (events.length >= limit) profile.notes?.push(`The search returned the maximum of ${limit} events; narrow the query or the time range to see everything.`);
  }
  const buildMs = Date.now() - started;
  profileCache.set(key, { profile, builtAt: Date.now() });
  return { profile, buildMs, cached: false };
}

app.get('/api/graph/search', asyncRoute(async (req, res) => {
  const query = String(req.query.q || '').trim().slice(0, 2000);
  if (!query) throw new HttpError(400, 'q (the search query) is required');
  const { windowHours, t0Ms } = parseWindow(req);
  const { profile, buildMs, cached } = await getSearchProfile(query, windowHours, t0Ms, req.query.refresh === '1');
  const withNotes = await withAnnotations(searchKey(query), profile);
  await audit('VIEW_SEARCH_GRAPH', searchKey(query), `Search graph for "${query.slice(0, 120)}" (${profile.nodes.length} nodes, ${profile.edges.length} edges${cached ? ', cached' : ''})`);
  res.json({ profile: withNotes, investigationKey: searchKey(query), windowHours: profile.windowHours, buildMs, cached });
}));

app.get('/api/graph/:userId', asyncRoute(async (req, res) => {
  const entityKey = entityKeyOf(req.params.userId);
  const { windowHours, t0Ms } = parseWindow(req);
  const force = req.query.refresh === '1';
  const { profile, buildMs, cached } = await getProfile(entityKey, windowHours, t0Ms, force);
  await audit('VIEW_SUBGRAPH', entityKey, `Viewed ${profile.windowHours}h subgraph (${profile.nodes.length} nodes, ${profile.edges.length} edges, source ${profile.dataSource}${cached ? ', cached' : ''})`);
  res.json({ profile, windowHours: profile.windowHours, buildMs, cached });
}));

app.post('/api/graph/expand', asyncRoute(async (req, res) => {
  const searchQuery = typeof req.body.searchQuery === 'string' ? req.body.searchQuery.trim() : '';
  const entityKey = searchQuery ? searchKey(searchQuery) : entityKeyOf(req.body.userKey);
  const nodeId = String(req.body.nodeId || '');
  const { windowHours, t0Ms } = parseWindow(req);
  const { profile } = searchQuery ? await getSearchProfile(searchQuery, windowHours, t0Ms) : await getProfile(entityKey, windowHours, t0Ms);
  const node = profile.nodes.find(n => n.id === nodeId);
  if (!node) throw new HttpError(404, `Node ${nodeId} is not in the current graph`);

  if (DATA_SOURCE === 'demo') {
    return res.json({ nodes: [], edges: [], message: 'Demo mode: 1-hop expansion needs a live data source (DATA_SOURCE=splunk or elastic).' });
  }
  if (!['host', 'ip', 'domain'].includes(node.type)) {
    return res.json({ nodes: [], edges: [], message: `Expansion is supported for host, IP and domain nodes (this is a ${node.type}).` });
  }

  const hours = profile.windowHours ?? windowHours;
  const t0 = Date.parse(profile.t0 || '') || t0Ms;
  const events = (await SOURCE!.fetchEntityEvents(node.name, t0 - hours * HOUR_MS, t0)).filter(e => e.user && e.user !== entityKey);
  const hourOf = (ms: number) => Math.max(0, Math.min(hours, Math.ceil((t0 - ms) / HOUR_MS)));
  const existing = new Set(profile.nodes.map(n => n.id));
  const newNodes = new Map<string, SecurityNode>();
  const newEdges = new Map<string, SecurityEdge>();
  for (const ev of events) {
    const uid = opaqueId('user', `user:${ev.user}`);
    if (!existing.has(uid) && !newNodes.has(uid)) {
      newNodes.set(uid, {
        id: uid, name: ev.user!, type: 'user', riskScore: 10, riskBand: 'LOW', compromised: false,
        classification: `Also active on ${node.name}`, firstSeenHour: hourOf(ev.tsMs), firstSeen: ev.ts, details: { PivotedFrom: node.name },
      });
    }
    const type = ev.category === 'auth' ? (ev.outcome === 'failure' ? 'AUTH_FAIL' : 'AUTH_SUCCESS') : 'CONNECTED_TO';
    const eid = `x_${crypto.createHash('sha1').update(`${uid}|${type}|${node.id}`).digest('hex').slice(0, 8)}`;
    const e = newEdges.get(eid);
    if (e) {
      e.eventCount++;
      e.hour = Math.max(e.hour, hourOf(ev.tsMs));
    } else {
      newEdges.set(eid, {
        id: eid, source: uid, target: node.id, action: type, type, protocol: ev.sourcetype, hour: hourOf(ev.tsMs),
        firstSeen: ev.ts, eventCount: 1, status: type === 'AUTH_FAIL' ? 'blocked' : 'allowed',
        details: `${ev.user} ${type} ${node.name} (1-hop expansion)`, eventIds: [ev.id],
      });
    }
    if (newNodes.size >= 50) break;
  }
  await audit('EXPAND_NODE', entityKey, `Expanded ${node.type} ${node.name}: ${newNodes.size} related identities`);
  res.json({ nodes: Array.from(newNodes.values()), edges: Array.from(newEdges.values()).filter(e => newNodes.has(e.source) || existing.has(e.source)) });
}));

// ----------------- API: annotations (FR-08) & feedback (FR-23) -----------------
app.post('/api/annotations', asyncRoute(async (req, res) => {
  const entityKey = investigationKeyOf(req.body.entityKey);
  const nodeId = String(req.body.nodeId || '').slice(0, 64);
  const text = String(req.body.text || '').slice(0, 2000);
  if (!nodeId) throw new HttpError(400, 'nodeId is required');
  await store.upsertAnnotation({ entityKey, nodeId, text, analyst: ANALYST, updatedAt: new Date().toISOString() });
  await audit('ANNOTATE_NODE', entityKey, `${text ? 'Set' : 'Cleared'} annotation on ${nodeId}`);
  // Every saved hypothesis is also kept in the investigation notes (the annotation shows only the latest)
  const note = text.trim()
    ? await addNote({ entityKey, nodeId, nodeName: req.body.nodeName ? clipText(req.body.nodeName, 300) : undefined, caseId: req.body.caseId ? clipText(req.body.caseId, 64) : undefined, kind: 'HYPOTHESIS', text: text.trim() })
    : null;
  res.json({ success: true, note });
}));

app.post('/api/feedback', asyncRoute(async (req, res) => {
  const verdict = String(req.body.verdict || '');
  if (!['BENIGN', 'MALICIOUS'].includes(verdict)) throw new HttpError(400, 'verdict must be BENIGN or MALICIOUS');
  const targetId = clipText(req.body.targetId, 64);
  if (!targetId) throw new HttpError(400, 'targetId is required');
  const reason = clipText(req.body.note, 2000).trim();
  if (!reason) throw new HttpError(400, 'A reason is required for a verdict');
  const nodeName = clipText(req.body.nodeName || targetId, 300);
  const note = await addNote({
    entityKey: investigationKeyOf(req.body.entityKey),
    caseId: req.body.caseId ? clipText(req.body.caseId, 64) : undefined,
    nodeId: targetId,
    nodeName,
    kind: 'VERDICT',
    verdict: verdict as 'BENIGN' | 'MALICIOUS',
    text: reason,
  });
  await audit('SET_VERDICT', note.entityKey, `Analyst marked ${nodeName} (${targetId}) as ${verdict}: ${reason.slice(0, 300)}`);
  res.json({ success: true, note, message: 'Verdict saved to the investigation notes and the audit log. (Suppression and baseline tuning from feedback are not implemented yet.)' });
}));

// ----------------- Investigation notes -----------------
async function addNote(n: Omit<InvestigationNote, 'id' | 'createdAt' | 'analyst'>): Promise<InvestigationNote> {
  const note: InvestigationNote = { ...n, id: newId('note'), analyst: ANALYST, createdAt: new Date().toISOString() };
  await store.addNote(note);
  return note;
}

const clipText = (v: unknown, n: number) => String(v ?? '').slice(0, n);

app.get('/api/notes', asyncRoute(async (req, res) => {
  const entityKey = req.query.entityKey ? String(req.query.entityKey).slice(0, 300) : undefined;
  const caseId = req.query.caseId ? String(req.query.caseId).slice(0, 64) : undefined;
  if (!entityKey && !caseId) throw new HttpError(400, 'entityKey or caseId is required');
  res.json({ notes: await store.listNotes({ entityKey, caseId }) });
}));

app.post('/api/notes', asyncRoute(async (req, res) => {
  const kind: NoteKind = req.body.kind === 'HYPOTHESIS' ? 'HYPOTHESIS' : 'NOTE';
  const text = clipText(req.body.text, 4000).trim();
  if (!text) throw new HttpError(400, 'text is required');
  const note = await addNote({
    entityKey: investigationKeyOf(req.body.entityKey),
    caseId: req.body.caseId ? clipText(req.body.caseId, 64) : undefined,
    nodeId: req.body.nodeId ? clipText(req.body.nodeId, 64) : undefined,
    nodeName: req.body.nodeName ? clipText(req.body.nodeName, 300) : undefined,
    kind,
    text,
  });
  await audit(`ADD_${kind}`, note.entityKey, `${kind === 'HYPOTHESIS' ? 'Hypothesis' : 'Note'}${note.nodeName ? ` on ${note.nodeName}` : ''}: ${text.slice(0, 200)}`);
  res.json({ success: true, note });
}));

// ----------------- API: cases (FR-19, FR-20) -----------------
app.get('/api/cases', asyncRoute(async (_req, res) => {
  res.json({ cases: await store.listCases() });
}));

app.get('/api/cases/:id', asyncRoute(async (req, res) => {
  const c = await store.getCase(req.params.id);
  if (!c) throw new HttpError(404, 'Case not found');
  res.json({ case: c.record, snapshot: c.snapshot });
}));

app.post('/api/cases', asyncRoute(async (req, res) => {
  const entityKey = investigationKeyOf(req.body.entityKey || req.body.userKey);
  const clientProfile = req.body.profile as UserProfile | undefined;
  const snapshot: UserProfile | null = clientProfile && Array.isArray(clientProfile.nodes) ? clientProfile : latestCachedProfile(entityKey);
  if (!snapshot) throw new HttpError(400, 'No graph loaded for this entity; open it before saving a case.');
  const snapshotJson = JSON.stringify(snapshot);
  const record: CaseRecord = {
    id: newId('case'),
    caseRef: `INC-${crypto.randomInt(10000, 99999)}`,
    title: String(req.body.title || `${snapshot.triggerEvent} - ${snapshot.username}`).slice(0, 200),
    rootEntity: `${snapshot.username} (${snapshot.id})`,
    entityKey,
    analyst: ANALYST,
    status: 'INVESTIGATING',
    severity: ['P1', 'P2', 'P3'].includes(req.body.severity) ? req.body.severity : snapshot.riskBand === 'HIGH' ? 'P1' : snapshot.riskBand === 'MEDIUM' ? 'P2' : 'P3',
    windowHours: snapshot.windowHours ?? 48,
    nodeCount: snapshot.nodes.length,
    compromisedCount: snapshot.nodes.filter(n => n.compromised).length,
    sha256: sha256(snapshotJson),
    createdAt: new Date().toISOString(),
    notes: String(req.body.notes || '').slice(0, 2000) || undefined,
    verdict: snapshot.riskBand === 'HIGH' ? 'SUSPICIOUS' : undefined,
    pushedTo: [],
    evidence: [],
    dataSource: snapshot.dataSource,
    hasSnapshot: true,
  };
  await store.createCase(record, snapshot);
  await audit('CREATE_CASE', entityKey, `Saved case ${record.caseRef}; graph snapshot SHA-256 ${record.sha256}`, record.sha256);
  res.json({ success: true, case: record });
}));

const DISPOSITIONS: Disposition[] = ['TRUE_POSITIVE_MALICIOUS', 'TRUE_POSITIVE_BENIGN', 'FALSE_POSITIVE', 'INCONCLUSIVE', 'DUPLICATE'];
const DISPOSITION_LABEL: Record<Disposition, string> = {
  TRUE_POSITIVE_MALICIOUS: 'True positive (malicious)', TRUE_POSITIVE_BENIGN: 'True positive (authorized / benign)',
  FALSE_POSITIVE: 'False positive', INCONCLUSIVE: 'Inconclusive', DUPLICATE: 'Duplicate',
};

// Assign, change status, and close (with disposition and closure notes). Each change is recorded as a note.
app.patch('/api/cases/:id', asyncRoute(async (req, res) => {
  const existing = await store.getCase(req.params.id);
  if (!existing) throw new HttpError(404, 'Case not found');
  const before = existing.record;
  const patch: Partial<CaseRecord> = {};
  if (['OPEN', 'INVESTIGATING', 'CONTAINED', 'CLOSED'].includes(req.body.status)) patch.status = req.body.status;
  if (['BENIGN', 'SUSPICIOUS', 'MALICIOUS'].includes(req.body.verdict)) patch.verdict = req.body.verdict;
  if (typeof req.body.notes === 'string') patch.notes = req.body.notes.slice(0, 2000);
  if (typeof req.body.assignee === 'string') {
    const a = req.body.assignee.trim().slice(0, 100);
    if (!/^[\w.@ -]{1,100}$/.test(a)) throw new HttpError(400, 'assignee must be a name or email');
    patch.assignee = a;
  }
  if (req.body.disposition !== undefined) {
    if (!DISPOSITIONS.includes(req.body.disposition)) throw new HttpError(400, `disposition must be one of ${DISPOSITIONS.join(', ')}`);
    patch.disposition = req.body.disposition;
  }
  if (typeof req.body.closureNotes === 'string') patch.closureNotes = req.body.closureNotes.trim().slice(0, 4000);

  const closing = patch.status === 'CLOSED' && before.status !== 'CLOSED';
  const reopening = patch.status && patch.status !== 'CLOSED' && before.status === 'CLOSED';
  if (closing) {
    if (!(patch.disposition || before.disposition)) throw new HttpError(400, 'Choose a disposition to close the investigation');
    if (!(patch.closureNotes || '').trim()) throw new HttpError(400, 'Closure notes are required to close the investigation');
    patch.closedAt = new Date().toISOString();
    patch.closedBy = ANALYST;
    if (!patch.verdict) {
      const d = patch.disposition || before.disposition;
      patch.verdict = d === 'TRUE_POSITIVE_MALICIOUS' ? 'MALICIOUS' : d === 'INCONCLUSIVE' ? 'SUSPICIOUS' : 'BENIGN';
    }
  }
  if (reopening) { patch.closedAt = ''; patch.closedBy = ''; }

  const updated = await store.updateCase(req.params.id, patch);
  if (!updated) throw new HttpError(404, 'Case not found');
  const entityKey = updated.entityKey || updated.rootEntity;
  const notes: InvestigationNote[] = [];
  if (patch.assignee && patch.assignee !== before.assignee) {
    notes.push(await addNote({ entityKey, caseId: updated.id, kind: 'ASSIGNMENT', text: `Assigned ${updated.caseRef} to ${patch.assignee}${before.assignee ? ` (was ${before.assignee})` : ''}.` }));
  }
  if (closing) {
    notes.push(await addNote({ entityKey, caseId: updated.id, kind: 'CLOSURE', text: `Closed ${updated.caseRef} as ${DISPOSITION_LABEL[updated.disposition!]}. ${updated.closureNotes}` }));
  } else if (reopening) {
    notes.push(await addNote({ entityKey, caseId: updated.id, kind: 'NOTE', text: `Reopened ${updated.caseRef} (status ${updated.status}).` }));
  } else if (patch.status && patch.status !== before.status) {
    notes.push(await addNote({ entityKey, caseId: updated.id, kind: 'NOTE', text: `Status changed from ${before.status} to ${patch.status}.` }));
  }
  await audit(closing ? 'CLOSE_CASE' : 'UPDATE_CASE', updated.caseRef, closing
    ? `Closed as ${updated.disposition} by ${ANALYST}; assignee ${updated.assignee || '-'}`
    : `Updated ${Object.keys(patch).join(', ') || 'nothing'}`);
  res.json({ success: true, case: updated, notes });
}));

// Freeze an approved AI storyline into the case (the analyst's approval makes it case content)
app.post('/api/cases/:id/storyline', asyncRoute(async (req, res) => {
  const s = req.body.storyline as Storyline | undefined;
  if (!s || !Array.isArray(s.phases) || typeof s.sha256 !== 'string') throw new HttpError(400, 'storyline is required');
  if (storylineHash(s) !== s.sha256) throw new HttpError(400, 'Storyline content does not match its hash; regenerate it before approving');
  const c = await store.getCase(req.params.id);
  if (!c) throw new HttpError(404, 'Case not found');
  const approved: Storyline = { ...s, approvedBy: ANALYST, approvedAt: new Date().toISOString() };
  const updated = await store.updateCase(req.params.id, { storyline: approved });
  const note = await addNote({
    entityKey: c.record.entityKey || c.record.rootEntity, caseId: c.record.id, kind: 'AI_STORYLINE',
    text: `Approved storyline (${s.engine}): ${s.headline}. ${s.phases.map(p => p.name).join(' → ')}`.slice(0, 2000),
  });
  await audit('APPROVE_AI_STORYLINE', c.record.caseRef, `${s.engine}; ${s.phases.length} phase(s), ${s.droppedSteps} uncited step(s) dropped`, s.sha256);
  res.json({ success: true, case: updated, note });
}));

// Register an evidence file (hash computed in the browser) against a case
app.post('/api/cases/:id/evidence', asyncRoute(async (req, res) => {
  const hash = String(req.body.sha256 || '').toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(hash)) throw new HttpError(400, 'sha256 must be 64 hex characters');
  const kind = ['REPLAY_VIDEO', 'GRAPH_PNG', 'SNAPSHOT'].includes(req.body.kind) ? req.body.kind : 'REPLAY_VIDEO';
  const evidence: EvidenceRecord = {
    kind,
    fileName: String(req.body.fileName || 'evidence').slice(0, 200),
    mimeType: String(req.body.mimeType || 'application/octet-stream').slice(0, 100),
    sizeBytes: Math.max(0, Number(req.body.sizeBytes) || 0),
    sha256: hash,
    analyst: ANALYST,
    createdAt: new Date().toISOString(),
  };
  const updated = await store.addEvidence(req.params.id, evidence);
  if (!updated) throw new HttpError(404, 'Case not found');
  await audit(`REGISTER_${kind}`, updated.caseRef, `Registered ${evidence.fileName} (${evidence.mimeType}, ${evidence.sizeBytes} bytes)`, hash);
  res.json({ success: true, case: updated });
}));

// FR-20: ticketing push. No ticketing integration is configured yet, so this records a simulated push only.
app.post('/api/cases/:id/push', asyncRoute(async (req, res) => {
  const target = String(req.body.target || '');
  const labels: Record<string, string> = { jira: 'Jira', slack: 'Slack', servicenow: 'ServiceNow' };
  if (!labels[target]) throw new HttpError(400, 'target must be jira, slack or servicenow');
  const c = await store.getCase(req.params.id);
  if (!c) throw new HttpError(404, 'Case not found');
  const label = `${labels[target]} (simulated)`;
  const pushedTo = Array.from(new Set([...(c.record.pushedTo || []), label]));
  await store.updateCase(req.params.id, { pushedTo });
  await audit(`SIMULATED_PUSH_TO_${target.toUpperCase()}`, c.record.caseRef, `Simulated push to ${labels[target]}: no ${labels[target]} integration is configured, nothing was sent.`);
  res.json({ success: true, simulated: true, pushedTo, message: `${labels[target]} is not connected. Recorded as a simulated push; nothing was sent.` });
}));

// ----------------- API: admin & audit (FR-24, section 12) -----------------
function liveConnectors(): ConnectorConfig[] {
  if (!SOURCE) return [];
  const c = SOURCE.connector;
  return [{
    id: c.id, name: c.name, vendor: c.vendor, category: 'SIEM', type: 'SIEM',
    status: 'CONNECTED', eps: 0, lagMs: 0, lastSync: 'on demand',
    authType: c.authType, endpoint: c.endpoint,
    eventsConsumed: c.eventsConsumed, health: 'Query on demand', alertsBuffered: 0, simulated: false,
  }];
}

app.get('/api/admin/config', asyncRoute(async (_req, res) => {
  const config = await store.getConfig();
  res.json({ config: { ...config, connectors: [...liveConnectors(), ...config.connectors] }, auditLog: await store.listAudit(500) });
}));

const RISK_WEIGHT_KEYS = Object.keys(DEFAULT_ADMIN_CONFIG.riskWeights).concat(['encodedPowerShell']);

function cleanStringList(v: unknown, max = 200): string[] {
  if (!Array.isArray(v)) throw new HttpError(400, 'Expected an array of strings');
  return Array.from(new Set(v.map(x => String(x).trim()).filter(x => x && x.length <= 128))).slice(0, max);
}

app.post('/api/admin/config', asyncRoute(async (req, res) => {
  const current = await store.getConfig();
  const next: AdminConfig = { ...current };
  if (req.body.crownJewelTags !== undefined) next.crownJewelTags = cleanStringList(req.body.crownJewelTags);
  if (req.body.vipEntities !== undefined) next.vipEntities = cleanStringList(req.body.vipEntities);
  if (req.body.retentionWindowHours !== undefined) {
    const h = Number(req.body.retentionWindowHours);
    if (!Number.isInteger(h) || h < 1 || h > 168) throw new HttpError(400, 'retentionWindowHours must be 1-168');
    next.retentionWindowHours = h;
  }
  if (req.body.riskWeights !== undefined) {
    const w: Record<string, number> = { ...current.riskWeights };
    for (const [k, v] of Object.entries(req.body.riskWeights || {})) {
      if (!RISK_WEIGHT_KEYS.includes(k)) throw new HttpError(400, `Unknown risk weight "${k}"`);
      const n = Number(v);
      if (!Number.isFinite(n) || n < 0 || n > 100) throw new HttpError(400, `Risk weight ${k} must be 0-100`);
      w[k] = n;
    }
    next.riskWeights = w;
  }
  await store.setConfig(next);
  profileCache.clear(); // tags and weights change scoring
  await audit('UPDATE_CONFIG', 'admin', `Updated ${Object.keys(req.body).filter(k => k !== 'connectors').join(', ')}`);
  res.json({ success: true, config: { ...next, connectors: [...liveConnectors(), ...next.connectors] } });
}));

// ----------------- API: integrations -----------------
// Inbound SIEM/EDR alert webhook. Set WEBHOOK_SECRET and send it in the X-WatchMe-Secret header.
app.post('/api/integrations/webhook', asyncRoute(async (req, res) => {
  if (WEBHOOK_SECRET) {
    const got = String(req.get('x-watchme-secret') || '');
    const ok = got.length === WEBHOOK_SECRET.length && crypto.timingSafeEqual(Buffer.from(got), Buffer.from(WEBHOOK_SECRET));
    if (!ok) throw new HttpError(401, 'Invalid or missing X-WatchMe-Secret header');
  }
  const entityKey = entityKeyOf(req.body.entity);
  const severity = String(req.body.severity || 'MEDIUM').toUpperCase();
  if (!['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(severity)) throw new HttpError(400, 'severity must be LOW, MEDIUM, HIGH or CRITICAL');
  if (DATA_SOURCE === 'demo' && !DEMO_USERS[entityKey]) throw new HttpError(404, `Unknown demo entity "${entityKey}"`);
  const ts = req.body.timestamp && Number.isFinite(Date.parse(req.body.timestamp)) ? new Date(req.body.timestamp).toISOString() : new Date().toISOString();
  const alert: AlertRecord = {
    id: `ALT-${crypto.randomInt(10000, 99999)}`,
    ts,
    entityKey,
    source: String(req.body.source || 'SIEM').slice(0, 80),
    alertType: String(req.body.alertType || 'Security alert').slice(0, 200),
    severity,
    ttp: Array.isArray(req.body.ttp) ? req.body.ttp.map(String).filter((t: string) => /^T\d{4}(\.\d{3})?$/.test(t)).slice(0, 10) : undefined,
  };
  await store.addAlert(alert);
  invalidateEntity(entityKey);
  await audit('INGEST_ALERT_WEBHOOK', entityKey, `Ingested ${severity} alert "${alert.alertType}" from ${alert.source} (${alert.id})`, undefined, `${alert.source}-webhook`);
  res.json({ success: true, alertId: alert.id, message: `Alert ${alert.id} stored and attached to ${entityKey}'s graph.` });
}));

// Containment actions are SIMULATED: WatchMe v1 does not call EDR / IdP / firewall APIs.
function simulatedContainment(action: string, target: string, tool: string) {
  return {
    success: true,
    simulated: true,
    status: 'SIMULATED',
    tool,
    latencyMs: 0,
    message: `SIMULATED: no request was sent to ${tool}. ${action} for ${target} must be performed in ${tool} directly.`,
  };
}

app.post('/api/integrations/contain/isolate-host', asyncRoute(async (req, res) => {
  const hostId = String(req.body.hostId || '').slice(0, 200);
  const tool = String(req.body.tool || 'EDR').slice(0, 80);
  if (!hostId) throw new HttpError(400, 'hostId is required');
  await audit('SIMULATED_EDR_HOST_ISOLATE', hostId, `Simulated isolation of ${hostId} via ${tool}; no action taken`);
  res.json({ hostId, ...simulatedContainment('Host isolation', hostId, tool) });
}));

app.post('/api/integrations/contain/revoke-user', asyncRoute(async (req, res) => {
  const userId = String(req.body.userId || '').slice(0, 200);
  const tool = String(req.body.tool || 'IdP').slice(0, 80);
  if (!userId) throw new HttpError(400, 'userId is required');
  await audit('SIMULATED_IDP_USER_REVOKE', userId, `Simulated session revocation for ${userId} via ${tool}; no action taken`);
  res.json({ userId, ...simulatedContainment('Session revocation', userId, tool) });
}));

app.post('/api/integrations/contain/block-indicator', asyncRoute(async (req, res) => {
  const indicator = String(req.body.indicator || '').slice(0, 200);
  const tool = String(req.body.tool || 'Firewall').slice(0, 80);
  if (!indicator) throw new HttpError(400, 'indicator is required');
  await audit('SIMULATED_FIREWALL_BLOCK', indicator, `Simulated block of ${indicator} via ${tool}; no action taken`);
  res.json({ indicator, ...simulatedContainment('Blocking', indicator, tool) });
}));

// Query console: real for the configured live source; other engines return clearly-labelled sample rows.
app.post('/api/integrations/query', asyncRoute(async (req, res) => {
  const tool = String(req.body.tool || SOURCE?.kind || 'splunk');
  const query = String(req.body.query || '');
  const { windowHours, t0Ms } = parseWindow(req);

  if (SOURCE && tool === SOURCE.kind) {
    const logs = await SOURCE.runAdhocQuery(query, t0Ms - windowHours * HOUR_MS, t0Ms);
    await audit('RUN_SIEM_QUERY', String(req.body.entityId || '-'), `Ran ${SOURCE.queryLanguage} on ${SOURCE.label} (${logs.length} rows): ${query.slice(0, 120)}`);
    return res.json({ success: true, simulated: false, tool, query, count: logs.length, logs });
  }

  const now = Date.now();
  const logs = [
    { timestamp: new Date(now - 2 * HOUR_MS).toISOString(), source: 'SAMPLE', action: 'Logon', host: 'SAMPLE-HOST-01', ip: '198.51.100.7', details: 'Sample row: no connection to this engine is configured' },
    { timestamp: new Date(now - 5 * HOUR_MS).toISOString(), source: 'SAMPLE', action: 'ProcessCreate', host: 'SAMPLE-HOST-01', ip: '198.51.100.7', details: 'Sample row: no connection to this engine is configured' },
  ];
  await audit('RUN_SIMULATED_QUERY', String(req.body.entityId || '-'), `Simulated ${tool} query (no connector configured)`);
  res.json({
    success: true, simulated: true, tool, query, count: logs.length, logs,
    message: `${tool} is not connected${SOURCE ? ` (the live source is ${SOURCE.label})` : ''}. Showing sample rows.`,
  });
}));

app.post('/api/integrations/connectors', asyncRoute(async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 100);
  if (!name) throw new HttpError(400, 'name is required');
  const config = await store.getConfig();
  const conn: ConnectorConfig = {
    id: newId('conn'), name, vendor: String(req.body.vendor || '').slice(0, 100), category: String(req.body.category || 'SIEM'),
    type: String(req.body.category || 'SIEM'), status: 'NOT CONNECTED', eps: 0, lagMs: 0, lastSync: 'never',
    authType: String(req.body.authType || '').slice(0, 100), endpoint: String(req.body.endpoint || '').slice(0, 300),
    eventsConsumed: '-', health: 'Placeholder: no adapter for this connector yet', alertsBuffered: 0, simulated: true,
  };
  config.connectors.push(conn);
  await store.setConfig(config);
  await audit('ADD_CONNECTOR', conn.name, `Added placeholder connector ${conn.name} (${conn.category})`);
  res.json({ success: true, connector: conn });
}));

app.delete('/api/integrations/connectors/:id', asyncRoute(async (req, res) => {
  const config = await store.getConfig();
  config.connectors = config.connectors.filter(c => c.id !== req.params.id);
  await store.setConfig(config);
  await audit('REMOVE_CONNECTOR', req.params.id, `Removed connector ${req.params.id}`);
  res.json({ success: true });
}));

app.post('/api/integrations/test/:connectorId', asyncRoute(async (req, res) => {
  if (req.params.connectorId === 'conn-live' && SOURCE) {
    const r = await SOURCE.testConnection();
    await audit('TEST_CONNECTOR', SOURCE.connector.name, `${r.ok ? 'OK' : 'FAILED'}: ${r.message}`);
    return res.json({ success: r.ok, simulated: false, latencyMs: r.latencyMs, message: r.message, error: r.ok ? undefined : r.message });
  }
  res.json({ success: false, simulated: true, error: 'Simulated connector: there is no real connection to test. Only the live connector can be tested.' });
}));

// Re-query the data source for the current entity
app.post('/api/integrations/sync-entity', asyncRoute(async (req, res) => {
  const entityKey = entityKeyOf(req.body.entityId);
  const { windowHours, t0Ms } = parseWindow(req);
  invalidateEntity(entityKey);
  const { profile, buildMs } = await getProfile(entityKey, windowHours, t0Ms, true);
  await audit('SYNC_ENTITY', entityKey, `Rebuilt graph from ${profile.dataSource} (${profile.totalEventCount ?? 0} events, ${buildMs} ms)`);
  res.json({
    success: true,
    syncedEventsCount: profile.totalEventCount ?? 0,
    buildMs,
    message: profile.dataSource === 'demo' ? 'Demo mode: graph reloaded from the demo dataset.' : `Pulled ${profile.totalEventCount} events from ${SOURCE?.label} in ${buildMs} ms.`,
  });
}));

// Detection rule export (section 2): generated from the current graph, not from fixed demo names.
app.get('/api/detection/export-rule/:userKey', asyncRoute(async (req, res) => {
  const entityKey = entityKeyOf(req.params.userKey);
  const { windowHours, t0Ms } = parseWindow(req);
  const { profile } = await getProfile(entityKey, windowHours, t0Ms);
  const byId = new Map(profile.nodes.map(n => [n.id, n]));
  const interesting = profile.edges
    .filter(e => ['AUTH_SUCCESS', 'ACCESSED'].includes(e.type) && (e.status === 'critical' || e.status === 'anomalous'))
    .map(e => byId.get(e.target)?.name)
    .filter((x): x is string => !!x && !/[" \\]/.test(x));
  const targets = Array.from(new Set(interesting)).slice(0, 10);
  const user = profile.username.replace(/[^A-Za-z0-9._-]/g, '');
  const ruleName = `watchme_${user.replace(/[^a-z0-9]/gi, '_').toLowerCase()}_suspicious_access`;
  const regex = targets.length ? targets.map(t => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|') : '.*';
  const ttps = Array.from(new Set(profile.contributingFactors.map(f => f.mitreTactic).filter(t => /^T\d/.test(t))));

  const yaraL = `rule ${ruleName} {
  meta:
    author = "WatchMe (generated from graph; review before deploying)"
    description = "Failed logons followed by access to hosts first seen for ${user}"
    mitre_attack = "${ttps.join(', ') || 'n/a'}"
    severity = "${profile.riskBand}"

  events:
    $fail.metadata.event_type = "USER_LOGIN"
    $fail.security_result.action = "BLOCK"
    $fail.target.user.userid = $user

    $access.metadata.event_type = "USER_LOGIN"
    $access.security_result.action = "ALLOW"
    $access.target.user.userid = $user
    $access.target.hostname = /${regex}/ nocase

  match:
    $user over 48h

  condition:
    #fail >= 5 and $access
}`;

  const kql = `// Sentinel KQL (generated from the WatchMe graph; review before deploying)
let timeframe = 48h;
let targets = dynamic([${targets.map(t => `"${t}"`).join(', ')}]);
let failures = SecurityEvent
| where TimeGenerated >= ago(timeframe) and EventID == 4625
| summarize FailedCount = count(), LastFail = max(TimeGenerated) by TargetAccount = tolower(TargetUserName)
| where FailedCount >= 5;
SecurityEvent
| where TimeGenerated >= ago(timeframe) and EventID == 4624 and LogonType in (3, 10)
| where array_length(targets) == 0 or Computer in~ (targets)
| extend TargetAccount = tolower(TargetUserName)
| join kind=inner failures on TargetAccount
| where TimeGenerated > LastFail
| project TimeGenerated, TargetAccount, Computer, IpAddress, LogonType, FailedCount`;

  res.json({ yaraL, kql, basedOn: { user, targets, ttps } });
}));

// ----------------- API: AI case summary (FR-17, FR-18, section 7) -----------------
const SYSTEM_INSTRUCTION = `You are an incident response analyst writing a case summary for a SOC ticket.
You receive a sanitized graph of one identity's activity. Entity names are replaced by tokens such as USER_1 or HOST_3.
Keep the tokens exactly as given. Do not invent facts, hosts, numbers, or techniques that are not in the input.

Rules:
1. Every bullet in the Timeline and Blast Radius sections must cite at least one edge or node id in brackets, e.g. [e4] or [host_1a2b3c4d]. Use only ids present in the input.
2. Use this exact structure:

# WATCHME CASE SUMMARY: <short headline>
### 1. Headline
One sentence: what happened and to whom, with the risk band.
### 2. Timeline
5-10 bullets in chronological order, each with citations.
### 3. Blast Radius
Hosts, apps, and data touched; call out crown jewels. Cite ids.
### 4. ATT&CK Mapping
Techniques that appear in the input, with ids.
### 5. Assessment
Likely benign / suspicious / likely malicious, with the facts behind it.
### 6. Recommended Next Steps
Numbered containment and validation steps.`;

app.post('/api/gemini/case-summary', asyncRoute(async (req, res) => {
  const profile = req.body.profile as UserProfile | undefined;
  if (!profile || !Array.isArray(profile.nodes) || !Array.isArray(profile.edges)) throw new HttpError(400, 'profile with nodes and edges is required');
  const privacyMode = req.body.privacyModeEnabled !== false;
  const ctx = tokenizeProfile(profile, privacyMode);

  let summary = '';
  let engine = 'Deterministic summary (no AI model configured)';
  let sentToModel = false;
  let modelError: string | undefined;

  if (ai) {
    try {
      summary = await ai.generate(SYSTEM_INSTRUCTION, `Write the case summary for this sanitized graph context:\n\n${JSON.stringify(ctx.payload, null, 2)}`, { temperature: 0.2 });
      sentToModel = true;
      engine = `${aiLabel()} (${privacyMode ? 'tokenized context' : 'PASSTHROUGH: real names sent'})`;
    } catch (err: any) {
      modelError = err.message || String(err);
      console.warn('AI summary failed, using deterministic summary:', modelError);
    }
  }
  if (!summary) {
    summary = deterministicSummary(profile, typeof req.body.tz === 'string' ? req.body.tz.slice(0, 64) : undefined);
    if (modelError) engine = `Deterministic summary (AI call failed: ${modelError})`;
  } else if (privacyMode) {
    summary = rehydrate(summary, ctx.nameByToken);
  }

  const citationAudit = auditCitations(summary, profile);
  await audit('GENERATE_AI_SUMMARY', profile.username, `${engine}; ${citationAudit.validCitations}/${citationAudit.totalCitations} citations valid, ${citationAudit.uncitedLines} uncited line(s)`, sha256(summary));
  res.json({
    summary,
    engine,
    sentToModel,
    privacyMode,
    sanitizedContext: ctx.payload,
    citationAudit,
    timestamp: new Date().toISOString(),
  });
}));

app.post('/api/ai/approve', asyncRoute(async (req, res) => {
  const entity = String(req.body.entityKey || '-').slice(0, 128);
  const hash = String(req.body.summarySha256 || '').slice(0, 64);
  await audit('APPROVE_AI_SUMMARY', entity, 'Analyst approved AI summary for handover', /^[a-f0-9]{64}$/.test(hash) ? hash : undefined);
  res.json({ success: true });
}));

// AI Storyline (interpretation of the Attack Path; deterministic when no AI provider is configured)
app.post('/api/ai/storyline', asyncRoute(async (req, res) => {
  const profile = req.body.profile as UserProfile | undefined;
  if (!profile || !Array.isArray(profile.nodes) || !Array.isArray(profile.edges)) throw new HttpError(400, 'profile with nodes and edges is required');
  const privacyMode = req.body.privacyModeEnabled !== false;
  const { storyline, sentPayload } = await generateStoryline(profile, ai, privacyMode);
  await audit('GENERATE_AI_STORYLINE', profile.username, `${storyline.engine}; verdict ${storyline.verdict}; ${storyline.phases.length} phase(s); ${storyline.droppedSteps} uncited step(s) dropped${storyline.injectionWarnings.length ? `; ${storyline.injectionWarnings.length} injection warning(s)` : ''}`, storyline.sha256);
  res.json({ storyline, sentPayload });
}));

// Unknown API routes return JSON 404s instead of falling through to the SPA
app.use('/api', (_req, res) => { res.status(404).json({ error: 'Not found' }); });

// Error handler
app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
  const status = err instanceof HttpError ? err.status : 500;
  if (status >= 500) console.error(err);
  res.status(status).json({ error: err.message || 'Internal error' });
});

// ----------------- Static assets & start -----------------
async function startServer() {
  const seedDemo = DATA_SOURCE === 'demo';
  await store.init({
    watchlist: seedDemo ? DEMO_WATCHLIST : [],
    cases: seedDemo ? DEMO_CASES : [],
    audit: seedDemo ? DEMO_AUDIT : [],
    config: DEFAULT_ADMIN_CONFIG,
  });

  const production = process.env.NODE_ENV === 'production' || process.argv.includes('--production');
  if (!production) {
    const hmrPort = process.env.HMR_PORT ? parseInt(process.env.HMR_PORT, 10) : undefined; // set when running two dev servers
    const vite = await createViteServer({ server: { middlewareMode: true, ...(hmrPort ? { hmr: { port: hmrPort } } : {}) }, appType: 'spa' });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, 'dist')));
    app.get('*', (_req, res) => { res.sendFile(path.join(__dirname, 'dist', 'index.html')); });
  }

  app.listen(PORT, HOST, () => {
    console.log(`WatchMe listening on http://${HOST}:${PORT}`);
    console.log(`  data source: ${DATA_SOURCE}${SOURCE ? ` (${SOURCE.connector.endpoint})` : ''}`);
    console.log(`  storage:     ${store.kind}${store.kind === 'memory' ? ' (cases and audit log are lost on restart; set DATABASE_URL for PostgreSQL)' : ''}`);
    console.log(`  AI:          ${aiLabel()}`);
  });
}

startServer().catch(err => {
  console.error('Failed to start WatchMe:', err);
  process.exit(1);
});
