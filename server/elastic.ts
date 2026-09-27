// Elasticsearch adapter (Winlogbeat / ECS data). Uses the _search API; works with the free Basic license.
import https from 'node:https';
import http from 'node:http';
import { normalizeEcsHits, type EcsDoc, get } from './normalizeEcs';
import type { NormalizedEvent } from './normalize';

export interface ElasticConfig {
  baseUrl: string; // e.g. http://localhost:9200
  username?: string;
  password?: string;
  apiKey?: string; // base64 "id:key" API key; used instead of username/password when set
  verifyTls: boolean;
  index: string; // index pattern(s), e.g. winlogbeat-*
  timeoutMs: number;
  maxEvents: number;
}

export function loadElasticConfig(env = process.env): ElasticConfig | null {
  if (!env.ELASTIC_URL) return null;
  const index = env.ELASTIC_INDEX || 'winlogbeat-*';
  if (!/^[A-Za-z0-9_.*,-]+$/.test(index)) throw new Error(`Invalid ELASTIC_INDEX "${index}"`);
  return {
    baseUrl: env.ELASTIC_URL.replace(/\/+$/, ''),
    username: env.ELASTIC_USERNAME,
    password: env.ELASTIC_PASSWORD,
    apiKey: env.ELASTIC_API_KEY,
    verifyTls: env.ELASTIC_VERIFY_TLS !== 'false',
    index,
    timeoutMs: parseInt(env.ELASTIC_TIMEOUT_MS || '60000', 10),
    maxEvents: parseInt(env.ELASTIC_MAX_EVENTS || '20000', 10),
  };
}

function request(cfg: ElasticConfig, method: string, path: string, body?: unknown): Promise<any> {
  return new Promise((resolve, reject) => {
    const url = new URL(cfg.baseUrl + path);
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (payload) {
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(payload).toString();
    }
    if (cfg.apiKey) headers.Authorization = `ApiKey ${cfg.apiKey}`;
    else if (cfg.username) headers.Authorization = 'Basic ' + Buffer.from(`${cfg.username}:${cfg.password || ''}`).toString('base64');

    const lib = url.protocol === 'https:' ? https : http;
    const req = lib.request(url, { method, headers, rejectUnauthorized: cfg.verifyTls, timeout: cfg.timeoutMs } as https.RequestOptions, res => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', c => (data += c));
      res.on('end', () => {
        let parsed: any = null;
        try { parsed = data ? JSON.parse(data) : null; } catch { /* not JSON */ }
        if (!res.statusCode || res.statusCode >= 400) {
          const reason = parsed?.error?.root_cause?.[0]?.reason || parsed?.error?.reason || data.slice(0, 300);
          reject(new Error(`Elasticsearch HTTP ${res.statusCode}: ${reason}`));
          return;
        }
        resolve(parsed);
      });
    });
    req.on('timeout', () => req.destroy(new Error(`Elasticsearch request timed out after ${cfg.timeoutMs} ms`)));
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

const indexPath = (cfg: ElasticConfig) => `/${encodeURIComponent(cfg.index).replace(/%2C/g, ',').replace(/%2A/g, '*')}`;

const range = (fromMs: number, toMs: number) => ({
  range: { '@timestamp': { gte: new Date(fromMs).toISOString(), lte: new Date(toMs).toISOString() } },
});

// Fields that hold the account an event is about (Winlogbeat security + sysmon modules, plus ECS related.user)
const USER_FIELDS = ['user.name', 'related.user', 'winlog.event_data.TargetUserName', 'winlog.event_data.SubjectUserName', 'user.target.name'];

function userClause(username: string) {
  const bare = username.includes('\\') ? username.split('\\').pop()! : username;
  return {
    bool: {
      should: [
        ...USER_FIELDS.map(f => ({ term: { [f]: { value: bare, case_insensitive: true } } })),
        // Raw Sysmon events (no Winlogbeat ingest pipeline) carry the account as DOMAIN\user
        { wildcard: { 'winlog.event_data.User': { value: `*\\${bare}`, case_insensitive: true } } },
      ],
      minimum_should_match: 1,
    },
  };
}

function isIp(s: string) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(s) || (/^[0-9a-f:]+$/i.test(s) && s.includes(':'));
}

function entityClause(entity: string) {
  if (isIp(entity)) {
    return { bool: { should: ['source.ip', 'destination.ip', 'client.ip', 'server.ip', 'host.ip'].map(f => ({ term: { [f]: entity } })), minimum_should_match: 1 } };
  }
  return {
    bool: {
      should: ['host.name', 'host.hostname', 'winlog.computer_name', 'destination.domain', 'url.domain', 'source.domain'].map(f => ({ term: { [f]: { value: entity, case_insensitive: true } } })),
      minimum_should_match: 1,
    },
  };
}

// Page through results in time order (search_after), up to maxEvents
async function searchAll(cfg: ElasticConfig, query: unknown, limit: number): Promise<{ _id: string; _source: EcsDoc }[]> {
  const out: { _id: string; _source: EcsDoc }[] = [];
  let after: unknown[] | undefined;
  while (out.length < limit) {
    const size = Math.min(5000, limit - out.length);
    const res = await request(cfg, 'POST', `${indexPath(cfg)}/_search?ignore_unavailable=true&allow_no_indices=true`, {
      size,
      query,
      sort: [{ '@timestamp': 'asc' }, { _doc: 'asc' }],
      track_total_hits: false,
      ...(after ? { search_after: after } : {}),
    });
    const hits = res?.hits?.hits || [];
    out.push(...hits);
    if (hits.length < size) break;
    after = hits[hits.length - 1].sort;
  }
  return out;
}

export async function fetchUserEvents(cfg: ElasticConfig, username: string, fromMs: number, toMs: number): Promise<{ events: NormalizedEvent[]; rawCount: number }> {
  const hits = await searchAll(cfg, { bool: { filter: [range(fromMs, toMs), userClause(username)] } }, cfg.maxEvents);
  return { events: normalizeEcsHits(hits), rawCount: hits.length };
}

export async function fetchEntityEvents(cfg: ElasticConfig, entity: string, fromMs: number, toMs: number, limit = 2000): Promise<NormalizedEvent[]> {
  const hits = await searchAll(cfg, { bool: { filter: [range(fromMs, toMs), entityClause(entity)] } }, limit);
  return normalizeEcsHits(hits);
}

// Hosts, IPs and domains the user touched before the window. null = no history (baseline unavailable).
export async function fetchBaseline(cfg: ElasticConfig, username: string, fromMs: number, toMs: number): Promise<Set<string> | null> {
  const fields = ['host.name', 'winlog.computer_name', 'source.ip', 'destination.ip', 'destination.domain', 'url.domain'];
  const res = await request(cfg, 'POST', `${indexPath(cfg)}/_search?ignore_unavailable=true&allow_no_indices=true`, {
    size: 0,
    track_total_hits: true,
    query: { bool: { filter: [range(fromMs, toMs), userClause(username)] } },
    aggs: Object.fromEntries(fields.map((f, i) => [`f${i}`, { terms: { field: f, size: 1000 } }])),
  });
  const total = res?.hits?.total?.value ?? 0;
  if (!total) return null;
  const out = new Set<string>();
  fields.forEach((_, i) => (res.aggregations?.[`f${i}`]?.buckets || []).forEach((b: any) => out.add(String(b.key).toLowerCase())));
  return out;
}

const SYSTEM_ACCOUNTS = /^(system|local service|network service|anonymous logon|dwm-\d+|umfd-\d+|font driver host|window manager|-)$/i;

export async function searchUsers(cfg: ElasticConfig, term: string, fromMs: number, toMs: number): Promise<{ user: string; count: number }[]> {
  const pattern = `*${term.replace(/[*?\\]/g, '')}*`;
  const fields = ['user.name', 'winlog.event_data.TargetUserName'];
  const res = await request(cfg, 'POST', `${indexPath(cfg)}/_search?ignore_unavailable=true&allow_no_indices=true`, {
    size: 0,
    query: {
      bool: {
        filter: [range(fromMs, toMs)],
        should: fields.map(f => ({ wildcard: { [f]: { value: pattern, case_insensitive: true } } })),
        minimum_should_match: 1,
      },
    },
    aggs: Object.fromEntries(fields.map((f, i) => [`u${i}`, { terms: { field: f, size: 20 } }])),
  });
  const counts = new Map<string, number>();
  fields.forEach((_, i) =>
    (res.aggregations?.[`u${i}`]?.buckets || []).forEach((b: any) => {
      const name = String(b.key).split('\\').pop()!.toLowerCase();
      if (!name || name.endsWith('$') || SYSTEM_ACCOUNTS.test(name) || !name.includes(term.toLowerCase())) return;
      counts.set(name, Math.max(counts.get(name) || 0, b.doc_count));
    }),
  );
  return Array.from(counts.entries()).map(([user, count]) => ({ user, count })).sort((a, b) => b.count - a.count).slice(0, 10);
}

// Query console: Lucene query string syntax, e.g.  event.code:4625 AND user.name:epbas
export async function runAdhocQuery(cfg: ElasticConfig, q: string, fromMs: number, toMs: number, limit = 200) {
  const query = q.trim() ? { bool: { filter: [range(fromMs, toMs), { query_string: { query: q.trim() } }] } } : { bool: { filter: [range(fromMs, toMs)] } };
  const res = await request(cfg, 'POST', `${indexPath(cfg)}/_search?ignore_unavailable=true&allow_no_indices=true`, {
    size: limit,
    query,
    sort: [{ '@timestamp': 'desc' }],
  });
  return (res?.hits?.hits || []).map((h: any) => {
    const d = h._source;
    const pick = (...ps: string[]) => { for (const p of ps) { const v = get(d, p); if (v !== undefined && v !== null && v !== '') return Array.isArray(v) ? v.join('|') : String(v); } return ''; };
    return {
      timestamp: pick('@timestamp'),
      source: pick('event.dataset', 'winlog.channel', 'event.module') || '-',
      action: pick('event.code', 'event.action') || '-',
      host: pick('host.name', 'winlog.computer_name') || '-',
      ip: pick('source.ip', 'winlog.event_data.IpAddress') || '-',
      details: [
        ['user', pick('user.name', 'winlog.event_data.TargetUserName')],
        ['logon', pick('winlog.logon.type', 'winlog.event_data.LogonType')],
        ['process', pick('process.command_line', 'process.executable')],
        ['dest', pick('destination.ip', 'destination.domain')],
        ['outcome', pick('event.outcome')],
      ].filter(([, v]) => v).map(([k, v]) => `${k}=${v}`).join(' '),
    };
  });
}

export async function testConnection(cfg: ElasticConfig): Promise<{ ok: boolean; message: string; latencyMs: number }> {
  const started = Date.now();
  try {
    const info = await request(cfg, 'GET', '/');
    const count = await request(cfg, 'GET', `${indexPath(cfg)}/_count?ignore_unavailable=true&allow_no_indices=true`);
    return {
      ok: true,
      message: `Elasticsearch ${info?.version?.number || ''} reachable; ${count?.count ?? 0} documents in ${cfg.index}`,
      latencyMs: Date.now() - started,
    };
  } catch (err: any) {
    return { ok: false, message: err.message || String(err), latencyMs: Date.now() - started };
  }
}
