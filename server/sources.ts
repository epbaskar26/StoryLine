// One interface for every live log source, so the rest of the server does not care which SIEM it talks to.
import type { NormalizedEvent } from './normalize';
import { normalizeRows } from './normalize';
import * as splunk from './splunk';
import * as elastic from './elastic';

export interface AdhocRow {
  timestamp: string;
  source: string;
  action: string;
  host: string;
  ip: string;
  details: string;
}

export interface ConnectorInfo {
  id: string;
  name: string;
  vendor: string;
  authType: string;
  endpoint: string;
  eventsConsumed: string;
}

export interface LogSource {
  kind: 'splunk' | 'elastic';
  label: string; // shown in the UI, e.g. "Splunk" or "Elastic"
  location: string; // e.g. "index botsv3"
  queryLanguage: string; // for the query console
  maxEvents: number;
  connector: ConnectorInfo;
  fetchUserEvents(user: string, fromMs: number, toMs: number): Promise<{ events: NormalizedEvent[]; rawCount: number }>;
  fetchBaseline(user: string, fromMs: number, toMs: number): Promise<Set<string> | null>;
  fetchEntityEvents(entity: string, fromMs: number, toMs: number): Promise<NormalizedEvent[]>;
  fetchHostEvents(hosts: string[], fromMs: number, toMs: number): Promise<NormalizedEvent[]>;
  searchUsers(term: string, fromMs: number, toMs: number): Promise<{ user: string; count: number }[]>;
  runAdhocQuery(query: string, fromMs: number, toMs: number): Promise<AdhocRow[]>;
  searchEvents(query: string, fromMs: number, toMs: number, limit: number): Promise<NormalizedEvent[]>;
  testConnection(): Promise<{ ok: boolean; message: string; latencyMs: number }>;
}

export function splunkSource(cfg: splunk.SplunkConfig): LogSource {
  const s = (ms: number) => ms / 1000;
  return {
    kind: 'splunk',
    label: 'Splunk',
    location: `index ${cfg.index}`,
    queryLanguage: 'SPL',
    maxEvents: cfg.maxEvents,
    connector: {
      id: 'conn-live', name: 'Splunk (live)', vendor: 'Splunk',
      authType: cfg.token ? 'Bearer token' : 'Basic (username/password)',
      endpoint: `${cfg.baseUrl}/services/search/jobs/export`,
      eventsConsumed: `index ${cfg.index}: Windows Security, Sysmon, CIM fields`,
    },
    async fetchUserEvents(user, from, to) {
      const rows = await splunk.fetchUserEvents(cfg, user, s(from), s(to));
      return { events: normalizeRows(rows), rawCount: rows.length };
    },
    fetchBaseline: (user, from, to) => splunk.fetchBaseline(cfg, user, s(from), s(to)),
    async fetchHostEvents(hosts, from, to) { return normalizeRows(await splunk.fetchHostEvents(cfg, hosts, s(from), s(to))); },
    async fetchEntityEvents(entity, from, to) {
      return normalizeRows(await splunk.fetchEntityEvents(cfg, entity, s(from), s(to)));
    },
    searchUsers: (term, from, to) => splunk.searchUsers(cfg, term, s(from), s(to)),
    async runAdhocQuery(query, from, to) {
      const rows = await splunk.runAdhocQuery(cfg, query, s(from), s(to));
      return rows.map(r => {
        const g = (k: string) => { const v = r[k]; return Array.isArray(v) ? v[v.length - 1] : v; };
        const shown = new Set(['_time', 'sourcetype', 'EventCode', 'action', 'host', 'src_ip', 'src', 'IpAddress']);
        return {
          timestamp: g('_time') || '',
          source: g('sourcetype') || '-',
          action: g('EventCode') || g('action') || '-',
          host: g('host') || g('ComputerName') || '-',
          ip: g('src_ip') || g('src') || g('IpAddress') || '-',
          details: Object.entries(r).filter(([k]) => !shown.has(k) && !k.startsWith('_')).slice(0, 6).map(([k, v]) => `${k}=${Array.isArray(v) ? v.join('|') : v}`).join(' '),
        };
      });
    },
    async searchEvents(query, from, to, limit) {
      return normalizeRows(await splunk.searchEvents(cfg, query, s(from), s(to), limit));
    },
    testConnection: () => splunk.testConnection(cfg),
  };
}

export function elasticSource(cfg: elastic.ElasticConfig): LogSource {
  return {
    kind: 'elastic',
    label: 'Elastic',
    location: `index ${cfg.index}`,
    queryLanguage: 'Lucene',
    maxEvents: cfg.maxEvents,
    connector: {
      id: 'conn-live', name: 'Elasticsearch (live)', vendor: 'Elastic',
      authType: cfg.apiKey ? 'API key' : cfg.username ? 'Basic (username/password)' : 'None',
      endpoint: `${cfg.baseUrl}/${cfg.index}/_search`,
      eventsConsumed: `${cfg.index}: Winlogbeat (Windows Security, Sysmon), ECS fields`,
    },
    fetchUserEvents: (user, from, to) => elastic.fetchUserEvents(cfg, user, from, to),
    fetchBaseline: (user, from, to) => elastic.fetchBaseline(cfg, user, from, to),
    fetchHostEvents: (hosts, from, to) => elastic.fetchHostEvents(cfg, hosts, from, to),
    fetchEntityEvents: (entity, from, to) => elastic.fetchEntityEvents(cfg, entity, from, to),
    searchUsers: (term, from, to) => elastic.searchUsers(cfg, term, from, to),
    runAdhocQuery: (query, from, to) => elastic.runAdhocQuery(cfg, query, from, to),
    searchEvents: (query, from, to, limit) => elastic.searchEvents(cfg, query, from, to, limit),
    testConnection: () => elastic.testConnection(cfg),
  };
}

// DATA_SOURCE picks the source; without it, the first configured one wins (Splunk, then Elastic), else demo.
export function loadLogSource(env = process.env): { dataSource: 'demo' | 'splunk' | 'elastic'; source: LogSource | null } {
  const sp = splunk.loadSplunkConfig(env);
  const el = elastic.loadElasticConfig(env);
  const wanted = (env.DATA_SOURCE || '').toLowerCase();
  if (wanted === 'demo') return { dataSource: 'demo', source: null };
  if (wanted === 'splunk') {
    if (!sp) throw new Error('DATA_SOURCE=splunk requires SPLUNK_URL (and credentials). See .env.example.');
    return { dataSource: 'splunk', source: splunkSource(sp) };
  }
  if (wanted === 'elastic') {
    if (!el) throw new Error('DATA_SOURCE=elastic requires ELASTIC_URL (and credentials). See .env.example.');
    return { dataSource: 'elastic', source: elasticSource(el) };
  }
  if (wanted) throw new Error(`Unknown DATA_SOURCE "${wanted}" (use demo, splunk or elastic)`);
  if (sp) return { dataSource: 'splunk', source: splunkSource(sp) };
  if (el) return { dataSource: 'elastic', source: elasticSource(el) };
  return { dataSource: 'demo', source: null };
}
