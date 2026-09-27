// Persistence: PostgreSQL when DATABASE_URL is set, otherwise an in-memory store (lost on restart).
import pg from 'pg';
import type { WatchlistItem, CaseRecord, AuditLogEntry, UserProfile, EvidenceRecord, InvestigationNote } from '../src/types';
import type { AdminConfig } from './demoData';
import type { AlertRecord } from './graphBuilder';

export interface Annotation {
  entityKey: string;
  nodeId: string;
  text: string;
  analyst: string;
  updatedAt: string;
}

export interface Store {
  kind: 'postgres' | 'memory';
  init(seed: { watchlist: WatchlistItem[]; cases: CaseRecord[]; audit: AuditLogEntry[]; config: AdminConfig }): Promise<void>;
  listWatchlist(): Promise<WatchlistItem[]>;
  addWatchlist(item: WatchlistItem): Promise<void>;
  removeWatchlist(id: string): Promise<void>;
  listCases(): Promise<CaseRecord[]>;
  getCase(id: string): Promise<{ record: CaseRecord; snapshot: UserProfile | null } | null>;
  createCase(record: CaseRecord, snapshot: UserProfile | null): Promise<void>;
  updateCase(id: string, patch: Partial<CaseRecord>): Promise<CaseRecord | null>;
  addEvidence(caseId: string, evidence: EvidenceRecord): Promise<CaseRecord | null>;
  listAudit(limit?: number): Promise<AuditLogEntry[]>;
  addAudit(entry: AuditLogEntry): Promise<void>;
  getConfig(): Promise<AdminConfig>;
  setConfig(config: AdminConfig): Promise<void>;
  listAnnotations(entityKey: string): Promise<Annotation[]>;
  upsertAnnotation(a: Annotation): Promise<void>;
  addAlert(alert: AlertRecord): Promise<void>;
  listAlerts(entityKey: string): Promise<AlertRecord[]>;
  listNotes(filter: { entityKey?: string; caseId?: string }): Promise<InvestigationNote[]>;
  addNote(note: InvestigationNote): Promise<void>;
}

const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v));

export class MemoryStore implements Store {
  kind = 'memory' as const;
  private watchlist: WatchlistItem[] = [];
  private cases: { record: CaseRecord; snapshot: UserProfile | null }[] = [];
  private audit: AuditLogEntry[] = [];
  private config!: AdminConfig;
  private annotations: Annotation[] = [];
  private alerts: AlertRecord[] = [];
  private notes: InvestigationNote[] = [];

  async init(seed: { watchlist: WatchlistItem[]; cases: CaseRecord[]; audit: AuditLogEntry[]; config: AdminConfig }) {
    this.watchlist = clone(seed.watchlist);
    this.cases = seed.cases.map(c => ({ record: clone(c), snapshot: null }));
    this.audit = clone(seed.audit);
    this.config = clone(seed.config);
  }
  async listWatchlist() { return clone(this.watchlist); }
  async addWatchlist(item: WatchlistItem) {
    this.watchlist.unshift(item);
    if (this.watchlist.length > 20) this.watchlist.pop();
  }
  async removeWatchlist(id: string) { this.watchlist = this.watchlist.filter(w => w.id !== id); }
  async listCases() { return clone(this.cases.map(c => c.record)); }
  async getCase(id: string) { const c = this.cases.find(x => x.record.id === id); return c ? clone(c) : null; }
  async createCase(record: CaseRecord, snapshot: UserProfile | null) { this.cases.unshift({ record, snapshot }); }
  async updateCase(id: string, patch: Partial<CaseRecord>) {
    const c = this.cases.find(x => x.record.id === id);
    if (!c) return null;
    c.record = { ...c.record, ...patch };
    return clone(c.record);
  }
  async addEvidence(caseId: string, evidence: EvidenceRecord) {
    const c = this.cases.find(x => x.record.id === caseId);
    if (!c) return null;
    c.record.evidence = [...(c.record.evidence || []), evidence];
    return clone(c.record);
  }
  async listAudit(limit = 500) { return clone(this.audit.slice(0, limit)); }
  async addAudit(entry: AuditLogEntry) { this.audit.unshift(entry); }
  async getConfig() { return clone(this.config); }
  async setConfig(config: AdminConfig) { this.config = clone(config); }
  async listAnnotations(entityKey: string) { return clone(this.annotations.filter(a => a.entityKey === entityKey)); }
  async upsertAnnotation(a: Annotation) {
    this.annotations = this.annotations.filter(x => !(x.entityKey === a.entityKey && x.nodeId === a.nodeId));
    if (a.text.trim()) this.annotations.push(a);
  }
  async addAlert(alert: AlertRecord) { this.alerts.push(alert); }
  async listAlerts(entityKey: string) { return clone(this.alerts.filter(a => a.entityKey === entityKey)); }
  async listNotes(f: { entityKey?: string; caseId?: string }) {
    return clone(this.notes.filter(n => (!f.entityKey || n.entityKey === f.entityKey) && (!f.caseId || n.caseId === f.caseId)).sort((a, b) => b.createdAt.localeCompare(a.createdAt)));
  }
  async addNote(note: InvestigationNote) { this.notes.push(clone(note)); }
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS watchlist (
  id TEXT PRIMARY KEY,
  data JSONB NOT NULL,
  added_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS cases (
  id TEXT PRIMARY KEY,
  data JSONB NOT NULL,
  snapshot JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY,
  ts TIMESTAMPTZ NOT NULL,
  analyst TEXT NOT NULL,
  action TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  details TEXT NOT NULL,
  sha256 TEXT
);
-- The audit log is append-only: block UPDATE and DELETE at the database level.
CREATE OR REPLACE FUNCTION audit_log_immutable() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS audit_log_no_update ON audit_log;
CREATE TRIGGER audit_log_no_update BEFORE UPDATE OR DELETE ON audit_log FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();
CREATE TABLE IF NOT EXISTS app_config (
  key TEXT PRIMARY KEY,
  data JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS annotations (
  entity_key TEXT NOT NULL,
  node_id TEXT NOT NULL,
  text TEXT NOT NULL,
  analyst TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (entity_key, node_id)
);
CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY,
  entity_key TEXT NOT NULL,
  data JSONB NOT NULL,
  received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS alerts_entity_idx ON alerts (entity_key);
-- Investigation notes (hypotheses, verdicts, assignment and closure) are append-only like the audit log
CREATE TABLE IF NOT EXISTS notes (
  id TEXT PRIMARY KEY,
  entity_key TEXT NOT NULL,
  case_id TEXT,
  data JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS notes_entity_idx ON notes (entity_key);
CREATE OR REPLACE FUNCTION notes_immutable() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'notes are append-only';
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS notes_no_update ON notes;
CREATE TRIGGER notes_no_update BEFORE UPDATE OR DELETE ON notes FOR EACH ROW EXECUTE FUNCTION notes_immutable();
`;

export class PgStore implements Store {
  kind = 'postgres' as const;
  private pool: pg.Pool;
  constructor(connectionString: string) {
    this.pool = new pg.Pool({ connectionString, max: 10 });
  }
  private q(text: string, params: unknown[] = []) { return this.pool.query(text, params); }

  async init(seed: { watchlist: WatchlistItem[]; cases: CaseRecord[]; audit: AuditLogEntry[]; config: AdminConfig }) {
    await this.q(SCHEMA);
    const cfg = await this.q(`SELECT 1 FROM app_config WHERE key = 'admin'`);
    if (cfg.rowCount === 0) {
      await this.q(`INSERT INTO app_config (key, data) VALUES ('admin', $1)`, [JSON.stringify(seed.config)]);
      for (const w of seed.watchlist) await this.addWatchlist(w);
      for (const c of seed.cases) await this.createCase(c, null);
      for (const a of [...seed.audit].reverse()) await this.addAudit(a);
    }
  }
  async listWatchlist() {
    const r = await this.q(`SELECT data FROM watchlist ORDER BY added_at DESC LIMIT 20`);
    return r.rows.map(x => x.data as WatchlistItem);
  }
  async addWatchlist(item: WatchlistItem) {
    await this.q(`INSERT INTO watchlist (id, data, added_at) VALUES ($1, $2, $3) ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data`, [item.id, JSON.stringify(item), item.addedAt]);
  }
  async removeWatchlist(id: string) { await this.q(`DELETE FROM watchlist WHERE id = $1`, [id]); }
  async listCases() {
    const r = await this.q(`SELECT data FROM cases ORDER BY created_at DESC`);
    return r.rows.map(x => x.data as CaseRecord);
  }
  async getCase(id: string) {
    const r = await this.q(`SELECT data, snapshot FROM cases WHERE id = $1`, [id]);
    if (!r.rowCount) return null;
    return { record: r.rows[0].data as CaseRecord, snapshot: (r.rows[0].snapshot as UserProfile) || null };
  }
  async createCase(record: CaseRecord, snapshot: UserProfile | null) {
    await this.q(`INSERT INTO cases (id, data, snapshot, created_at) VALUES ($1, $2, $3, $4)`, [record.id, JSON.stringify(record), snapshot ? JSON.stringify(snapshot) : null, record.createdAt]);
  }
  async updateCase(id: string, patch: Partial<CaseRecord>) {
    const r = await this.q(`UPDATE cases SET data = data || $2::jsonb WHERE id = $1 RETURNING data`, [id, JSON.stringify(patch)]);
    return r.rowCount ? (r.rows[0].data as CaseRecord) : null;
  }
  async addEvidence(caseId: string, evidence: EvidenceRecord) {
    const r = await this.q(
      `UPDATE cases SET data = jsonb_set(data, '{evidence}', COALESCE(data->'evidence', '[]'::jsonb) || $2::jsonb) WHERE id = $1 RETURNING data`,
      [caseId, JSON.stringify([evidence])],
    );
    return r.rowCount ? (r.rows[0].data as CaseRecord) : null;
  }
  async listAudit(limit = 500) {
    const r = await this.q(`SELECT id, ts, analyst, action, entity_id, details, sha256 FROM audit_log ORDER BY ts DESC LIMIT $1`, [limit]);
    return r.rows.map(x => ({ id: x.id, timestamp: new Date(x.ts).toISOString(), analyst: x.analyst, action: x.action, entityId: x.entity_id, details: x.details, sha256: x.sha256 || undefined }));
  }
  async addAudit(e: AuditLogEntry) {
    await this.q(`INSERT INTO audit_log (id, ts, analyst, action, entity_id, details, sha256) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (id) DO NOTHING`, [e.id, e.timestamp, e.analyst, e.action, e.entityId, e.details, e.sha256 || null]);
  }
  async getConfig() {
    const r = await this.q(`SELECT data FROM app_config WHERE key = 'admin'`);
    return r.rows[0].data as AdminConfig;
  }
  async setConfig(config: AdminConfig) {
    await this.q(`UPDATE app_config SET data = $1 WHERE key = 'admin'`, [JSON.stringify(config)]);
  }
  async listAnnotations(entityKey: string) {
    const r = await this.q(`SELECT entity_key, node_id, text, analyst, updated_at FROM annotations WHERE entity_key = $1`, [entityKey]);
    return r.rows.map(x => ({ entityKey: x.entity_key, nodeId: x.node_id, text: x.text, analyst: x.analyst, updatedAt: new Date(x.updated_at).toISOString() }));
  }
  async upsertAnnotation(a: Annotation) {
    if (!a.text.trim()) {
      await this.q(`DELETE FROM annotations WHERE entity_key = $1 AND node_id = $2`, [a.entityKey, a.nodeId]);
      return;
    }
    await this.q(
      `INSERT INTO annotations (entity_key, node_id, text, analyst, updated_at) VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (entity_key, node_id) DO UPDATE SET text = EXCLUDED.text, analyst = EXCLUDED.analyst, updated_at = EXCLUDED.updated_at`,
      [a.entityKey, a.nodeId, a.text, a.analyst, a.updatedAt],
    );
  }
  async addAlert(alert: AlertRecord) {
    await this.q(`INSERT INTO alerts (id, entity_key, data) VALUES ($1,$2,$3) ON CONFLICT (id) DO NOTHING`, [alert.id, alert.entityKey, JSON.stringify(alert)]);
  }
  async listAlerts(entityKey: string) {
    const r = await this.q(`SELECT data FROM alerts WHERE entity_key = $1 ORDER BY received_at`, [entityKey]);
    return r.rows.map(x => x.data as AlertRecord);
  }
  async listNotes(f: { entityKey?: string; caseId?: string }) {
    const where: string[] = [];
    const params: unknown[] = [];
    if (f.entityKey) { params.push(f.entityKey); where.push(`entity_key = $${params.length}`); }
    if (f.caseId) { params.push(f.caseId); where.push(`case_id = $${params.length}`); }
    const r = await this.q(`SELECT data FROM notes ${where.length ? `WHERE ${where.join(' AND ')}` : ''} ORDER BY created_at DESC LIMIT 1000`, params);
    return r.rows.map(x => x.data as InvestigationNote);
  }
  async addNote(n: InvestigationNote) {
    await this.q(`INSERT INTO notes (id, entity_key, case_id, data, created_at) VALUES ($1,$2,$3,$4,$5)`, [n.id, n.entityKey, n.caseId || null, JSON.stringify(n), n.createdAt]);
  }
}

export function createStore(env = process.env): Store {
  return env.DATABASE_URL ? new PgStore(env.DATABASE_URL) : new MemoryStore();
}
