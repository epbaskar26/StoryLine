// Splunk REST adapter: runs searches through /services/search/jobs/export and streams JSON results.
// Works with Splunk Free (set allowRemoteLogin = always in server.conf when calling from another host).
import https from 'node:https';
import http from 'node:http';

export interface SplunkConfig {
  baseUrl: string; // e.g. https://localhost:8089
  username?: string;
  password?: string;
  token?: string; // Splunk auth token (Bearer). Used instead of username/password when set.
  verifyTls: boolean;
  index: string; // e.g. botsv3 or "botsv3 OR index=main"
  timeoutMs: number;
  maxEvents: number;
}

export function loadSplunkConfig(env = process.env): SplunkConfig | null {
  if (!env.SPLUNK_URL) return null;
  return {
    baseUrl: env.SPLUNK_URL.replace(/\/+$/, ''),
    username: env.SPLUNK_USERNAME,
    password: env.SPLUNK_PASSWORD,
    token: env.SPLUNK_TOKEN,
    verifyTls: env.SPLUNK_VERIFY_TLS !== 'false',
    index: env.SPLUNK_INDEX || 'main',
    timeoutMs: parseInt(env.SPLUNK_TIMEOUT_MS || '120000', 10),
    maxEvents: parseInt(env.SPLUNK_MAX_EVENTS || '20000', 10),
  };
}

export type SplunkRow = Record<string, string | string[] | undefined>;

// Usernames are interpolated into SPL, so only allow characters that appear in real account names.
const SAFE_ENTITY = /^[A-Za-z0-9._@$\-\\]{1,128}$/;

export function assertSafeEntity(value: string): string {
  if (!SAFE_ENTITY.test(value)) {
    throw new Error(`Rejected entity value "${value}": only letters, digits and . _ @ $ - \\ are allowed`);
  }
  return value;
}

// Escape a value for use inside a double-quoted SPL string.
export function splQuote(value: string): string {
  return '"' + value.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}

// Build the index clause: "botsv3" -> index="botsv3"; supports a comma-separated list.
export function indexClause(index: string): string {
  const parts = index.split(',').map(s => s.trim()).filter(Boolean);
  const safe = parts.map(p => {
    if (!/^[A-Za-z0-9_\-*]+$/.test(p)) throw new Error(`Invalid SPLUNK_INDEX entry: ${p}`);
    return `index=${splQuote(p)}`;
  });
  return safe.length === 1 ? safe[0] : `(${safe.join(' OR ')})`;
}

// Search clause that matches a user across the common Windows, Sysmon and CIM field names.
export function userFilterClause(username: string): string {
  const u = assertSafeEntity(username);
  const bare = u.includes('\\') ? u.split('\\').pop()! : u;
  const q = splQuote(bare);
  return `(user=${q} OR src_user=${q} OR Account_Name=${q} OR TargetUserName=${q} OR SubjectUserName=${q} OR User=${splQuote('*\\' + bare)} OR user=${splQuote('*\\' + bare)})`;
}

// Fields pulled from Splunk. Keeping this list explicit keeps the payload small and avoids pulling raw logs.
export const EXPORT_FIELDS = [
  '_time', '_cd', 'sourcetype', 'host', 'EventCode', 'Logon_Type', 'LogonType',
  'user', 'src_user', 'Account_Name', 'TargetUserName', 'SubjectUserName', 'User', 'Account_Domain',
  'src', 'src_ip', 'Source_Network_Address', 'IpAddress', 'Workstation_Name', 'src_host',
  'dest', 'dest_ip', 'dest_host', 'dest_port', 'DestinationIp', 'DestinationPort', 'DestinationHostname',
  'ComputerName', 'Computer', 'process', 'process_name', 'Image', 'New_Process_Name', 'ParentImage',
  'Creator_Process_Name', 'parent_process', 'CommandLine', 'Process_Command_Line', 'process_command_line',
  'TargetFilename', 'file_path', 'file_name', 'Object_Name', 'QueryName', 'query',
  'url', 'site', 'uri', 'http_method', 'bytes_out', 'bytes', 'action', 'signature', 'Group_Name',
  'app', 'status', 'Failure_Reason', 'Status',
];

function requestJson(cfg: SplunkConfig, path: string, form: Record<string, string>, onRow: (row: SplunkRow) => boolean | void): Promise<number> {
  return new Promise((resolve, reject) => {
    const url = new URL(cfg.baseUrl + path);
    const body = new URLSearchParams(form).toString();
    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': Buffer.byteLength(body).toString(),
    };
    if (cfg.token) headers['Authorization'] = `Bearer ${cfg.token}`;
    else if (cfg.username) headers['Authorization'] = 'Basic ' + Buffer.from(`${cfg.username}:${cfg.password || ''}`).toString('base64');

    const lib = url.protocol === 'https:' ? https : http;
    let count = 0;
    let stopped = false;
    const req = lib.request(
      url,
      { method: 'POST', headers, rejectUnauthorized: cfg.verifyTls, timeout: cfg.timeoutMs } as https.RequestOptions,
      res => {
        if (res.statusCode && res.statusCode >= 400) {
          let errBody = '';
          res.on('data', c => (errBody += c));
          res.on('end', () => reject(new Error(`Splunk HTTP ${res.statusCode}: ${errBody.slice(0, 500)}`)));
          return;
        }
        res.setEncoding('utf8');
        let buf = '';
        res.on('data', chunk => {
          if (stopped) return;
          buf += chunk;
          let nl: number;
          while ((nl = buf.indexOf('\n')) >= 0) {
            const line = buf.slice(0, nl).trim();
            buf = buf.slice(nl + 1);
            if (!line) continue;
            try {
              const obj = JSON.parse(line);
              if (obj.result) {
                count++;
                if (onRow(obj.result) === false || count >= cfg.maxEvents) {
                  stopped = true;
                  req.destroy();
                  resolve(count);
                  return;
                }
              } else if (obj.messages?.some((m: any) => m.type === 'FATAL' || m.type === 'ERROR')) {
                stopped = true;
                req.destroy();
                reject(new Error('Splunk search error: ' + obj.messages.map((m: any) => m.text).join('; ')));
                return;
              }
            } catch {
              // ignore partial / non-JSON lines
            }
          }
        });
        res.on('end', () => {
          if (stopped) return;
          const line = buf.trim();
          if (line) {
            try {
              const obj = JSON.parse(line);
              if (obj.result) { count++; onRow(obj.result); }
            } catch { /* ignore */ }
          }
          resolve(count);
        });
      },
    );
    req.on('timeout', () => req.destroy(new Error(`Splunk request timed out after ${cfg.timeoutMs} ms`)));
    req.on('error', err => { if (!stopped) reject(err); });
    req.write(body);
    req.end();
  });
}

// Run an SPL search (must start with "search" or "|") between two epoch-second bounds and collect rows.
export async function exportSearch(cfg: SplunkConfig, spl: string, earliest: number, latest: number): Promise<SplunkRow[]> {
  const rows: SplunkRow[] = [];
  const search = spl.trim().startsWith('|') || spl.trim().startsWith('search ') ? spl.trim() : `search ${spl.trim()}`;
  await requestJson(
    cfg,
    '/services/search/jobs/export',
    {
      search,
      earliest_time: String(Math.floor(earliest)),
      latest_time: String(Math.ceil(latest)),
      output_mode: 'json',
    },
    row => { rows.push(row); },
  );
  return rows;
}

// Fetch the user's events for the investigation window.
export async function fetchUserEvents(cfg: SplunkConfig, username: string, earliest: number, latest: number): Promise<SplunkRow[]> {
  const spl = `search ${indexClause(cfg.index)} ${userFilterClause(username)} | fields ${EXPORT_FIELDS.join(', ')} | fields - _raw | head ${cfg.maxEvents}`;
  return exportSearch(cfg, spl, earliest, latest);
}

// Fetch events that touch a given host / IP / domain name (1-hop expansion), excluding the root user.
export async function fetchEntityEvents(cfg: SplunkConfig, entity: string, earliest: number, latest: number, limit = 2000): Promise<SplunkRow[]> {
  const v = splQuote(assertSafeEntity(entity));
  const spl = `search ${indexClause(cfg.index)} (host=${v} OR dest=${v} OR src=${v} OR src_ip=${v} OR dest_ip=${v} OR ComputerName=${v} OR DestinationIp=${v} OR DestinationHostname=${v} OR IpAddress=${v}) | fields ${EXPORT_FIELDS.join(', ')} | fields - _raw | head ${limit}`;
  return exportSearch(cfg, spl, earliest, latest);
}

// Baseline: which hosts, source IPs and destinations did this user touch before the window?
export async function fetchBaseline(cfg: SplunkConfig, username: string, earliest: number, latest: number): Promise<Set<string> | null> {
  const spl = `search ${indexClause(cfg.index)} ${userFilterClause(username)}
    | eval wm_host=lower(coalesce(ComputerName, Computer, host)), wm_src=lower(coalesce(src_ip, Source_Network_Address, IpAddress, src)), wm_dest=lower(coalesce(dest, DestinationHostname, DestinationIp, dest_ip, site))
    | stats count as events, values(wm_host) as hosts, values(wm_src) as srcs, values(wm_dest) as dests`;
  const rows = await exportSearch(cfg, spl.replace(/\s*\n\s*/g, ' '), earliest, latest);
  const row = rows[0];
  if (!row || !row.events || Number(row.events) === 0) return null; // no history -> baseline unavailable
  const out = new Set<string>();
  for (const key of ['hosts', 'srcs', 'dests']) {
    const v = row[key];
    const list = Array.isArray(v) ? v : v ? [v] : [];
    list.forEach(x => out.add(String(x).toLowerCase()));
  }
  return out;
}

// Distinct users matching a search term, for the entity search box.
export async function searchUsers(cfg: SplunkConfig, term: string, earliest: number, latest: number): Promise<{ user: string; count: number }[]> {
  const safe = assertSafeEntity(term).replace(/[\\*]/g, '');
  const pattern = splQuote(`*${safe}*`);
  const spl = `search ${indexClause(cfg.index)} (user=${pattern} OR Account_Name=${pattern} OR TargetUserName=${pattern} OR User=${pattern})
    | eval wm_user=lower(coalesce(user, TargetUserName, User, Account_Name))
    | eval wm_user=mvindex(split(mvindex(wm_user, -1), "\\\\"), -1)
    | where isnotnull(wm_user) AND wm_user!="-" AND NOT match(wm_user, "\\$$")
    | stats count by wm_user | sort - count | head 10`;
  const rows = await exportSearch(cfg, spl.replace(/\s*\n\s*/g, ' '), earliest, latest);
  return rows.map(r => ({ user: String(r.wm_user), count: Number(r.count) || 0 }));
}

// Analyst-supplied SPL from the query console. A result cap is appended.
export async function runAdhocQuery(cfg: SplunkConfig, spl: string, earliest: number, latest: number, limit = 200): Promise<SplunkRow[]> {
  const trimmed = spl.trim();
  if (!trimmed) throw new Error('Empty query');
  return exportSearch(cfg, `${trimmed} | head ${limit}`, earliest, latest);
}

// Analyst SPL returning raw events (for building a graph from a manual search). Transforming searches
// (stats, table...) have no events to graph, so only plain searches are accepted.
export async function searchEvents(cfg: SplunkConfig, spl: string, earliest: number, latest: number, limit: number): Promise<SplunkRow[]> {
  let q = spl.trim().replace(/^search\s+/i, '');
  if (!q) throw new Error('Empty query');
  if (q.startsWith('|') || /\|\s*(stats|chart|timechart|table|top|rare|tstats|eventstats)\b/i.test(q)) {
    throw new Error('Graphs need events: use a plain search (filters only), not a transforming command such as stats or table.');
  }
  if (!/\bindex\s*=/.test(q)) q = `${indexClause(cfg.index)} ${q}`;
  return exportSearch(cfg, `search ${q} | fields ${EXPORT_FIELDS.join(', ')} | fields - _raw | head ${limit}`, earliest, latest);
}

// Connectivity check for the "Test Connection" button.
export async function testConnection(cfg: SplunkConfig): Promise<{ ok: boolean; message: string; latencyMs: number }> {
  const started = Date.now();
  try {
    const rows = await exportSearch(cfg, '| makeresults | eval ok=1', 0, Date.now() / 1000);
    return { ok: rows.length > 0, message: rows.length > 0 ? 'Splunk search API reachable and authenticated' : 'Splunk answered but returned no rows', latencyMs: Date.now() - started };
  } catch (err: any) {
    return { ok: false, message: err.message || String(err), latencyMs: Date.now() - started };
  }
}
