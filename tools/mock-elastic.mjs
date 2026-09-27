// Mock of the Elasticsearch _search API with Winlogbeat-style (ECS) documents, for testing without Elastic.
// Run: npm run mock:elastic   then set ELASTIC_URL=http://127.0.0.1:9200 ELASTIC_USERNAME=elastic ELASTIC_PASSWORD=changeme
// Data is relative to "now", so it behaves like live data. Planted story for user "epbas" on host "baskaranep":
//   T-10d   normal logons (baseline history)
//   T-30h   normal interactive logon from 192.168.1.20
//   T-20h   6 failed RDP logons (4625) from 203.0.113.50, then success (4624 type 10)
//   T-19h   encoded PowerShell (Sysmon 1) + connection to 203.0.113.50:443 (Sysmon 3)
//   T-18h   epbas adds itself to Administrators (4732)
//   T-17h   network logons (type 3) to 5 servers within 40 min
//   T-6h    DNS lookup of transfer.sh + 700 MB upload (proxy-style ECS event)
import http from 'node:http';

const NOW = Date.now();
const H = 3600_000;
const iso = ms => new Date(ms).toISOString();
let seq = 0;
const docs = [];
const add = (msAgo, doc) => docs.push({ _id: `doc${++seq}`, _source: { '@timestamp': iso(NOW - msAgo), ...doc } });

const sec = (code, outcome, host, data, extra = {}) => ({
  event: { code, outcome, provider: 'Microsoft-Windows-Security-Auditing', module: 'security', dataset: 'windows.security' },
  winlog: { channel: 'Security', computer_name: host.toUpperCase(), event_id: code, event_data: data, ...(extra.winlog || {}) },
  host: { name: host },
  user: { name: data.TargetUserName || data.SubjectUserName },
  related: { user: [data.TargetUserName, data.SubjectUserName].filter(Boolean) },
  ...(data.IpAddress ? { source: { ip: data.IpAddress } } : {}),
});
const sysmon = (code, data) => ({
  event: { code, provider: 'Microsoft-Windows-Sysmon', module: 'sysmon', dataset: 'windows.sysmon_operational' },
  winlog: { channel: 'Microsoft-Windows-Sysmon/Operational', computer_name: 'BASKARANEP', event_id: code },
  host: { name: 'baskaranep' },
  user: { name: 'epbas', domain: 'BASKARANEP' },
  related: { user: ['epbas'] },
  ...data,
});

// Baseline history (10 days ago)
for (let i = 0; i < 5; i++) add(240 * H + i * H, sec('4624', 'success', 'baskaranep', { TargetUserName: 'epbas', LogonType: '2', IpAddress: '192.168.1.20' }, { winlog: { logon: { type: 'Interactive' } } }));
add(239 * H, sec('4624', 'success', 'srv-files', { TargetUserName: 'epbas', LogonType: '3', IpAddress: '192.168.1.20' }));
// Normal day
for (let i = 0; i < 3; i++) add(30 * H - i * 10 * 60_000, sec('4624', 'success', 'baskaranep', { TargetUserName: 'epbas', LogonType: '2', IpAddress: '192.168.1.20' }, { winlog: { logon: { type: 'Interactive' } } }));
// Brute force then success
for (let i = 0; i < 6; i++) add(20 * H + (10 - i) * 60_000, sec('4625', 'failure', 'baskaranep', { TargetUserName: 'epbas', LogonType: '10', IpAddress: '203.0.113.50', Status: '0xc000006d' }));
add(20 * H - 2 * 60_000, sec('4624', 'success', 'baskaranep', { TargetUserName: 'epbas', LogonType: '10', IpAddress: '203.0.113.50' }, { winlog: { logon: { type: 'RemoteInteractive' } } }));
// Encoded PowerShell and C2
add(19 * H, sysmon('1', { process: { executable: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', command_line: 'powershell.exe -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=', parent: { executable: 'C:\\Windows\\explorer.exe' } } }));
add(19 * H - 60_000, sysmon('3', { process: { executable: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' }, destination: { ip: '203.0.113.50', port: 443 } }));
// Added to local Administrators
add(18 * H, sec('4732', 'success', 'baskaranep', { SubjectUserName: 'epbas', TargetUserName: 'Administrators', MemberSid: 'S-1-5-21-1-1001' }, {}));
docs[docs.length - 1]._source.group = { name: 'Administrators' };
docs[docs.length - 1]._source.user = { name: 'epbas' }; // Winlogbeat puts the actor in user.name for group changes
// Lateral logons
['srv-files', 'srv-app01', 'srv-hr-db01', 'srv-sql02', 'dc01'].forEach((h, i) => add(17 * H - i * 8 * 60_000, sec('4624', 'success', h, { TargetUserName: 'epbas', LogonType: '3', IpAddress: '192.168.1.20' }, { winlog: { logon: { type: 'Network' } } })));
// DNS + upload
add(6 * H + 60_000, sysmon('22', { dns: { question: { name: 'transfer.sh' } } }));
add(6 * H, { event: { dataset: 'proxy.access', outcome: 'success' }, host: { name: 'baskaranep' }, user: { name: 'epbas' }, related: { user: ['epbas'] }, url: { full: 'https://transfer.sh/upload', domain: 'transfer.sh' }, http: { request: { bytes: 700 * 1024 * 1024, method: 'PUT' } }, source: { ip: '192.168.1.20' } });
// Noise from another user on srv-hr-db01 (shows up in 1-hop expansion)
add(12 * H, sec('4624', 'success', 'srv-hr-db01', { TargetUserName: 'kfinch', LogonType: '3', IpAddress: '192.168.1.44' }));
// Machine/system account noise that must be ignored
add(2 * H, sec('4624', 'success', 'baskaranep', { TargetUserName: 'SYSTEM', LogonType: '5' }));

// ----- tiny query evaluator (only what WatchMe uses) -----
const get = (o, path) => path.split('.').reduce((a, k) => (a == null ? undefined : a[k]), o);
const vals = (d, f) => [].concat(get(d, f) ?? []).map(String);
function matches(d, q) {
  if (!q) return true;
  if (q.bool) {
    const f = (q.bool.filter || []).every(c => matches(d, c)) && (q.bool.must || []).every(c => matches(d, c));
    const sh = q.bool.should || [];
    const need = q.bool.minimum_should_match ?? (sh.length && !q.bool.filter && !q.bool.must ? 1 : 0);
    return f && sh.filter(c => matches(d, c)).length >= need;
  }
  if (q.range) {
    const [field, r] = Object.entries(q.range)[0];
    const t = Date.parse(get(d, field));
    return (!r.gte || t >= Date.parse(r.gte)) && (!r.lte || t <= Date.parse(r.lte));
  }
  if (q.term) {
    const [field, spec] = Object.entries(q.term)[0];
    const value = typeof spec === 'object' ? spec.value : spec;
    const ci = typeof spec === 'object' && spec.case_insensitive;
    return vals(d, field).some(v => (ci ? v.toLowerCase() === String(value).toLowerCase() : v === String(value)));
  }
  if (q.wildcard) {
    const [field, spec] = Object.entries(q.wildcard)[0];
    const re = new RegExp('^' + String(spec.value).replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$', spec.case_insensitive ? 'i' : '');
    return vals(d, field).some(v => re.test(v));
  }
  if (q.query_string) {
    // naive: every field:value / bare term must appear
    return q.query_string.query.split(/\s+AND\s+/i).every(part => {
      const m = part.match(/^([\w.@]+):\(?"?([^")]*)"?\)?$/);
      if (m) return m[2].split(/\s+OR\s+/i).some(alt => vals(d, m[1]).some(v => v.toLowerCase() === alt.trim().toLowerCase()));
      return JSON.stringify(d).toLowerCase().includes(part.replace(/"/g, '').toLowerCase());
    });
  }
  return true;
}

http.createServer((req, res) => {
  let body = '';
  req.on('data', c => (body += c));
  req.on('end', () => {
    const auth = req.headers.authorization || '';
    const send = (code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };
    if (auth !== 'Basic ' + Buffer.from('elastic:changeme').toString('base64')) return send(401, { error: { reason: 'missing authentication credentials' }, status: 401 });
    const url = new URL(req.url, 'http://x');
    if (url.pathname === '/') return send(200, { name: 'mock', cluster_name: 'mock-elastic', version: { number: '8.19.13-mock' } });
    if (url.pathname.endsWith('/_count')) return send(200, { count: docs.length });
    if (!url.pathname.endsWith('/_search')) return send(404, { error: { reason: 'not found' } });
    const q = body ? JSON.parse(body) : {};
    let hits = docs.filter(d => matches(d._source, q.query));
    const desc = JSON.stringify(q.sort || []).includes('desc');
    hits.sort((a, b) => (Date.parse(a._source['@timestamp']) - Date.parse(b._source['@timestamp'])) * (desc ? -1 : 1));
    if (q.search_after) hits = hits.filter(h => Date.parse(h._source['@timestamp']) > q.search_after[0]);
    const aggregations = {};
    for (const [name, agg] of Object.entries(q.aggs || {})) {
      const counts = new Map();
      hits.forEach(h => vals(h._source, agg.terms.field).forEach(v => counts.set(v, (counts.get(v) || 0) + 1)));
      aggregations[name] = { buckets: [...counts.entries()].map(([key, doc_count]) => ({ key, doc_count })) };
    }
    const size = q.size ?? 10;
    const page = hits.slice(0, size).map(h => ({ ...h, sort: [Date.parse(h._source['@timestamp']), 0] }));
    send(200, { hits: { total: { value: hits.length, relation: 'eq' }, hits: page }, aggregations });
  });
}).listen(9200, '127.0.0.1', () => console.log(`mock elasticsearch on 9200 (${docs.length} docs)`));
