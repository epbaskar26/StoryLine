// Seed real Elasticsearch with dummy Winlogbeat/ECS logs so WatchMe (and Kibana) can query them.
// Runs on the PC against your local Elasticsearch. Timestamps are relative to "now" so the data
// lands inside WatchMe's window. Everything is fictional; no real hosts, users or malware.
//
//   node tools/lab/seed-elastic.mjs                 # -> http://localhost:9200, elastic:changeme, index watchme-demo
//   node tools/lab/seed-elastic.mjs --url http://localhost:9200 --user elastic --pass changeme --index watchme-demo
//   node tools/lab/seed-elastic.mjs --reset         # delete and recreate the index first
//   node tools/lab/seed-elastic.mjs --dry           # print the documents, index nothing
//
// Then point WatchMe at the index (in .env):  ELASTIC_INDEX=winlogbeat-*,watchme-demo
// restart `npm run dev`, and open  http://127.0.0.1:3000/?entity=jsmith  (or aturner, or search a host).

const args = process.argv.slice(2);
const opt = (name, def) => { const i = args.indexOf(`--${name}`); return i >= 0 && args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : def; };
const flag = name => args.includes(`--${name}`);

const URL = opt('url', process.env.ELASTIC_URL || 'http://localhost:9200').replace(/\/+$/, '');
const USER = opt('user', process.env.ELASTIC_USERNAME || 'elastic');
const PASS = opt('pass', process.env.ELASTIC_PASSWORD || 'changeme');
const INDEX = opt('index', 'watchme-demo');
const DRY = flag('dry');
const RESET = flag('reset');

const NOW = Date.now();
const H = 3600_000;
const iso = msAgo => new Date(NOW - msAgo).toISOString();
const docs = [];
let seq = 0;
const push = (msAgo, src) => docs.push({ _id: `seed-${++seq}`, _source: { '@timestamp': iso(msAgo), ...src } });

// ---- helpers that mirror Winlogbeat ECS shapes WatchMe reads ----
const sec = (code, outcome, host, data, extra = {}) => ({
  event: { code: String(code), outcome, provider: 'Microsoft-Windows-Security-Auditing', module: 'security', dataset: 'windows.security' },
  winlog: { channel: 'Security', computer_name: host.toUpperCase(), event_id: String(code), event_data: data, ...(extra.winlog || {}) },
  host: { name: host }, user: { name: data.TargetUserName || data.SubjectUserName },
  related: { user: [data.TargetUserName, data.SubjectUserName].filter(Boolean) },
  ...(data.IpAddress ? { source: { ip: data.IpAddress } } : {}),
});
const sysmon = (code, host, user, data) => ({
  event: { code: String(code), provider: 'Microsoft-Windows-Sysmon', module: 'sysmon', dataset: 'windows.sysmon_operational' },
  winlog: { channel: 'Microsoft-Windows-Sysmon/Operational', computer_name: host.toUpperCase(), event_id: String(code), event_data: data },
  host: { name: host }, user: { name: user }, related: { user: [user] },
});
const system = (code, host, provider, data, user) => ({
  event: { code: String(code), provider, module: 'windows', dataset: 'windows.system' },
  winlog: { channel: 'System', computer_name: host.toUpperCase(), event_id: String(code), provider_name: provider, event_data: data },
  host: { name: host }, ...(user ? { user: { name: user } } : {}),
});
const appLog = (code, host, data, user) => ({
  event: { code: String(code), provider: 'MsiInstaller', module: 'windows', dataset: 'windows.application' },
  winlog: { channel: 'Application', computer_name: host.toUpperCase(), event_id: String(code), provider_name: 'MsiInstaller', event_data: data },
  host: { name: host }, ...(user ? { user: { name: user } } : {}),
});
const defender = (code, host, user, data) => ({
  event: { code: String(code), provider: 'Microsoft-Windows-Windows Defender', module: 'windows', dataset: 'windows.defender' },
  winlog: { channel: 'Microsoft-Windows-Windows Defender/Operational', computer_name: host.toUpperCase(), event_id: String(code), provider_name: 'Windows Defender', event_data: data },
  host: { name: host }, user: { name: user }, related: { user: [user] },
});
const ps4104 = (host, user, text) => ({
  event: { code: '4104', provider: 'Microsoft-Windows-PowerShell', module: 'powershell', dataset: 'windows.powershell_operational' },
  winlog: { channel: 'Microsoft-Windows-PowerShell/Operational', computer_name: host.toUpperCase(), event_id: '4104', user: { name: user } },
  host: { name: host }, user: { name: user }, powershell: { file: { script_block_text: text } },
});
const cloud = (msAgo, mod, dataset, action, user, ip, outcome = 'success', sig) => push(msAgo, {
  event: { module: mod, dataset, action, outcome, code: 'cloud' }, user: { name: user }, source: { ip }, host: { name: `${mod}-cloud` }, ...(sig ? { signature: sig } : {}),
});

// ============================================================================
// STORY 1 - jsmith: phishing -> beacon -> credential access -> persistence ->
//           lateral movement -> collection -> exfiltration, with install/service/
//           task/registry/LSASS/Defender/lockout/audit-clear along the way.
// ============================================================================
const U = 'jsmith', WS = 'ws-jsmith-01';
// Baseline history (10 days back) so first-seen detection has something to compare against
for (let i = 0; i < 6; i++) push(240 * H + i * H, sec('4624', 'success', WS, { TargetUserName: U, LogonType: '2', IpAddress: '10.20.1.15' }, { winlog: { logon: { type: 'Interactive' } } }));
push(239 * H, sec('4624', 'success', 'srv-files', { TargetUserName: U, LogonType: '3', IpAddress: '10.20.1.15' }));
// Normal day
for (let i = 0; i < 3; i++) push(30 * H - i * 10 * 60_000, sec('4624', 'success', WS, { TargetUserName: U, LogonType: '2', IpAddress: '10.20.1.15' }, { winlog: { logon: { type: 'Interactive' } } }));
// Software installed (normal, informational)
push(28 * H, appLog('11707', WS, { ProductName: 'Zoom Workplace', Manufacturer: 'Zoom Video Communications', Version: '6.1.0' }, U));
// Phishing: Outlook writes the attachment, then spawns it
push(22 * H, sysmon('11', WS, U, { Image: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE', TargetFilename: 'C:\\Users\\jsmith\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\AB12\\Invoice_4021.pdf.exe' }));
push(22 * H - 60_000, sysmon('1', WS, U, { Image: 'C:\\Users\\jsmith\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\AB12\\Invoice_4021.pdf.exe', CommandLine: '"C:\\Users\\jsmith\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\AB12\\Invoice_4021.pdf.exe"', ParentImage: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE' }));
// Defender flags the dropper
push(22 * H - 90_000, defender('1116', WS, U, { 'Threat Name': 'Behavior:Win32/CobaltStrike.A', Path: 'C:\\Users\\jsmith\\AppData\\Local\\...\\Invoice_4021.pdf.exe' }));
// C2 beacon
push(21 * H, sysmon('3', WS, U, { Image: 'C:\\Users\\jsmith\\AppData\\Local\\...\\Invoice_4021.pdf.exe', 'DestinationIp': '185.220.101.5', 'DestinationPort': '8443' }));
// Beacon spawns rundll32
push(21 * H - 30_000, sysmon('1', WS, U, { Image: 'C:\\Windows\\System32\\rundll32.exe', CommandLine: 'rundll32.exe C:\\Users\\jsmith\\AppData\\Roaming\\msupd.dll,StartW', ParentImage: 'C:\\Users\\jsmith\\AppData\\Local\\...\\Invoice_4021.pdf.exe' }));
// LSASS access (credential dumping)
{ const d = sysmon('10', WS, U, {}); d.winlog.event_data = { SourceImage: 'C:\\Windows\\System32\\rundll32.exe', TargetImage: 'C:\\Windows\\System32\\lsass.exe', GrantedAccess: '0x1410' }; push(20 * H, d); }
// Encoded PowerShell (net view / nltest = domain discovery), then a script block
push(20 * H - 60_000, sysmon('1', WS, U, { Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', CommandLine: 'powershell.exe -NoP -W Hidden -enc bgBlAHQAIAB2AGkAZQB3ACAALwBkAG8AbQBhAGkAbgA7ACAAbgBsAHQAZQBzAHQAIAAvAGQAYwBsAGkAcwB0ADoAYwBvAHIAcAAuAGwAbwBjAGEAbAA=', ParentImage: 'C:\\Windows\\System32\\rundll32.exe' }));
push(20 * H - 65_000, ps4104(WS, U, 'net view /domain; nltest /dclist:corp.local'));
// Service install (persistence)
push(19 * H, system('7045', WS, 'Service Control Manager', { ServiceName: 'WinDefendUpd', ImagePath: 'C:\\Users\\jsmith\\AppData\\Roaming\\msupd.dll', ServiceType: 'user mode service', StartType: 'auto start' }, U));
// Scheduled task (persistence)
push(19 * H - 60_000, { event: { code: '106', provider: 'Microsoft-Windows-TaskScheduler', module: 'windows', dataset: 'windows.taskscheduler' }, winlog: { channel: 'Microsoft-Windows-TaskScheduler/Operational', computer_name: WS.toUpperCase(), event_id: '106', event_data: { TaskName: '\\OneDriveSync', UserContext: U } }, host: { name: WS }, user: { name: U } });
// Registry Run-key persistence (Sysmon 13)
{ const d = sysmon('13', WS, U, {}); d.winlog.event_data = { TargetObject: 'HKU\\S-1-5-21-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDriveSync', Details: 'C:\\Users\\jsmith\\AppData\\Roaming\\msupd.dll' }; push(19 * H - 120_000, d); }
// AnyDesk install (remote-access tool)
push(18 * H, appLog('11707', WS, { ProductName: 'AnyDesk', Manufacturer: 'AnyDesk Software GmbH', Version: '8.0.8' }, U));
// Lateral movement: 5 servers in ~40 min
['srv-files', 'srv-app01', 'srv-hr-db01', 'srv-sql02', 'dc01'].forEach((h, i) => push(17 * H - i * 8 * 60_000, sec('4624', 'success', h, { TargetUserName: U, LogonType: '3', IpAddress: '10.20.1.15' }, { winlog: { logon: { type: 'Network' } } })));
// Host-only service install on a server (no user field) - tests host-event pull
push(16 * H, system('7045', 'srv-files', 'Service Control Manager', { ServiceName: 'PSEXESVC', ImagePath: 'C:\\Windows\\PSEXESVC.exe', ServiceType: 'user mode service' }));
// Collection: mass file access on the HR DB
push(15 * H, sec('4663', 'success', 'srv-hr-db01', { SubjectUserName: U, ObjectName: 'D:\\Payroll\\SSN_export.csv' }));
// Audit log cleared (defense evasion)
push(14 * H, sec('1102', 'success', WS, { SubjectUserName: U }));
// Exfiltration: DNS + large upload
push(6 * H + 60_000, sysmon('22', WS, U, { QueryName: 'transfer.sh' }));
push(6 * H, { event: { dataset: 'proxy.access', outcome: 'success' }, host: { name: WS }, user: { name: U }, related: { user: [U] }, url: { full: 'https://transfer.sh/upload', domain: 'transfer.sh' }, http: { request: { bytes: 700 * 1024 * 1024, method: 'PUT' } }, source: { ip: '10.20.1.15' } });

// ============================================================================
// STORY 2 - aturner: quieter, mostly-benign account (a good "no attack pattern" test)
// ============================================================================
const A = 'aturner', WS2 = 'ws-aturner-07';
for (let i = 0; i < 5; i++) push((30 - i * 4) * H, sec('4624', 'success', WS2, { TargetUserName: A, LogonType: '2', IpAddress: '10.20.3.44' }, { winlog: { logon: { type: 'Interactive' } } }));
push(20 * H, appLog('11707', WS2, { ProductName: 'Slack', Manufacturer: 'Slack Technologies', Version: '4.38' }, A));
for (let i = 0; i < 2; i++) push((12 - i) * H, sec('4625', 'failure', WS2, { TargetUserName: A, LogonType: '2', Status: '0xc000006a' })); // two mistyped passwords (benign)
push(8 * H, sec('4624', 'success', 'srv-files', { TargetUserName: A, LogonType: '3', IpAddress: '10.20.3.44' }));

// ============================================================================
// STORY 3 - account lockout burst on a service account
// ============================================================================
for (let i = 0; i < 6; i++) push(9 * H + (6 - i) * 60_000, sec('4625', 'failure', 'srv-app01', { TargetUserName: 'svc-backup', LogonType: '3', IpAddress: '10.20.9.12', Status: '0xc000006a' }));
push(9 * H - 60_000, sec('4740', 'failure', 'srv-app01', { TargetUserName: 'svc-backup' }));

// Noise: SYSTEM logons that WatchMe must ignore
push(2 * H, sec('4624', 'success', WS, { TargetUserName: 'SYSTEM', LogonType: '5' }));

// Cloud sign-ins (indexed into the same index so one ELASTIC_INDEX covers everything)
cloud(21 * H, 'azure', 'azure.signinlogs', 'Sign-in activity', U, '185.220.101.5');
cloud(20 * H, 'o365', 'o365.audit', 'UserLoggedIn', U, '185.220.101.5');
cloud(5 * H, 'aws', 'aws.cloudtrail', 'AssumeRole', U, '45.154.255.89', 'success', 'AssumeRole');
cloud(4 * H, 'okta', 'okta.system', 'user.session.start', A, '10.20.3.44');

// ---------------------------------------------------------------------------
docs.sort((a, b) => a._source['@timestamp'].localeCompare(b._source['@timestamp']));

if (DRY) {
  console.log(JSON.stringify(docs.map(d => d._source), null, 2));
  console.error(`\n${docs.length} documents (dry run, nothing indexed).`);
  process.exit(0);
}

const auth = 'Basic ' + Buffer.from(`${USER}:${PASS}`).toString('base64');
async function es(method, path, body, ndjson = false) {
  const res = await fetch(`${URL}${path}`, {
    method,
    headers: { Authorization: auth, 'Content-Type': ndjson ? 'application/x-ndjson' : 'application/json' },
    body,
  });
  const text = await res.text();
  return { ok: res.ok, status: res.status, text };
}

(async () => {
  // Reachability / auth check
  const ping = await es('GET', '/');
  if (!ping.ok) { console.error(`Cannot reach Elasticsearch at ${URL} (HTTP ${ping.status}). Check the URL and elastic password.\n${ping.text.slice(0, 200)}`); process.exit(1); }
  console.log(`Connected to Elasticsearch at ${URL}`);

  if (RESET) { await es('DELETE', `/${INDEX}`); console.log(`Deleted index ${INDEX} (if it existed).`); }

  // Bulk index. Each doc: an action line then the source line.
  const body = docs.map(d => `${JSON.stringify({ index: { _index: INDEX, _id: d._id } })}\n${JSON.stringify(d._source)}`).join('\n') + '\n';
  const r = await es('POST', '/_bulk?refresh=wait_for', body, true);
  if (!r.ok) { console.error(`Bulk index failed (HTTP ${r.status}):\n${r.text.slice(0, 400)}`); process.exit(1); }
  const parsed = JSON.parse(r.text);
  const errors = (parsed.items || []).filter(i => i.index && i.index.error);
  console.log(`Indexed ${docs.length - errors.length}/${docs.length} documents into "${INDEX}".`);
  if (errors.length) console.error(`  ${errors.length} failed. First error: ${JSON.stringify(errors[0].index.error).slice(0, 200)}`);

  console.log('\nNext:');
  console.log(`  1. Point WatchMe at this index. In .env:   ELASTIC_INDEX=winlogbeat-*,${INDEX}`);
  console.log('  2. Restart:  npm run dev');
  console.log('  3. Open:  http://127.0.0.1:3000/?entity=jsmith   (also try aturner, or Ctrl+K host.name:"srv-hr-db01")');
  console.log(`\nKibana: create a data view for "${INDEX}" to browse the raw events.`);
  console.log(`Remove later:  curl -u ${USER}:*** -X DELETE ${URL}/${INDEX}`);
})();
