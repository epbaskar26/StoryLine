// Mock of the Splunk REST export endpoint for local testing without Splunk (npm run mock:splunk).
// Credentials: admin / changeme. Point WatchMe at it with SPLUNK_URL=http://127.0.0.1:8089 and DEFAULT_T0=2018-08-21T00:00:00Z.
// Planted story for user "bgist" (T-0 = 2018-08-21T00:00:00Z):
//  T-30h  normal logons to wrk-bgist from 10.0.1.15 (also in baseline)
//  T-20h  7 failed logons (4625) then success (4624 type 10) on wrk-bgist from 45.77.65.211 (new IP)
//  T-19h  logons to 5 servers within 40 min (type 3) -> lateral fan-out; srv-hr-db01 is first-seen
//  T-18h  encoded PowerShell (Sysmon 1)
//  T-17h  added to Domain Admins (4728)
//  T-6h   600 MB upload to files.transfer-now.io (stream:http)
import http from 'node:http';

const T0 = Date.parse('2018-08-21T00:00:00Z');
const H = 3600_000;
const iso = ms => new Date(ms).toISOString();
let cd = 0;
const ev = (msAgo, fields) => ({ _time: iso(T0 - msAgo), _cd: `1:${++cd}`, ...fields });

const events = [];
for (let i = 0; i < 4; i++) events.push(ev(30 * H - i * 60_000, { sourcetype: 'WinEventLog:Security', host: 'wrk-bgist', EventCode: '4624', Logon_Type: '2', Account_Name: ['-', 'bgist'], Source_Network_Address: '10.0.1.15' }));
for (let i = 0; i < 7; i++) events.push(ev(20 * H - i * 60_000 + 10 * 60_000, { sourcetype: 'WinEventLog:Security', host: 'wrk-bgist', EventCode: '4625', Logon_Type: '10', Account_Name: ['-', 'bgist'], Source_Network_Address: '45.77.65.211', Failure_Reason: 'Unknown user name or bad password.' }));
events.push(ev(20 * H - 5 * 60_000, { sourcetype: 'WinEventLog:Security', host: 'wrk-bgist', EventCode: '4624', Logon_Type: '10', Account_Name: ['-', 'bgist'], Source_Network_Address: '45.77.65.211' }));
['srv-file01', 'srv-app02', 'srv-hr-db01', 'srv-sql03', 'srv-dc01'].forEach((h, i) =>
  events.push(ev(19 * H - i * 8 * 60_000, { sourcetype: 'WinEventLog:Security', host: h, EventCode: '4624', Logon_Type: '3', Account_Name: ['-', 'bgist'], Source_Network_Address: '10.0.1.15' })));
events.push(ev(18 * H, { sourcetype: 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational', host: 'wrk-bgist', EventCode: '1', User: 'FROTHLY\\bgist', Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ParentImage: 'C:\\Windows\\explorer.exe', CommandLine: 'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=' }));
events.push(ev(18 * H - 60_000, { sourcetype: 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational', host: 'wrk-bgist', EventCode: '3', User: 'FROTHLY\\bgist', Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', DestinationIp: '45.77.65.211', DestinationPort: '443' }));
events.push(ev(17 * H, { sourcetype: 'WinEventLog:Security', host: 'srv-dc01', EventCode: '4728', Account_Name: ['bgist', 'bgist'], Group_Name: 'Domain Admins' }));
events.push(ev(6 * H, { sourcetype: 'stream:http', host: 'wrk-bgist', src_ip: '10.0.1.15', user: 'bgist', site: 'files.transfer-now.io', url: 'https://files.transfer-now.io/upload', http_method: 'POST', bytes_out: String(600 * 1024 * 1024) }));
events.push(ev(5 * H, { sourcetype: 'stream:http', host: 'wrk-bgist', src_ip: '10.0.1.15', user: 'bgist', site: 'www.office.com', url: 'https://www.office.com/', http_method: 'GET', bytes_out: '5120' }));
// Another user on srv-hr-db01 (for 1-hop expansion)
const others = [ev(10 * H, { sourcetype: 'WinEventLog:Security', host: 'srv-hr-db01', EventCode: '4624', Logon_Type: '3', Account_Name: ['-', 'kfinch'], Source_Network_Address: '10.0.2.20' })];

let requests = [];
http.createServer((req, res) => {
  let body = '';
  req.on('data', c => (body += c));
  req.on('end', () => {
    const auth = req.headers.authorization || '';
    if (auth !== 'Basic ' + Buffer.from('admin:changeme').toString('base64')) {
      res.writeHead(401); res.end('{"messages":[{"type":"WARN","text":"call not properly authenticated"}]}'); return;
    }
    if (req.url === '/__requests') { res.end(JSON.stringify(requests)); return; }
    const form = new URLSearchParams(body);
    const search = form.get('search') || '';
    const earliest = Number(form.get('earliest_time')) * 1000;
    const latest = Number(form.get('latest_time')) * 1000;
    requests.push({ search, earliest: iso(earliest), latest: iso(latest) });
    let rows = [];
    if (search.includes('makeresults')) rows = [{ ok: '1' }];
    else if (search.includes('stats count as events')) rows = [{ events: '120', hosts: ['wrk-bgist', 'srv-file01', 'srv-app02', 'srv-sql03', 'srv-dc01'], srcs: ['10.0.1.15'], dests: ['www.office.com'] }];
    else if (search.includes('stats count by wm_user')) rows = [{ wm_user: 'bgist', count: '42' }];
    else if (search.includes('host="srv-hr-db01"')) rows = [...others, ...events.filter(e => e.host === 'srv-hr-db01')];
    else if (search.includes('"bgist"')) rows = events.filter(e => { const t = Date.parse(e._time); return t >= earliest && t <= latest; });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    for (const r of rows) res.write(JSON.stringify({ preview: false, offset: 0, result: r }) + '\n');
    res.end();
  });
}).listen(8089, '127.0.0.1', () => console.log('mock splunk on 8089'));
