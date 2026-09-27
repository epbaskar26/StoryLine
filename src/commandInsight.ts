// Explains a command line in one line for the analyst: decodes encoded PowerShell and flags known
// attacker techniques. Deterministic (no AI), so it works offline and the same input always gives the same answer.

export interface CommandFlag {
  label: string;
  severity: 'high' | 'medium' | 'low';
  ttp?: string;
}

export interface CommandInsight {
  interpreter: string; // PowerShell, cmd, rundll32 ...
  summary: string; // one line
  decoded?: string; // decoded -EncodedCommand payload
  flags: CommandFlag[];
  severity: 'high' | 'medium' | 'low' | 'info';
}

const RULES: { re: RegExp; flag: CommandFlag }[] = [
  { re: /\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt|zip)\.(exe|scr|com|bat|cmd|js|vbs|hta)\b/i, flag: { label: 'double file extension (masquerading)', severity: 'high', ttp: 'T1036.007' } },
  { re: /content\.outlook|\\inetcache\\|olk[0-9a-f]*\\/i, flag: { label: 'runs from the email attachment cache', severity: 'high', ttp: 'T1204.002' } },
  { re: /rundll32(\.exe)?\s+"?[a-z]:\\(users|programdata)\\[^,]*,/i, flag: { label: 'rundll32 loads a DLL from a user folder', severity: 'high', ttp: 'T1218.011' } },
  { re: /^"?[a-z]:\\users\\[^\\]+\\(downloads|appdata\\local\\temp|desktop)\\/i, flag: { label: 'runs from a user-writable folder', severity: 'medium', ttp: 'T1204.002' } },
  { re: /\b(iex|invoke-expression)\b/i, flag: { label: 'runs code from a string (IEX)', severity: 'high', ttp: 'T1059.001' } },
  { re: /downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|\bwget\b|\bcurl(\.exe)?\s+-|start-bitstransfer|net\.webclient|bitsadmin\s+\/transfer/i, flag: { label: 'downloads from the internet', severity: 'high', ttp: 'T1105' } },
  { re: /certutil(\.exe)?\s+.*(-urlcache|-decode|-f\s+http)/i, flag: { label: 'certutil download/decode', severity: 'high', ttp: 'T1140' } },
  { re: /mimikatz|sekurlsa|lsadump|invoke-mimikatz|procdump.*lsass|comsvcs\.dll.*minidump|lsass\.dmp/i, flag: { label: 'credential dumping', severity: 'high', ttp: 'T1003' } },
  { re: /vssadmin(\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|wbadmin\s+delete|bcdedit.*recoveryenabled\s+no/i, flag: { label: 'deletes backups / shadow copies', severity: 'high', ttp: 'T1490' } },
  { re: /(set|add)-mppreference.*(disable|exclusion)|disablerealtimemonitoring|sc\s+(stop|config)\s+windefend/i, flag: { label: 'weakens Defender', severity: 'high', ttp: 'T1562.001' } },
  { re: /net1?\s+(user|localgroup|group)\s+.*\/add/i, flag: { label: 'creates account or adds to group', severity: 'high', ttp: 'T1098' } },
  { re: /mshta(\.exe)?\s+(http|javascript|vbscript)|regsvr32(\.exe)?.*\/i:http|rundll32(\.exe)?.*(javascript:|http)/i, flag: { label: 'signed-binary proxy execution', severity: 'high', ttp: 'T1218' } },
  { re: /schtasks(\.exe)?\s+\/create|new-scheduledtask|register-scheduledtask/i, flag: { label: 'creates a scheduled task', severity: 'medium', ttp: 'T1053.005' } },
  { re: /currentversion\\run|\\startup\\|start menu\\programs\\startup/i, flag: { label: 'autorun persistence', severity: 'medium', ttp: 'T1547.001' } },
  { re: /rclone|transfer\.sh|mega(\.nz|cmd)|anonfiles|file\.io|pastebin/i, flag: { label: 'transfer to file-sharing service', severity: 'high', ttp: 'T1567' } },
  { re: /\b7z(a|\.exe)?\s+a\b.*-p|\brar(\.exe)?\s+a\b.*-hp|compress-archive/i, flag: { label: 'archives data', severity: 'medium', ttp: 'T1560' } },
  { re: /\b(nltest|net\s+view|net\s+group\s+"?domain|get-adcomputer|get-aduser|adfind|dsquery)\b/i, flag: { label: 'domain discovery', severity: 'medium', ttp: 'T1087.002' } },
  { re: /\b(whoami|systeminfo|ipconfig\s+\/all|quser|tasklist|net\s+user\b(?!.*\/add))/i, flag: { label: 'host/user discovery', severity: 'low', ttp: 'T1082' } },
  { re: /-(w|win|window|windowstyle)\s+(h|hidden)\b/i, flag: { label: 'hidden window', severity: 'medium', ttp: 'T1564.003' } },
  { re: /-(ep|exec|executionpolicy)\s+(bypass|unrestricted)\b/i, flag: { label: 'execution policy bypass', severity: 'low' } },
  { re: /-(nop|noprofile)\b/i, flag: { label: 'no profile', severity: 'low' } },
  { re: /frombase64string|\[convert\]::/i, flag: { label: 'decodes base64 at runtime', severity: 'medium', ttp: 'T1140' } },
  { re: /amsiutils|amsiinitfailed|amsi\.dll/i, flag: { label: 'AMSI bypass', severity: 'high', ttp: 'T1562.001' } },
];

const ENC_ARG = /(?:^|\s)[-\/](?:e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand|ec)\s+["']?([A-Za-z0-9+/=]{8,})["']?/i;

function b64Utf16(b64: string): string | undefined {
  try {
    const bin = typeof atob === 'function' ? atob(b64) : Buffer.from(b64, 'base64').toString('binary');
    let out = '';
    for (let i = 0; i + 1 < bin.length; i += 2) out += String.fromCharCode(bin.charCodeAt(i) | (bin.charCodeAt(i + 1) << 8));
    // Reject garbage: mostly printable text expected
    const printable = out.replace(/[\x20-\x7E\r\n\t]/g, '').length;
    return out && printable / out.length < 0.1 ? out : undefined;
  } catch {
    return undefined;
  }
}

// First token of a command line; handles "C:\Program Files\x.exe" quoting
export function exePath(cmd: string): string {
  const t = cmd.trim();
  if (t.startsWith('"')) return t.slice(1, t.indexOf('"', 1) > 0 ? t.indexOf('"', 1) : undefined);
  return t.split(/\s+/)[0] || '';
}

function argsOf(cmd: string): string {
  const t = cmd.trim();
  if (t.startsWith('"')) { const end = t.indexOf('"', 1); return end > 0 ? t.slice(end + 1).trim() : ''; }
  return t.replace(/^\S+\s*/, '');
}

function interpreterOf(cmd: string): string {
  const base = exePath(cmd).split(/[\\/]/).pop() || '';
  const exe = base.toLowerCase();
  if (/^(powershell|pwsh)(\.exe)?$/.test(exe) || /\bpowershell(\.exe)?\b/i.test(cmd)) return 'PowerShell';
  if (exe === 'cmd.exe' || exe === 'cmd') return 'cmd';
  if (exe) return base.replace(/\.exe$/i, '');
  return 'command';
}

function clip(s: string, n: number): string {
  const one = s.replace(/\s+/g, ' ').trim();
  return one.length > n ? one.slice(0, n - 1) + '…' : one;
}

export function analyzeCommand(commandLine: string, opts: { scriptBlock?: boolean } = {}): CommandInsight {
  const cmd = commandLine || '';
  const interpreter = opts.scriptBlock ? 'PowerShell script block' : interpreterOf(cmd);
  let decoded: string | undefined;
  const enc = cmd.match(ENC_ARG);
  if (enc && /powershell|pwsh/i.test(cmd)) decoded = b64Utf16(enc[1]);

  const haystack = `${cmd}\n${decoded || ''}`;
  const flags: CommandFlag[] = [];
  if (enc && /powershell|pwsh/i.test(cmd)) flags.push({ label: decoded ? 'encoded command' : 'encoded command (could not decode)', severity: 'high', ttp: 'T1027' });
  for (const r of RULES) if (r.re.test(haystack) && !flags.some(f => f.label === r.flag.label)) flags.push(r.flag);

  const rank = { high: 3, medium: 2, low: 1 } as const;
  const top = [...flags].sort((a, b) => rank[b.severity] - rank[a.severity]);
  const severity: CommandInsight['severity'] = top[0]?.severity || 'info';

  let summary: string;
  if (decoded) {
    summary = `${interpreter} (${top.slice(0, 3).map(f => f.label).join(', ')}) · decodes to: ${clip(decoded, 90)}`;
  } else if (top.length) {
    summary = `${interpreter}: ${top.slice(0, 3).map(f => f.label).join(', ')}`;
  } else {
    const args = argsOf(cmd);
    summary = args ? `${interpreter} ${clip(args, 90)}` : `${interpreter} started (no arguments)`;
  }
  return { interpreter, summary, decoded, flags: top, severity };
}

// Text that looks like an instruction aimed at an AI model (prompt injection inside log data)
export function looksLikeInjection(text: string): boolean {
  return /ignore (all |any )?(previous|prior|above) (instructions|prompts)|disregard (the )?(system|previous)|you are (now )?(an? )?(ai|assistant|chatgpt|claude|gemini)|system prompt|mark (this|it) as (benign|safe)|classify (this|it) as (benign|safe)|do not (report|flag)|<\/?(system|instructions?)>/i.test(text);
}
