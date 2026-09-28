// Icons for graph entities, picked by entity type and by what the entity is (mail client, browser, shell,
// archive, server...). Generic line icons, not vendor logos: vendor logos are trademarks, and fetching
// favicons for investigated domains would leak the investigation to third parties.
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import {
  User, Users, UserCog, Monitor, Laptop, Server, Database, Network, Globe, Cloud, CloudUpload, Mail, SquareTerminal,
  FileText, FileArchive, FileSpreadsheet, FileCode, FileImage, FileLock, Presentation, Cpu, Cog, KeyRound, AppWindow,
  FolderOpen, MessagesSquare, Siren, ShieldAlert, Search, Bug, Package, Router, PackagePlus, Wrench, CalendarClock, Regex, Usb, CircleDot, type LucideIcon,
} from 'lucide-react';
import type { SecurityNode } from './types';

export interface IconSpec {
  Icon: LucideIcon;
  kind: string; // short description shown under the name, e.g. "mail client"
  tint: string; // accent colour for the icon tile
}

const C = {
  blue: '#2740CB', teal: '#13A8B1', purple: '#843CF3', orange: '#E08A00', red: '#D75054', green: '#018102', pink: '#C80B92', slate: '#5B6270',
};

const PROCESS_RULES: [RegExp, IconSpec][] = [
  [/^(outlook|thunderbird|olk|hxoutlook)\b/, { Icon: Mail, kind: 'mail client', tint: C.blue }],
  [/^(chrome|msedge|firefox|iexplore|brave|opera|safari|arc)\b/, { Icon: Globe, kind: 'web browser', tint: C.teal }],
  [/^(powershell|pwsh|powershell_ise)\b/, { Icon: SquareTerminal, kind: 'PowerShell', tint: C.purple }],
  [/^(cmd|bash|sh|zsh|wsl|conhost|windowsterminal|wt)\b/, { Icon: SquareTerminal, kind: 'shell', tint: C.slate }],
  [/^(winword|wordpad|soffice|swriter)\b/, { Icon: FileText, kind: 'word processor', tint: C.blue }],
  [/^(excel|scalc)\b/, { Icon: FileSpreadsheet, kind: 'spreadsheet', tint: C.green }],
  [/^(powerpnt|simpress)\b/, { Icon: Presentation, kind: 'presentation', tint: C.orange }],
  [/^(acrord32|acrobat|foxitreader|sumatrapdf)\b/, { Icon: FileText, kind: 'PDF reader', tint: C.red }],
  [/^(teams|ms-teams|slack|zoom|discord|skype|telegram|whatsapp)\b/, { Icon: MessagesSquare, kind: 'chat / meetings', tint: C.purple }],
  [/^(explorer)\b/, { Icon: FolderOpen, kind: 'file explorer', tint: C.orange }],
  [/^(7z|7za|7zg|winrar|rar|zip|tar)\b/, { Icon: FileArchive, kind: 'archiver', tint: C.orange }],
  [/^(rclone|megasync|megacmd|curl|wget|bitsadmin|certutil)\b/, { Icon: CloudUpload, kind: 'transfer tool', tint: C.red }],
  [/^(mimikatz|procdump|lsass|pwdump|lazagne|rubeus)\b/, { Icon: KeyRound, kind: 'credential access', tint: C.red }],
  [/^(rundll32|regsvr32|mshta|wscript|cscript|msiexec|installutil|regasm)\b/, { Icon: Cog, kind: 'system binary', tint: C.pink }],
  [/^(vssadmin|wbadmin|bcdedit|schtasks|sc|reg|net|net1|wmic|whoami|nltest)\b/, { Icon: Cog, kind: 'admin tool', tint: C.slate }],
  [/^(code|notepad|notepad\+\+|devenv|idea64|pycharm64)\b/, { Icon: FileCode, kind: 'editor', tint: C.blue }],
  [/^(svchost|services|lsm|winlogon|csrss|smss|wininit|taskhostw|runtimebroker|dllhost|searchindexer)\b/, { Icon: Cpu, kind: 'Windows service', tint: C.slate }],
];

const FILE_RULES: [RegExp, IconSpec][] = [
  [/\.(exe|dll|scr|msi|com|sys)$/, { Icon: Bug, kind: 'executable', tint: C.red }],
  [/\.(ps1|psm1|bat|cmd|vbs|js|jse|hta|py|sh|lnk)$/, { Icon: FileCode, kind: 'script / shortcut', tint: C.purple }],
  [/\.(zip|7z|rar|tar|gz|tgz|iso|img|cab)$/, { Icon: FileArchive, kind: 'archive', tint: C.orange }],
  [/\.(xlsx?|xlsm|csv|ods)$/, { Icon: FileSpreadsheet, kind: 'spreadsheet', tint: C.green }],
  [/\.(docx?|docm|rtf|odt|txt|md)$/, { Icon: FileText, kind: 'document', tint: C.blue }],
  [/\.(pptx?|pptm|odp)$/, { Icon: Presentation, kind: 'presentation', tint: C.orange }],
  [/\.(pdf)$/, { Icon: FileText, kind: 'PDF', tint: C.red }],
  [/\.(png|jpe?g|gif|bmp|svg|webp)$/, { Icon: FileImage, kind: 'image', tint: C.teal }],
  [/\.(locked|encrypted|enc|crypt|ransom)$/, { Icon: FileLock, kind: 'encrypted file', tint: C.red }],
  [/\.(kdbx|pfx|pem|key|ppk)$/, { Icon: KeyRound, kind: 'secret / key', tint: C.red }],
];

const DOMAIN_RULES: [RegExp, IconSpec][] = [
  [/(outlook\.office|office365|outlook\.com|mail\.google|gmail|protonmail|mail\.yahoo)/, { Icon: Mail, kind: 'email service', tint: C.blue }],
  [/(s3\.amazonaws|s3-|blob\.core\.windows|storage\.googleapis|dropbox|drive\.google|onedrive|sharepoint|box\.com|mega\.nz|transfer\.sh|file\.io|wetransfer)/, { Icon: CloudUpload, kind: 'cloud storage', tint: C.red }],
  [/(amazonaws|azure|googleapis|cloudflare)/, { Icon: Cloud, kind: 'cloud service', tint: C.teal }],
  [/(teams\.microsoft|slack\.com|zoom\.us|discord)/, { Icon: MessagesSquare, kind: 'chat service', tint: C.purple }],
];

const HOST_SERVER = /(^|[-_.])(srv|server|dc\d*|sql|db|fs|file|share|app\d*|web|exch|jump|bastion|vault|esx|hv)([-_.\d]|$)/i;

function processImage(node: SecurityNode): string {
  const raw = node.details?.Image || node.name.split(' @ ')[0] || node.name;
  return (raw.split(/[\\/]/).pop() || raw).toLowerCase().replace(/\.exe$/, '');
}

export function iconFor(node: SecurityNode): IconSpec {
  const name = node.name.toLowerCase();
  switch (node.type) {
    case 'user':
      if (node.classification === 'Group' || /admins|administrators|group/.test(name)) return { Icon: Users, kind: 'group', tint: C.orange };
      if (node.isPrivileged || node.isServiceAccount) return { Icon: UserCog, kind: 'privileged identity', tint: C.purple };
      return { Icon: User, kind: 'identity', tint: C.blue };
    case 'host':
      return HOST_SERVER.test(name) ? { Icon: Server, kind: 'server', tint: C.slate } : /laptop|book|thinkpad|nb-|lt-/.test(name) ? { Icon: Laptop, kind: 'workstation', tint: C.blue } : { Icon: Monitor, kind: 'host', tint: C.blue };
    case 'ip':
      return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(name) ? { Icon: Router, kind: 'internal IP', tint: C.slate } : { Icon: Network, kind: 'external IP', tint: C.orange };
    case 'domain':
      for (const [re, spec] of DOMAIN_RULES) if (re.test(name)) return spec;
      return { Icon: Globe, kind: 'domain', tint: C.teal };
    case 'application':
      if (/mail|exchange|outlook|gmail/.test(name)) return { Icon: Mail, kind: 'mail app', tint: C.blue };
      if (/db|sql|database|postgres|oracle|payroll|hr/.test(name)) return { Icon: Database, kind: 'database', tint: C.purple };
      if (/vault|secret|kms|keychain/.test(name)) return { Icon: KeyRound, kind: 'secrets store', tint: C.red };
      return { Icon: AppWindow, kind: 'application', tint: C.teal };
    case 'file':
      for (const [re, spec] of FILE_RULES) if (re.test(name)) return spec;
      return { Icon: FileText, kind: 'file', tint: C.slate };
    case 'process': {
      const img = processImage(node);
      for (const [re, spec] of PROCESS_RULES) if (re.test(img)) return spec;
      if (/\.(pdf|docx?|xlsx?|jpg)\.exe$/.test(node.name.toLowerCase()) || /invoice|payload|dropper/.test(img)) return { Icon: Bug, kind: 'suspicious program', tint: C.red };
      return { Icon: Package, kind: 'program', tint: C.slate };
    }
    case 'alert':
      return /critical|high/i.test(node.details?.Severity || '') ? { Icon: Siren, kind: 'alert', tint: C.red } : { Icon: ShieldAlert, kind: 'alert', tint: C.orange };
    case 'query':
      return { Icon: Search, kind: 'log search', tint: C.blue };
    case 'software':
      return { Icon: PackagePlus, kind: node.classification?.includes('Removed') ? 'removed software' : 'installed software', tint: node.classification?.includes('Removed') ? C.slate : C.blue };
    case 'service':
      return { Icon: Wrench, kind: 'Windows service', tint: C.orange };
    case 'task':
      return { Icon: CalendarClock, kind: 'scheduled task', tint: C.orange };
    case 'registry':
      return { Icon: Regex, kind: /persistence|autorun/i.test(node.classification || '') ? 'autorun key' : 'registry value', tint: C.purple };
    case 'device':
      return { Icon: Usb, kind: 'removable device', tint: C.teal };
    case 'event':
      return { Icon: CircleDot, kind: 'event', tint: C.slate };
    default:
      return { Icon: Package, kind: node.type, tint: C.slate };
  }
}

// Canvas drawing: render the icon's SVG once per (icon, colour) and reuse the bitmap.
const imageCache = new Map<string, HTMLImageElement>();

export function iconImage(spec: IconSpec, color: string): HTMLImageElement {
  const key = `${spec.Icon.displayName || spec.kind}|${color}`;
  let img = imageCache.get(key);
  if (!img) {
    const svg = renderToStaticMarkup(<spec.Icon color={color} size={48} strokeWidth={2} />);
    img = new Image();
    img.src = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg.includes('xmlns') ? svg : svg.replace('<svg', '<svg xmlns="http://www.w3.org/2000/svg"'))}`;
    imageCache.set(key, img);
  }
  return img;
}

// Rounded tile with the icon, used on Attack Path cards and graph nodes
export function drawIconTile(ctx: CanvasRenderingContext2D, node: SecurityNode, x: number, y: number, size: number, opts: { tileAlpha?: number; iconColor?: string } = {}) {
  const spec = iconFor(node);
  ctx.save();
  ctx.globalAlpha *= opts.tileAlpha ?? 0.12;
  ctx.fillStyle = spec.tint;
  ctx.beginPath();
  ctx.roundRect(x, y, size, size, size * 0.28);
  ctx.fill();
  ctx.restore();
  const img = iconImage(spec, opts.iconColor || spec.tint);
  if (img.complete && img.naturalWidth) {
    const pad = size * 0.2;
    ctx.drawImage(img, x + pad, y + pad, size - 2 * pad, size - 2 * pad);
  }
  return spec;
}
