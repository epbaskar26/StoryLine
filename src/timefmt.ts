// Real-time labels in the analyst's own time zone (the browser's), with UTC available on hover.
const HOUR_MS = 3_600_000;

function toMs(v: number | string | undefined | null): number {
  if (v === undefined || v === null || v === '') return NaN;
  return typeof v === 'number' ? v : Date.parse(v);
}

let tzCache: string | null = null;
// Short zone name such as "IST", "GMT+5:30" or "PDT"
export function tzLabel(): string {
  if (tzCache) return tzCache;
  try {
    const part = new Intl.DateTimeFormat(undefined, { timeZoneName: 'short' }).formatToParts(new Date()).find(p => p.type === 'timeZoneName');
    tzCache = part?.value || 'local';
  } catch {
    tzCache = 'local';
  }
  return tzCache;
}

const pad = (n: number) => String(n).padStart(2, '0');
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

// "27 Sep 20:45" (local). withZone adds " IST"; withSeconds adds ":07".
export function fmtLocal(v: number | string | undefined | null, opts: { withZone?: boolean; withSeconds?: boolean; dateOnly?: boolean } = {}): string {
  const ms = toMs(v);
  if (!Number.isFinite(ms)) return '-';
  const d = new Date(ms);
  const date = `${d.getDate()} ${MONTHS[d.getMonth()]}`;
  if (opts.dateOnly) return date;
  const time = `${pad(d.getHours())}:${pad(d.getMinutes())}${opts.withSeconds ? `:${pad(d.getSeconds())}` : ''}`;
  return `${date} ${time}${opts.withZone ? ` ${tzLabel()}` : ''}`;
}

// Time only ("20:45"), for dense labels
export function fmtClock(v: number | string | undefined | null): string {
  const ms = toMs(v);
  if (!Number.isFinite(ms)) return '-';
  const d = new Date(ms);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function fmtUtc(v: number | string | undefined | null): string {
  const ms = toMs(v);
  if (!Number.isFinite(ms)) return '-';
  return new Date(ms).toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}

// Absolute local time for a scrubber position (hours before the end of the window)
export function hourToLocal(t0: string | undefined, hour: number, opts: { withZone?: boolean } = {}): string {
  const end = toMs(t0);
  if (!Number.isFinite(end)) return '';
  return fmtLocal(end - hour * HOUR_MS, opts);
}

export function hourToMs(t0: string | undefined, hour: number): number {
  const end = toMs(t0);
  return Number.isFinite(end) ? end - hour * HOUR_MS : NaN;
}

// Value for <input type="datetime-local"> in local time
export function toLocalInput(v: number | string | undefined | null): string {
  const ms = toMs(v);
  if (!Number.isFinite(ms)) return '';
  const d = new Date(ms);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

// <input type="datetime-local"> value (local) -> ISO UTC
export function fromLocalInput(v: string): string {
  if (!v) return '';
  const ms = new Date(v).getTime(); // parsed as local time
  return Number.isFinite(ms) ? new Date(ms).toISOString() : '';
}

export function fmtAgo(ms: number, now = Date.now()): string {
  const s = Math.max(0, Math.round((now - ms) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  return `${Math.round(s / 3600)}h ago`;
}

export function fmtDuration(hours: number): string {
  if (hours % 24 === 0) return `${hours / 24}d`;
  return `${hours}h`;
}
