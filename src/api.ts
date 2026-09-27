// Small fetch wrapper: JSON in and out, and server error messages surfaced as exceptions.
export async function api<T = unknown>(url: string, opts: { method?: string; body?: unknown } = {}): Promise<T> {
  const res = await fetch(url, {
    method: opts.method || 'GET',
    headers: opts.body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
  const text = await res.text();
  let data: any = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    throw new Error(`${url} returned a non-JSON response (HTTP ${res.status})`);
  }
  if (!res.ok) throw new Error(data?.error || `HTTP ${res.status}`);
  return data as T;
}

export async function sha256Hex(data: ArrayBuffer | string): Promise<string> {
  const buf = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const digest = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function formatUtc(iso?: string): string {
  if (!iso) return '-';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '-' : d.toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
}

// Absolute time for an hour offset relative to T-0
export function hourToUtc(t0: string | undefined, hour: number): string {
  if (!t0) return '';
  const ms = Date.parse(t0) - hour * 3_600_000;
  return Number.isFinite(ms) ? formatUtc(new Date(ms).toISOString()) : '';
}
