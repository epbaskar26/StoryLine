import React, { useEffect, useState } from 'react';
import { Clock, Pencil, RefreshCw, Radio, Snowflake, UserCheck, Search as SearchIcon } from 'lucide-react';
import type { CaseRecord } from '../types';
import { fmtLocal, fmtUtc, tzLabel, toLocalInput, fromLocalInput, fmtAgo, fmtDuration } from '../timefmt';

interface Props {
  windowStart?: string;
  windowEnd?: string;
  windowHours: number;
  isLive: boolean;
  isSnapshot: boolean;
  lastRefreshMs: number | null;
  loading: boolean;
  searchQuery?: string;
  demoMode: boolean;
  caseRecord: CaseRecord | null;
  onApply: (w: { t0: string; windowHours: number }) => void;
  onRequery: () => void;
  onToggleLive: () => void;
  onAssignClose: () => void;
  onExitSearch?: () => void;
}

const MAX_HOURS = 168;

export const WindowBar: React.FC<Props> = ({
  windowStart, windowEnd, windowHours, isLive, isSnapshot, lastRefreshMs, loading, searchQuery, demoMode, caseRecord,
  onApply, onRequery, onToggleLive, onAssignClose, onExitSearch,
}) => {
  const [editing, setEditing] = useState(false);
  const [start, setStart] = useState('');
  const [end, setEnd] = useState('');
  const [err, setErr] = useState('');
  const [, tick] = useState(0);

  // Refresh the "updated Ns ago" label
  useEffect(() => {
    if (!isLive) return;
    const t = setInterval(() => tick(x => x + 1), 1000);
    return () => clearInterval(t);
  }, [isLive]);

  const openEditor = () => {
    setStart(toLocalInput(windowStart));
    setEnd(toLocalInput(windowEnd));
    setErr('');
    setEditing(true);
  };

  const apply = (t0: string, hours: number) => {
    setEditing(false);
    onApply({ t0, windowHours: hours });
  };

  const applyCustom = () => {
    const s = Date.parse(fromLocalInput(start));
    const e = Date.parse(fromLocalInput(end));
    if (!Number.isFinite(s) || !Number.isFinite(e)) return setErr('Enter a start and an end time.');
    if (e <= s) return setErr('The end must be after the start.');
    const hours = Math.ceil((e - s) / 3_600_000);
    if (hours > MAX_HOURS) return setErr(`The window can be at most ${MAX_HOURS / 24} days.`);
    apply(new Date(e).toISOString(), hours);
  };

  const preset = (hours: number) => apply(new Date().toISOString(), hours);
  const statusChip = caseRecord && (
    <span data-testid="case-chip" className={`px-2 py-0.5 rounded border text-[11px] font-mono ${caseRecord.status === 'CLOSED' ? 'border-emerald-500/40 text-emerald-400 bg-emerald-500/10' : 'border-sky-500/40 text-sky-300 bg-sky-500/10'}`}>
      {caseRecord.caseRef} · {caseRecord.status}{caseRecord.assignee ? ` · ${caseRecord.assignee}` : ''}
    </span>
  );

  return (
    <div data-testid="window-bar" className="relative flex flex-wrap items-center gap-x-3 gap-y-1 px-6 py-1.5 bg-slate-900 border-b border-slate-800 text-xs">
      {searchQuery && (
        <span className="flex items-center gap-1 px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 font-mono max-w-md truncate" title={searchQuery}>
          <SearchIcon className="w-3 h-3 shrink-0" /> {searchQuery}
          {onExitSearch && <button onClick={onExitSearch} className="ml-1 hover:text-white" title="Close search graph">✕</button>}
        </span>
      )}
      <span className="flex items-center gap-1.5 text-slate-300" title={`${fmtUtc(windowStart)} → ${fmtUtc(windowEnd)}`}>
        <Clock className="w-3.5 h-3.5 text-cyan-400" />
        <span data-testid="window-range" className="font-mono">{fmtLocal(windowStart)} → {isLive ? 'now' : fmtLocal(windowEnd)} {tzLabel()}</span>
        <span className="text-slate-500">({fmtDuration(windowHours)})</span>
      </span>

      {isSnapshot ? (
        <span className="px-1.5 py-0.5 rounded border border-sky-500/40 text-sky-300 text-[10px] font-semibold">CASE SNAPSHOT</span>
      ) : isLive ? (
        <span data-testid="live-badge" className="flex items-center gap-1 px-1.5 py-0.5 rounded border border-red-500/50 text-red-400 text-[10px] font-bold">
          <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" /> LIVE{lastRefreshMs ? ` · updated ${fmtAgo(lastRefreshMs)}` : ''}
        </span>
      ) : (
        <span data-testid="frozen-badge" className="flex items-center gap-1 px-1.5 py-0.5 rounded border border-slate-700 text-slate-300 text-[10px] font-semibold" title="The window is fixed: nodes do not drop out as time passes. Re-query refreshes the same window.">
          <Snowflake className="w-3 h-3" /> FROZEN
        </span>
      )}

      {!isSnapshot && (
        <>
          <button onClick={openEditor} className="flex items-center gap-1 px-2 py-0.5 rounded text-slate-300 hover:bg-slate-800" title="Edit start and end time"><Pencil className="w-3 h-3" /> Edit window</button>
          <button data-testid="requery" onClick={onRequery} disabled={loading} className="flex items-center gap-1 px-2 py-0.5 rounded text-slate-300 hover:bg-slate-800 disabled:opacity-50" title="Run the queries again for this window">
            <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} /> Re-query
          </button>
          <button
            data-testid="live-toggle"
            onClick={onToggleLive}
            className={`flex items-center gap-1 px-2 py-0.5 rounded font-semibold ${isLive ? 'bg-red-600 text-white hover:bg-red-500' : 'text-slate-300 hover:bg-slate-800'}`}
            title={isLive ? 'Stop live mode and freeze the window at the current time' : `Follow new events: the window ends at "now" and refreshes every 30 s${demoMode ? ' (demo data does not change)' : ''}`}
          >
            <Radio className="w-3 h-3" /> {isLive ? 'Stop live' : 'Live'}
          </button>
        </>
      )}

      <span className="ml-auto flex items-center gap-2">
        {statusChip}
        <button data-testid="assign-close" onClick={onAssignClose} className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-100 border border-slate-700 font-semibold">
          <UserCheck className="w-3.5 h-3.5 text-cyan-400" /> {caseRecord?.status === 'CLOSED' ? 'Reassign / reopen' : 'Assign & Close'}
        </button>
      </span>

      {editing && (
        <div data-testid="window-editor" className="absolute left-6 top-full mt-1 z-40 w-[26rem] bg-slate-900 border border-slate-700 rounded-xl shadow-2xl p-3 space-y-2">
          <div className="flex gap-1">
            {[24, 48, 168].map(h => (
              <button key={h} onClick={() => preset(h)} className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200">Last {fmtDuration(h)}</button>
            ))}
          </div>
          <div className="grid grid-cols-2 gap-2">
            <label className="space-y-0.5">
              <span className="text-slate-400">Start ({tzLabel()})</span>
              <input data-testid="window-start" type="datetime-local" value={start} onChange={e => setStart(e.target.value)} className="w-full bg-slate-950 border border-slate-700 rounded px-2 py-1 text-slate-100" />
            </label>
            <label className="space-y-0.5">
              <span className="text-slate-400">End ({tzLabel()})</span>
              <input data-testid="window-end" type="datetime-local" value={end} onChange={e => setEnd(e.target.value)} className="w-full bg-slate-950 border border-slate-700 rounded px-2 py-1 text-slate-100" />
            </label>
          </div>
          {demoMode && <p className="text-[11px] text-amber-400">Demo data always covers 48 h ending at the chosen end time.</p>}
          {err && <p className="text-[11px] text-red-400">{err}</p>}
          <div className="flex justify-end gap-2">
            <button onClick={() => setEditing(false)} className="px-3 py-1 rounded text-slate-300 hover:bg-slate-800">Cancel</button>
            <button data-testid="window-apply" onClick={applyCustom} className="px-3 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-semibold">Apply & re-query</button>
          </div>
        </div>
      )}
    </div>
  );
};
