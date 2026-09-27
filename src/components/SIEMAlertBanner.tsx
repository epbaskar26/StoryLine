import React, { useState } from 'react';
import { ShieldAlert, ArrowRight, Clock, Target, Database, RefreshCw, Info } from 'lucide-react';
import { UserProfile } from '../types';

interface Props {
  userProfile: UserProfile;
  timeToContextMs: number | null; // measured: request start to graph data received
  loading: boolean;
  onRefresh?: () => void;
  onQuickReplay: () => void;
}

const SOURCE_LABEL: Record<string, { text: string; cls: string }> = {
  demo: { text: 'DEMO DATA', cls: 'bg-amber-500/20 text-amber-300 border-amber-500/40' },
  splunk: { text: 'SPLUNK (LIVE)', cls: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40' },
  elastic: { text: 'ELASTIC (LIVE)', cls: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40' },
  snapshot: { text: 'CASE SNAPSHOT', cls: 'bg-sky-500/20 text-sky-300 border-sky-500/40' },
};

export const SIEMAlertBanner: React.FC<Props> = ({ userProfile, timeToContextMs, loading, onRefresh, onQuickReplay }) => {
  const [showNotes, setShowNotes] = useState(false);
  const highRiskCount = userProfile.nodes.filter(n => n.compromised).length;
  const hasAlert = userProfile.nodes.some(n => n.type === 'alert');
  const source = SOURCE_LABEL[userProfile.dataSource || 'demo'];
  const notes = userProfile.notes || [];

  return (
    <div className="w-full bg-gradient-to-r from-red-950/40 via-slate-900 to-slate-950 border-b border-red-500/20 px-6 py-2.5 text-xs">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <span className={`px-2 py-0.5 border rounded font-mono font-semibold text-[11px] ${source.cls}`}>
            <Database className="w-3 h-3 inline mr-1" />
            {source.text}
          </span>
          <div className="flex items-center gap-1.5 px-2 py-0.5 bg-red-500/20 text-red-400 border border-red-500/30 rounded font-mono font-semibold text-[11px]">
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>{hasAlert ? 'ALERT-LINKED' : 'INVESTIGATION'}</span>
          </div>
          <div className="flex items-center gap-2 text-slate-300">
            <span className="font-semibold text-slate-100">{userProfile.alertSummary}</span>
            <span className="text-slate-600">·</span>
            <span className="text-slate-400 font-mono">
              {userProfile.fullName !== userProfile.username ? `${userProfile.fullName} (${userProfile.department})` : userProfile.username}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-4 text-xs font-mono">
          <div className="flex items-center gap-1.5 text-slate-400" title="Measured in this browser: from request to graph data received">
            <Clock className="w-3.5 h-3.5 text-cyan-400" />
            <span>Graph load: </span>
            <span className="text-cyan-400 font-bold">
              {loading ? '...' : timeToContextMs === null ? '-' : timeToContextMs < 1000 ? `${timeToContextMs} ms` : `${(timeToContextMs / 1000).toFixed(1)} s`}
            </span>
          </div>

          <span className="text-slate-700">·</span>

          <div className="flex items-center gap-1.5">
            <Target className="w-3.5 h-3.5 text-red-400" />
            <span className="text-slate-400">High-risk nodes: </span>
            <span className="text-red-400 font-bold tabular-nums">{highRiskCount}</span>
          </div>

          {notes.length > 0 && (
            <button onClick={() => setShowNotes(s => !s)} className="flex items-center gap-1 text-slate-400 hover:text-slate-200" title="Data notes and limitations">
              <Info className="w-3.5 h-3.5" />
              <span>Data notes ({notes.length})</span>
            </button>
          )}

          {onRefresh && (
            <button onClick={onRefresh} disabled={loading} className="flex items-center gap-1 text-slate-400 hover:text-slate-200 disabled:opacity-50" title="Re-query the data source">
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            </button>
          )}

          <button
            onClick={onQuickReplay}
            className="flex items-center gap-1 px-2.5 py-1 bg-red-600/30 hover:bg-red-600/50 text-red-200 border border-red-500/40 rounded transition-colors text-[11px] font-semibold"
          >
            <span>Watch Replay</span>
            <ArrowRight className="w-3 h-3" />
          </button>
        </div>
      </div>

      {showNotes && (
        <ul className="mt-2 pl-5 list-disc text-[11px] text-slate-400 font-mono space-y-0.5">
          {notes.map((n, i) => <li key={i}>{n}</li>)}
        </ul>
      )}
    </div>
  );
};
