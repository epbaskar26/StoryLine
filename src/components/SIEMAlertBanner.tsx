import React from 'react';
import { ShieldAlert, Zap, AlertTriangle, ArrowRight, Clock, Target, Server } from 'lucide-react';
import { UserProfile } from '../types';

interface Props {
  userProfile: UserProfile;
  onExploreGraph: () => void;
  onQuickReplay: () => void;
}

export const SIEMAlertBanner: React.FC<Props> = ({
  userProfile,
  onExploreGraph,
  onQuickReplay,
}) => {
  const compromisedCount = userProfile.nodes.filter(n => n.compromised).length;

  return (
    <div className="w-full bg-gradient-to-r from-red-950/40 via-slate-900 to-slate-950 border-b border-red-500/20 px-6 py-2.5 flex flex-wrap items-center justify-between gap-3 text-xs">
      {/* Alert Trigger Notice */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-1.5 px-2 py-0.5 bg-red-500/20 text-red-400 border border-red-500/30 rounded font-mono font-semibold text-[11px]">
          <ShieldAlert className="w-3.5 h-3.5" />
          <span>INCOMING SIEM TRIGGER</span>
        </div>

        <div className="flex items-center gap-2 text-slate-300">
          <span className="font-semibold text-slate-100">{userProfile.alertSummary}</span>
          <span className="text-slate-600">·</span>
          <span className="text-slate-400 font-mono">User: {userProfile.fullName} ({userProfile.department})</span>
        </div>
      </div>

      {/* Value Prop & Context Acceleration Metrics */}
      <div className="flex items-center gap-4 text-xs font-mono">
        <div className="flex items-center gap-1.5 text-slate-400">
          <Clock className="w-3.5 h-3.5 text-cyan-400" />
          <span>Time-to-Context: </span>
          <span className="text-cyan-400 font-bold">32s</span>
          <span className="text-slate-400">(was 45m)</span>
        </div>

        <span className="text-slate-700">·</span>

        <div className="flex items-center gap-1.5">
          <Target className="w-3.5 h-3.5 text-red-400" />
          <span className="text-slate-400">Blast Radius: </span>
          <span className="text-red-400 font-bold tabular-nums">{compromisedCount} Compromised Nodes</span>
        </div>

        <button
          onClick={onQuickReplay}
          className="flex items-center gap-1 px-2.5 py-1 bg-red-600/30 hover:bg-red-600/50 text-red-200 border border-red-500/40 rounded transition-colors text-[11px] font-semibold"
        >
          <span>Watch Attack Replay</span>
          <ArrowRight className="w-3 h-3" />
        </button>
      </div>
    </div>
  );
};
