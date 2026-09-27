import React, { useEffect } from 'react';
import { Play, Pause, RotateCcw, SkipForward, SkipBack, Clock, AlertTriangle, ChevronRight, Activity } from 'lucide-react';
import { SecurityMilestone, SecurityEdge } from '../types';
import { hourToUtc } from '../api';

interface Props {
  currentHour: number; // windowHours to 0
  onChangeHour: React.Dispatch<React.SetStateAction<number>>;
  isPlaying: boolean;
  onTogglePlay: () => void;
  playbackSpeed: number;
  onChangeSpeed: (speed: number) => void;
  milestones: SecurityMilestone[];
  edges: SecurityEdge[];
  windowHours: number;
  t0?: string;
  visibleNodeCount: number;
  totalNodeCount: number;
  visibleEdgeCount: number;
}

export const TimeScrubber: React.FC<Props> = ({
  currentHour,
  onChangeHour,
  isPlaying,
  onTogglePlay,
  playbackSpeed,
  onChangeSpeed,
  milestones,
  edges,
  windowHours,
  t0,
  visibleNodeCount,
  totalNodeCount,
  visibleEdgeCount,
}) => {
  // FR-12: Play/pause at 1x, 10x, 60x, 600x speed
  useEffect(() => {
    if (!isPlaying) return;

    // Base interval adjusted for speed factor
    const baseIntervalMs = 300;
    const intervalTime = Math.max(30, Math.floor(baseIntervalMs / (playbackSpeed === 1 ? 1 : playbackSpeed === 10 ? 3 : playbackSpeed === 60 ? 6 : 10)));

    const interval = setInterval(() => {
      onChangeHour((prevHour: number) => {
        if (prevHour <= 0) {
          onTogglePlay();
          return 0;
        }
        return Math.max(0, prevHour - 1);
      });
    }, intervalTime);

    return () => clearInterval(interval);
  }, [isPlaying, playbackSpeed, onChangeHour, onTogglePlay]);

  // Keyboard Shortcuts (Section 10 Extended Spec):
  // Space play/pause, Left/Right step 1 min/hour, Shift+Left/Right jump to next risky event
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;

      if (e.code === 'Space') {
        e.preventDefault();
        onTogglePlay();
      } else if (e.key === 'ArrowRight' && !e.shiftKey) {
        e.preventDefault();
        onChangeHour((h: number) => Math.max(0, h - 1));
      } else if (e.key === 'ArrowLeft' && !e.shiftKey) {
        e.preventDefault();
        onChangeHour((h: number) => Math.min(windowHours, h + 1));
      } else if (e.key === 'ArrowRight' && e.shiftKey) {
        // Jump to next risky event
        e.preventDefault();
        const nextMilestone = [...milestones].sort((a, b) => b.hour - a.hour).find(m => m.hour < currentHour);
        if (nextMilestone) onChangeHour(nextMilestone.hour);
      } else if (e.key === 'ArrowLeft' && e.shiftKey) {
        // Jump to previous risky event
        e.preventDefault();
        const prevMilestone = [...milestones].sort((a, b) => a.hour - b.hour).find(m => m.hour > currentHour);
        if (prevMilestone) onChangeHour(prevMilestone.hour);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onTogglePlay, onChangeHour, milestones, currentHour]);

  const formatHourLabel = (h: number) => {
    const abs = hourToUtc(t0, h);
    if (h === 0) return `T-00:00 (T-0)${abs ? ` · ${abs}` : ''}`;
    return `T-${h.toString().padStart(2, '0')}:00${abs ? ` · ${abs}` : ''}`;
  };

  // FR-11: event density histogram, computed from the graph's edges (event count by hour of first activity)
  const severityRank: Record<SecurityEdge['status'], number> = { allowed: 0, blocked: 1, anomalous: 2, critical: 3 };
  const buckets = new Map<number, { count: number; rank: number }>();
  for (const e of edges) {
    const h = Math.max(1, Math.min(windowHours, e.hour));
    const b = buckets.get(h) || { count: 0, rank: 0 };
    b.count += e.eventCount;
    b.rank = Math.max(b.rank, severityRank[e.status] ?? 0);
    buckets.set(h, b);
  }
  const maxCount = Math.max(1, ...Array.from(buckets.values()).map(b => b.count));
  const histogramBars = Array.from({ length: windowHours }, (_, idx) => {
    const h = windowHours - idx;
    const b = buckets.get(h);
    const sev = !b ? 'none' : b.rank === 3 ? 'critical' : b.rank === 2 ? 'high' : 'low';
    return { hour: h, count: b?.count || 0, sev, milestone: milestones.find(item => item.hour === h) };
  });

  const jumpToNextRiskyEvent = () => {
    const nextMilestone = [...milestones].sort((a, b) => b.hour - a.hour).find(m => m.hour < currentHour);
    if (nextMilestone) onChangeHour(nextMilestone.hour);
  };

  const jumpToPrevRiskyEvent = () => {
    const prevMilestone = [...milestones].sort((a, b) => a.hour - b.hour).find(m => m.hour > currentHour);
    if (prevMilestone) onChangeHour(prevMilestone.hour);
  };

  const activeMilestone = milestones.find(m => Math.abs(m.hour - currentHour) <= 1);

  return (
    <div className="w-full bg-slate-900 border-t border-slate-800 p-4 select-none">
      {/* Top Header: Time Marker, Milestone Callout, Density Metrics */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 mb-2">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-md font-mono text-xs">
            <Clock className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-400">OFFSET:</span>
            <span className="text-cyan-300 font-semibold tabular-nums">{formatHourLabel(currentHour)}</span>
          </div>

          {activeMilestone && (
            <div className={`flex items-center gap-2 px-2.5 py-1 border rounded-md text-xs font-mono ${
              activeMilestone.severity === 'critical'
                ? 'bg-red-500/20 text-red-400 border-red-500/40'
                : 'bg-amber-500/20 text-amber-400 border-amber-500/40'
            }`}>
              <AlertTriangle className="w-3.5 h-3.5" />
              <span className="font-semibold">{activeMilestone.title}</span>
              <span className="text-slate-400">({activeMilestone.mitreTactic})</span>
            </div>
          )}
        </div>

        <div className="flex items-center gap-4 text-xs font-mono text-slate-400">
          <div>
            <span>NODES: </span>
            <span className="text-slate-200 font-semibold tabular-nums">{visibleNodeCount}</span>
            <span className="text-slate-500">/{totalNodeCount}</span>
          </div>
          <span className="text-slate-700">·</span>
          <div>
            <span>EDGES: </span>
            <span className="text-slate-200 font-semibold tabular-nums">{visibleEdgeCount}</span>
          </div>
        </div>
      </div>

      {/* FR-11: Event Density Histogram Above Slider */}
      <div className="relative w-full h-8 mb-1 flex items-end gap-[2px] px-1 bg-slate-950/60 rounded border border-slate-800/60 pt-1">
        {histogramBars.map((bar, idx) => {
          const isCurrent = bar.hour === currentHour;
          const isPastOrCurrent = currentHour <= bar.hour;
          const barHeightPct = bar.count === 0 ? 4 : Math.max(12, Math.sqrt(bar.count / maxCount) * 100);

          return (
            <div
              key={idx}
              onClick={() => onChangeHour(bar.hour)}
              title={`T-${bar.hour}:00h · ${bar.count} event(s) ${bar.milestone ? `· ${bar.milestone.title}` : ''}`}
              className="flex-1 h-full flex items-end cursor-pointer group"
            >
              <div
                className={`w-full rounded-t-[1px] transition-all ${
                  isCurrent 
                    ? 'bg-cyan-400 shadow-[0_0_8px_rgba(6,182,212,0.8)]' 
                    : bar.sev === 'critical'
                    ? isPastOrCurrent ? 'bg-red-500' : 'bg-red-950'
                    : bar.sev === 'high'
                    ? isPastOrCurrent ? 'bg-amber-500' : 'bg-amber-950'
                    : bar.sev === 'none'
                    ? 'bg-slate-800/40'
                    : isPastOrCurrent ? 'bg-slate-500' : 'bg-slate-800'
                } group-hover:bg-cyan-300`}
                style={{ height: `${barHeightPct}%` }}
              />
            </div>
          );
        })}
      </div>

      {/* Scrubber Slider Track & Milestone Pins */}
      <div className="relative w-full my-2 px-1">
        {/* Milestone Marker Pins */}
        <div className="relative w-full h-3 mb-1">
          {milestones.map((m) => {
            const leftPct = ((windowHours - m.hour) / windowHours) * 100;
            const isPassed = currentHour <= m.hour;

            return (
              <button
                key={`${m.timeLabel}-${m.title}`}
                onClick={() => onChangeHour(m.hour)}
                title={`${m.timeLabel}: ${m.title} (${m.mitreTactic})`}
                className="absolute top-0 -translate-x-1/2 flex flex-col items-center group cursor-pointer"
                style={{ left: `${leftPct}%` }}
              >
                <div 
                  className={`w-2 h-2 rounded-sm transition-all ${
                    m.severity === 'critical'
                      ? isPassed ? 'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.8)]' : 'bg-red-950 border border-red-500'
                      : isPassed ? 'bg-amber-400' : 'bg-slate-700'
                  } group-hover:scale-125`}
                />
              </button>
            );
          })}
        </div>

        {/* Chronological Range Input */}
        <input
          type="range"
          min="0"
          max={windowHours}
          step="1"
          value={windowHours - currentHour}
          onChange={(e) => onChangeHour(windowHours - Number(e.target.value))}
          className="w-full h-2 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-cyan-500 focus:outline-none"
        />

        <div className="flex justify-between text-[10px] font-mono text-slate-400 mt-1">
          {[1, 0.75, 0.5, 0.25, 0].map(f => {
            const h = Math.round(windowHours * f);
            return (
              <span key={f} className={h === 0 ? 'text-cyan-400 font-semibold' : ''} title={hourToUtc(t0, h)}>
                T-{String(h).padStart(2, '0')}:00{h === windowHours ? ' (start)' : h === 0 ? ' (T-0)' : ''}
              </span>
            );
          })}
        </div>
      </div>

      {/* Playback Controls & Speed Factor (FR-12: 1x, 10x, 60x, 600x) */}
      <div className="flex flex-wrap items-center justify-between gap-3 mt-2 pt-2 border-t border-slate-800/80">
        <div className="flex items-center gap-2">
          {/* Reset */}
          <button
            onClick={() => onChangeHour(windowHours)}
            title={`Reset to start of window (T-${windowHours}h)`}
            className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded transition-colors"
          >
            <RotateCcw className="w-4 h-4" />
          </button>

          {/* Jump Previous Risky Event (FR-12) */}
          <button
            onClick={jumpToPrevRiskyEvent}
            title="Jump to Previous Risky Event (Shift + Left)"
            className="px-2 py-1 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded text-xs font-mono transition-colors"
          >
            &lt; Prev Risk
          </button>

          {/* Main Play/Pause */}
          <button
            onClick={onTogglePlay}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-md font-mono text-xs font-semibold transition-all ${
              isPlaying
                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/50 hover:bg-amber-500/30'
                : 'bg-cyan-500 text-slate-950 hover:bg-cyan-400 shadow-[0_0_12px_rgba(6,182,212,0.4)]'
            }`}
          >
            {isPlaying ? (
              <>
                <Pause className="w-3.5 h-3.5 fill-current" />
                <span>PAUSE (Space)</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>REPLAY ATTACK (Space)</span>
              </>
            )}
          </button>

          {/* Jump Next Risky Event (FR-12) */}
          <button
            onClick={jumpToNextRiskyEvent}
            title="Jump to Next Risky Event (Shift + Right)"
            className="px-2 py-1 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded text-xs font-mono transition-colors"
          >
            Next Risk &gt;
          </button>
        </div>

        {/* FR-12: Play/pause at 1x, 10x, 60x, 600x speed */}
        <div className="flex items-center gap-1 bg-slate-950 p-1 border border-slate-800 rounded-md text-xs font-mono">
          <span className="px-2 text-slate-400 text-[11px]">SPEED:</span>
          {[1, 10, 60, 600].map((speed) => (
            <button
              key={speed}
              onClick={() => onChangeSpeed(speed)}
              className={`px-2 py-0.5 rounded transition-colors ${
                playbackSpeed === speed
                  ? 'bg-slate-800 text-cyan-300 font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {speed}x
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};
