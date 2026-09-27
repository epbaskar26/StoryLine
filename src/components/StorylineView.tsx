import React, { useEffect, useState } from 'react';
import { Sparkles, RefreshCw, ShieldAlert, ShieldQuestion, ShieldCheck, ArrowDown, ArrowRight, AlertTriangle, CheckCircle2, Info, Link2 } from 'lucide-react';
import type { Storyline, SystemStatus } from '../types';
import { fmtLocal, fmtUtc, tzLabel } from '../timefmt';

interface Props {
  storyline: Storyline | null;
  loading: boolean;
  error: string | null;
  status: SystemStatus | null;
  approvedCaseRef: string | null; // case the storyline was approved into
  onGenerate: () => void;
  onApprove: () => void;
  onCite: (edgeId: string, nodeId: string) => void;
}

const VERDICT: Record<Storyline['verdict'], { label: string; cls: string; Icon: typeof ShieldAlert }> = {
  attack: { label: 'Attack pattern', cls: 'bg-red-500/15 text-red-400 border-red-500/40', Icon: ShieldAlert },
  suspicious: { label: 'Suspicious', cls: 'bg-amber-500/15 text-amber-400 border-amber-500/40', Icon: ShieldQuestion },
  no_pattern: { label: 'No attack pattern', cls: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40', Icon: ShieldCheck },
};

const CONF: Record<string, string> = {
  high: 'bg-red-500/15 text-red-400 border-red-500/40',
  medium: 'bg-amber-500/15 text-amber-400 border-amber-500/40',
  low: 'bg-slate-500/15 text-slate-300 border-slate-600',
};

export const StorylineView: React.FC<Props> = ({ storyline, loading, error, status, approvedCaseRef, onGenerate, onApprove, onCite }) => {
  // Reveal phases one by one, so the flow builds up like the attack did
  const [revealed, setRevealed] = useState(0);
  useEffect(() => {
    setRevealed(0);
    if (!storyline) return;
    const t = setInterval(() => setRevealed(r => (r >= storyline.phases.length ? r : r + 1)), 280);
    return () => clearInterval(t);
  }, [storyline]);

  const providerNote = !status?.aiConfigured
    ? 'No AI provider is configured, so this is the rule-based storyline built from the risk indicators. Set GEMINI_API_KEY (cloud) or OLLAMA_URL (local) for an AI interpretation.'
    : `AI provider: ${status.aiProvider === 'ollama' ? 'Ollama (local, nothing leaves this machine)' : 'Gemini (tokenized input: names are replaced before sending)'} · ${status.aiModel}`;

  if (!storyline) {
    return (
      <div className="w-full h-full flex flex-col items-center justify-center p-8 text-center space-y-3">
        <Sparkles className="w-8 h-8 text-purple-400" />
        <h2 className="text-base font-bold text-slate-100">AI Storyline</h2>
        <p className="text-sm text-slate-400 max-w-xl">Groups the Attack Path into attack phases and explains each step in plain language. Every box cites a real step from the evidence; anything the model cannot cite is dropped.</p>
        <p className="text-xs text-slate-500 max-w-xl">{providerNote}</p>
        {error && <p className="text-xs text-red-400">{error}</p>}
        <button data-testid="storyline-generate" onClick={onGenerate} disabled={loading} className="flex items-center gap-2 px-4 py-2 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-sm font-semibold disabled:opacity-50">
          {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Sparkles className="w-4 h-4" />}
          {loading ? 'Building storyline…' : 'Build storyline'}
        </button>
      </div>
    );
  }

  const v = VERDICT[storyline.verdict];
  const stepCount = storyline.phases.reduce((n, p) => n + p.steps.length, 0);

  return (
    <div data-testid="storyline-view" className="w-full h-full overflow-y-auto p-5 space-y-4">
      {/* Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded border text-xs font-semibold ${v.cls}`}><v.Icon className="w-3.5 h-3.5" />{v.label}</span>
          <span className={`px-2 py-0.5 rounded border text-[11px] font-mono ${storyline.aiGenerated ? 'border-purple-500/40 text-purple-300 bg-purple-500/10' : 'border-slate-700 text-slate-300'}`}>
            {storyline.aiGenerated ? 'AI INTERPRETATION' : 'RULE-BASED'} · {storyline.engine}
          </span>
          <span className="ml-auto flex items-center gap-2">
            <button onClick={onGenerate} disabled={loading} className="flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs text-slate-300 hover:bg-slate-800 disabled:opacity-50" title="Generate again">
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} /> Regenerate
            </button>
            {approvedCaseRef ? (
              <span className="flex items-center gap-1 text-xs text-emerald-400"><CheckCircle2 className="w-3.5 h-3.5" /> Approved into {approvedCaseRef}</span>
            ) : (
              <button data-testid="storyline-approve" onClick={onApprove} className="px-3 py-1 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white" title="Freeze this storyline into the case (hash recorded in the audit log)">
                Approve & save to case
              </button>
            )}
          </span>
        </div>
        <h2 className="text-base font-bold text-slate-100">{storyline.headline}</h2>
        {storyline.summary && <p className="text-sm text-slate-300">{storyline.summary}</p>}
        <div className="text-[11px] text-slate-500 flex flex-wrap gap-x-3">
          <span>{storyline.phases.length} phase(s), {stepCount} cited step(s)</span>
          {storyline.droppedSteps > 0 && <span className="text-amber-400">{storyline.droppedSteps} step(s) dropped: the model cited steps that are not in the evidence</span>}
          <span title={fmtUtc(storyline.generatedAt)}>Generated {fmtLocal(storyline.generatedAt, { withZone: true })}</span>
          <span className="font-mono" title="SHA-256 of the storyline content">#{storyline.sha256.slice(0, 12)}</span>
        </div>
        {!storyline.aiGenerated && <div className="flex gap-1.5 text-[11px] text-slate-400"><Info className="w-3.5 h-3.5 shrink-0" />{providerNote}</div>}
        {storyline.injectionWarnings.length > 0 && (
          <div data-testid="injection-warning" className="flex gap-1.5 p-2 rounded-lg border border-red-500/40 bg-red-500/10 text-[11px] text-red-300">
            <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
            <span><b>Possible prompt injection in the logs.</b> {storyline.injectionWarnings.join('; ')}. The text was passed to the model as quoted data only; review those commands yourself.</span>
          </div>
        )}
      </div>

      {/* Flow chart */}
      {storyline.phases.length === 0 && (
        <div className="p-6 text-center text-sm text-slate-400 border border-dashed border-slate-800 rounded-xl">No attack phases: the evidence path contains routine activity only.</div>
      )}
      {/* Phases flow left to right (wrapping like text); steps inside a phase flow top to bottom */}
      <div className="flex flex-wrap items-stretch gap-y-4">
        {storyline.phases.slice(0, revealed).map((p, i) => (
          <div key={i} className="flex items-stretch animate-[fadeIn_0.3s_ease-out]">
            {i > 0 && <div className="flex items-center px-1.5"><ArrowRight className="w-5 h-5 text-slate-500" /></div>}
            <div data-testid="storyline-phase" className="w-72 bg-slate-900 border border-slate-800 rounded-xl p-3 flex flex-col">
              <div className="flex items-center gap-2 mb-1">
                <span className="w-6 h-6 rounded-full bg-cyan-600 text-white text-xs font-bold flex items-center justify-center shrink-0">{i + 1}</span>
                <span className="px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-300 text-[11px] font-semibold truncate">{p.tactic}</span>
                <span className={`ml-auto px-1.5 py-0.5 rounded border text-[10px] font-mono shrink-0 ${CONF[p.confidence]}`}>{p.confidence}</span>
              </div>
              <h3 className="text-sm font-bold text-slate-100 leading-snug">{p.name}</h3>
              {p.summary && <p className="text-[11px] text-slate-400 mb-2">{p.summary}</p>}
              <div className="space-y-0 flex-1">
                {p.steps.map((s, j) => (
                  <React.Fragment key={s.edgeId + j}>
                    {j > 0 && <div className="flex justify-center py-0.5"><ArrowDown className="w-3.5 h-3.5 text-slate-600" /></div>}
                    <div className="bg-slate-950 border border-slate-800 rounded-lg p-2.5 space-y-1">
                      <div className="flex items-center justify-between text-[10px] font-mono text-slate-500">
                        <span title={fmtUtc(s.time)}>{fmtLocal(s.time, { withSeconds: true })}</span>
                        <button onClick={() => onCite(s.edgeId, s.nodeId)} className="flex items-center gap-0.5 text-cyan-400 hover:underline" title="Show this step on the Attack Path">
                          <Link2 className="w-3 h-3" />{s.edgeId}
                        </button>
                      </div>
                      <div className="text-xs font-semibold text-slate-100">{s.title}</div>
                      <button onClick={() => onCite(s.edgeId, s.nodeId)} className="text-[11px] font-mono text-cyan-300 hover:underline break-all text-left">{s.entity}</button>
                      {s.explanation && <p className="text-[11px] text-slate-300 leading-snug">{s.explanation}</p>}
                      {s.techniques.length > 0 && (
                        <div className="flex flex-wrap gap-1">{s.techniques.map(t => <span key={t} className="px-1 py-0.5 rounded bg-slate-800 text-[10px] font-mono text-slate-300">{t}</span>)}</div>
                      )}
                    </div>
                  </React.Fragment>
                ))}
              </div>
            </div>
          </div>
        ))}
      </div>

      {(storyline.benignExplanations.length > 0 || storyline.gaps.length > 0) && revealed >= storyline.phases.length && (
        <div className="grid md:grid-cols-2 gap-3">
          {storyline.benignExplanations.length > 0 && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-3">
              <h4 className="text-xs font-bold text-emerald-400 mb-1">Possible benign explanations</h4>
              <ul className="list-disc pl-4 text-xs text-slate-300 space-y-0.5">{storyline.benignExplanations.map((b, i) => <li key={i}>{b}</li>)}</ul>
            </div>
          )}
          {storyline.gaps.length > 0 && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-3">
              <h4 className="text-xs font-bold text-amber-400 mb-1">Data gaps</h4>
              <ul className="list-disc pl-4 text-xs text-slate-300 space-y-0.5">{storyline.gaps.map((g, i) => <li key={i}>{g}</li>)}</ul>
            </div>
          )}
        </div>
      )}
      <p className="text-[11px] text-slate-500">Times in {tzLabel()}. The Attack Path stays the evidence of record; this storyline is an interpretation until an analyst approves it into a case.</p>
    </div>
  );
};
