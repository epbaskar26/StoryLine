import React, { useMemo, useState } from 'react';
import { X, Terminal, Pin, Maximize2, Activity, Copy, Check, ShieldCheck, ShieldAlert, Lightbulb, Search, ChevronDown, ChevronRight } from 'lucide-react';
import type { SecurityNode, SecurityEdge, InvestigationNote, ProcessExecution } from '../types';
import { analyzeCommand } from '../commandInsight';
import { iconFor } from '../nodeIcons';
import { fmtLocal, fmtUtc } from '../timefmt';

interface Props {
  node: SecurityNode | null;
  nodes: SecurityNode[];
  edges: SecurityEdge[];
  notes: InvestigationNote[]; // notes about this node
  onClose: () => void;
  onFilterToNodeTimeline: (nodeId: string) => void;
  onExpandNode?: (nodeId: string) => void;
  onPinNode?: (nodeId: string) => void;
  onSaveVerdict: (node: SecurityNode, verdict: 'BENIGN' | 'MALICIOUS', reason: string) => Promise<void>;
  onSaveHypothesis: (node: SecurityNode, text: string) => Promise<void>;
  onSearchEntity?: (node: SecurityNode) => void; // build a search graph around this host / IP / domain
}

function useCopy() {
  const [copied, setCopied] = useState<string | null>(null);
  const copy = (key: string, text: string) => {
    const done = () => { setCopied(key); setTimeout(() => setCopied(c => (c === key ? null : c)), 1500); };
    if (navigator.clipboard?.writeText) navigator.clipboard.writeText(text).then(done).catch(() => fallbackCopy(text) && done());
    else if (fallbackCopy(text)) done();
  };
  return { copied, copy };
}

function fallbackCopy(text: string): boolean {
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  const ok = document.execCommand('copy');
  ta.remove();
  return ok;
}

const SEV_CLASS: Record<string, string> = {
  high: 'bg-red-500/15 text-red-400 border-red-500/40',
  medium: 'bg-amber-500/15 text-amber-400 border-amber-500/40',
  low: 'bg-slate-500/15 text-slate-300 border-slate-600',
  info: 'bg-slate-500/10 text-slate-400 border-slate-700',
};

const CommandCard: React.FC<{ exec: ProcessExecution; index: number; copy: (k: string, t: string) => void; copied: string | null }> = ({ exec, index, copy, copied }) => {
  const insight = useMemo(() => analyzeCommand(exec.commandLine, { scriptBlock: exec.source?.includes('4104') }), [exec]);
  const [open, setOpen] = useState(index === 0 || insight.severity === 'high');
  return (
    <div className={`rounded-lg border ${insight.severity === 'high' ? 'border-red-500/40' : 'border-slate-800'} bg-slate-950`}>
      <button onClick={() => setOpen(o => !o)} className="w-full flex items-start gap-2 p-2 text-left">
        {open ? <ChevronDown className="w-3.5 h-3.5 mt-0.5 text-slate-500 shrink-0" /> : <ChevronRight className="w-3.5 h-3.5 mt-0.5 text-slate-500 shrink-0" />}
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5 text-[10px] font-mono text-slate-500">
            <span title={fmtUtc(exec.ts)}>{fmtLocal(exec.ts, { withSeconds: true })}</span>
            {exec.count > 1 && <span>· ran {exec.count}×</span>}
            {exec.source && <span>· {exec.source}</span>}
          </div>
          <div className={`mt-1 inline-block px-1.5 py-0.5 rounded border text-[11px] font-sans ${SEV_CLASS[insight.severity]}`}>{insight.summary}</div>
        </div>
      </button>
      {open && (
        <div className="px-2 pb-2 space-y-1.5">
          {insight.flags.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {insight.flags.map(f => (
                <span key={f.label} className={`px-1.5 py-0.5 rounded border text-[10px] font-mono ${SEV_CLASS[f.severity]}`}>{f.label}{f.ttp ? ` · ${f.ttp}` : ''}</span>
              ))}
            </div>
          )}
          {insight.decoded && (
            <div>
              <div className="flex items-center justify-between text-[10px] font-mono text-slate-500 mb-0.5">
                <span>DECODED (-EncodedCommand)</span>
                <button onClick={() => copy(`dec${index}`, insight.decoded!)} className="flex items-center gap-1 hover:text-slate-200">{copied === `dec${index}` ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}Copy</button>
              </div>
              <pre className="select-text whitespace-pre-wrap break-all text-[11px] leading-snug p-2 rounded bg-slate-900 border border-slate-800 text-amber-300 max-h-40 overflow-auto">{insight.decoded}</pre>
            </div>
          )}
          <div>
            <div className="flex items-center justify-between text-[10px] font-mono text-slate-500 mb-0.5">
              <span>{exec.source?.includes('4104') ? 'SCRIPT BLOCK' : 'FULL COMMAND LINE'} ({exec.commandLine.length} chars)</span>
              <button onClick={() => copy(`cmd${index}`, exec.commandLine)} className="flex items-center gap-1 hover:text-slate-200">{copied === `cmd${index}` ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}Copy</button>
            </div>
            <pre data-testid="full-command" className="select-text whitespace-pre-wrap break-all text-[11px] leading-snug p-2 rounded bg-slate-900 border border-slate-800 text-slate-200 max-h-48 overflow-auto">{exec.commandLine}</pre>
          </div>
          {(exec.parent || exec.user) && (
            <div className="text-[10px] font-mono text-slate-500 select-text break-all">
              {exec.parent && <>Parent: <span className="text-slate-300">{exec.parent}</span> </>}
              {exec.user && <>· User: <span className="text-slate-300">{exec.user}</span></>}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export const NodeDetailDrawer: React.FC<Props> = ({
  node, nodes, edges, notes, onClose, onFilterToNodeTimeline, onExpandNode, onPinNode, onSaveVerdict, onSaveHypothesis, onSearchEntity,
}) => {
  const [hypothesis, setHypothesis] = useState('');
  const [hypState, setHypState] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle');
  const [verdictDraft, setVerdictDraft] = useState<'BENIGN' | 'MALICIOUS' | null>(null);
  const [verdictReason, setVerdictReason] = useState('');
  const [verdictState, setVerdictState] = useState<'idle' | 'saving' | 'error'>('idle');
  const [verdictError, setVerdictError] = useState('');
  const { copied, copy } = useCopy();

  if (!node) return null;
  const spec = iconFor(node);
  const connectedEdges = edges.filter(e => e.source === node.id || e.target === node.id).sort((a, b) => (a.firstSeen || '').localeCompare(b.firstSeen || ''));
  const nameOf = (id: string) => nodes.find(n => n.id === id)?.name || id;
  const latestVerdict = notes.find(n => n.kind === 'VERDICT');
  const nodeNotes = notes.filter(n => n.kind === 'HYPOTHESIS' || n.kind === 'VERDICT' || n.kind === 'NOTE');

  const attributes: [string, string][] = [
    ['Name', node.name],
    ...(node.firstSeen ? [['First seen', `${fmtLocal(node.firstSeen, { withZone: true, withSeconds: true })} (${fmtUtc(node.firstSeen)})`] as [string, string]] : []),
    ...(node.lastSeen && node.lastSeen !== node.firstSeen ? [['Last seen', `${fmtLocal(node.lastSeen, { withZone: true, withSeconds: true })} (${fmtUtc(node.lastSeen)})`] as [string, string]] : []),
    ['Baseline', node.firstSeenInBaseline === undefined ? 'not available' : node.firstSeenInBaseline ? 'seen before' : 'FIRST SEEN'],
    ...Object.entries(node.details).filter(([, v]) => v),
    ['Node id', node.id],
  ];
  const allText = attributes.map(([k, v]) => `${k}: ${v}`).join('\n');

  const saveHypothesis = async () => {
    if (!hypothesis.trim()) return;
    setHypState('saving');
    try {
      await onSaveHypothesis(node, hypothesis.trim());
      setHypothesis('');
      setHypState('saved');
      setTimeout(() => setHypState('idle'), 2500);
    } catch {
      setHypState('error');
    }
  };

  const saveVerdict = async () => {
    if (!verdictDraft) return;
    if (!verdictReason.trim()) { setVerdictError('Add a short reason: it is saved in the notes and the audit log.'); return; }
    setVerdictState('saving');
    setVerdictError('');
    try {
      await onSaveVerdict(node, verdictDraft, verdictReason.trim());
      setVerdictDraft(null);
      setVerdictReason('');
      setVerdictState('idle');
    } catch (err: any) {
      setVerdictState('error');
      setVerdictError(err.message || 'Save failed');
    }
  };

  return (
    <aside data-testid="node-drawer" className="w-80 md:w-[26rem] bg-slate-900 border-l border-slate-800 h-full flex flex-col justify-between shadow-2xl z-20 overflow-y-auto">
      <div className="p-5 space-y-4">
        {/* Header */}
        <div className="flex items-start justify-between gap-2">
          <div className="flex items-start gap-2.5 min-w-0">
            <div className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0" style={{ background: `${spec.tint}1f` }}>
              <spec.Icon className="w-5 h-5" style={{ color: spec.tint }} />
            </div>
            <div className="min-w-0">
              <h3 className="text-sm font-bold text-slate-100 font-mono break-all select-text">{node.name}</h3>
              <span className="text-[11px] text-slate-400">{spec.kind} · {node.classification || node.type}</span>
              {node.isCrownJewel && <span className="ml-1 px-1.5 py-0.5 rounded text-[9px] font-mono bg-purple-500/20 text-purple-300 border border-purple-500/40">CROWN JEWEL</span>}
              {latestVerdict && (
                <div className={`mt-1 inline-flex items-center gap-1 px-1.5 py-0.5 rounded border text-[10px] font-mono ${latestVerdict.verdict === 'MALICIOUS' ? 'bg-red-500/15 text-red-400 border-red-500/40' : 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40'}`}>
                  {latestVerdict.verdict === 'MALICIOUS' ? <ShieldAlert className="w-3 h-3" /> : <ShieldCheck className="w-3 h-3" />}
                  {latestVerdict.verdict} · {latestVerdict.analyst} · {fmtLocal(latestVerdict.createdAt)}
                </div>
              )}
            </div>
          </div>
          <div className="flex items-center gap-1 shrink-0">
            {onPinNode && (
              <button onClick={() => onPinNode(node.id)} title="Pin / unpin node position" className={`p-1.5 rounded transition-colors ${node.pinned ? 'bg-cyan-500 text-slate-950' : 'text-slate-400 hover:bg-slate-800'}`}>
                <Pin className="w-3.5 h-3.5" />
              </button>
            )}
            <button onClick={onClose} title="Close" className="p-1.5 text-slate-400 hover:text-slate-100 hover:bg-slate-800 rounded transition-colors">
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {node.aliases && node.aliases.length > 0 && (
          <div className="p-2.5 bg-slate-950 border border-slate-800 rounded-lg">
            <span className="text-[10px] font-mono text-slate-400 block mb-1">RESOLVED ALIASES</span>
            <div className="flex flex-wrap gap-1 select-text">
              {node.aliases.map(al => <span key={al} className="px-1.5 py-0.5 bg-slate-900 border border-slate-800 rounded text-[10px] font-mono text-cyan-300">{al}</span>)}
            </div>
          </div>
        )}

        {/* Risk */}
        <div className={`p-3 rounded-lg border ${node.riskScore >= 70 ? 'bg-red-950/40 border-red-500/30' : 'bg-slate-950/60 border-slate-800'}`}>
          <div className="flex items-center justify-between text-xs font-mono mb-1.5">
            <span className="text-slate-400">RISK SCORE</span>
            <span className={`font-bold tabular-nums ${node.riskScore >= 70 ? 'text-red-400' : node.riskScore >= 40 ? 'text-amber-400' : 'text-slate-300'}`}>{node.riskScore}/100 [{node.riskBand}]</span>
          </div>
          <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
            <div className={`h-full ${node.riskScore >= 70 ? 'bg-red-500' : node.riskScore >= 40 ? 'bg-amber-400' : 'bg-slate-500'}`} style={{ width: `${node.riskScore}%` }} />
          </div>
          {node.contributingFactors && node.contributingFactors.length > 0 && (
            <div className="space-y-1.5 pt-2 mt-2 border-t border-slate-800/80">
              <span className="text-[10px] font-mono text-slate-400 block font-semibold">CONTRIBUTING FACTORS (MITRE ATT&CK)</span>
              {node.contributingFactors.map((fac, idx) => (
                <div key={idx} className="flex items-start justify-between text-[10px] font-mono bg-slate-900/80 p-1.5 rounded select-text">
                  <div>
                    <span className="text-slate-200 font-semibold">{fac.indicator}</span>
                    <span className="text-slate-400 ml-1">({fac.mitreTactic})</span>
                    <p className="text-[10px] text-slate-400 font-sans mt-0.5">{fac.description}</p>
                  </div>
                  <span className="text-red-400 font-bold ml-2">+{fac.weight}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Command lines (process nodes) */}
        {node.executions && node.executions.length > 0 && (
          <div className="space-y-1.5">
            <h4 className="text-xs font-mono text-slate-400 flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5 text-cyan-400" /> COMMAND LINES ({node.executions.length})
            </h4>
            <div className="space-y-1.5">
              {node.executions.map((ex, i) => <CommandCard key={i} exec={ex} index={i} copy={copy} copied={copied} />)}
            </div>
          </div>
        )}

        {/* Telemetry attributes: full values, selectable, copyable */}
        <div className="space-y-1.5">
          <h4 className="text-xs font-mono text-slate-400 flex items-center justify-between">
            <span className="flex items-center gap-1.5"><Terminal className="w-3.5 h-3.5 text-cyan-400" /> TELEMETRY ATTRIBUTES</span>
            <button onClick={() => copy('all', allText)} className="flex items-center gap-1 text-[10px] hover:text-slate-200" title="Copy all attributes">
              {copied === 'all' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}Copy all
            </button>
          </h4>
          <div data-testid="telemetry" className="p-2.5 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono max-h-72 overflow-y-auto divide-y divide-slate-800/40">
            {attributes.map(([key, val]) => (
              <div key={key} className="group py-1 grid grid-cols-[6.5rem_1fr_auto] gap-2 items-start">
                <span className="text-slate-400">{key}</span>
                <span className="text-slate-200 select-text whitespace-pre-wrap break-all">{val}</span>
                <button onClick={() => copy(key, val)} title={`Copy ${key}`} className="opacity-40 group-hover:opacity-100 text-slate-400 hover:text-slate-100">
                  {copied === key ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                </button>
              </div>
            ))}
          </div>
        </div>

        {/* Hypothesis */}
        <div className="space-y-1.5">
          <h4 className="text-xs font-mono text-slate-400 flex items-center justify-between">
            <span className="flex items-center gap-1.5"><Lightbulb className="w-3.5 h-3.5 text-amber-400" /> HYPOTHESIS</span>
            {hypState === 'saved' && <span className="text-[10px] text-emerald-400">Saved to notes</span>}
            {hypState === 'error' && <span className="text-[10px] text-red-400">Save failed</span>}
          </h4>
          <textarea
            data-testid="hypothesis-input"
            rows={2}
            placeholder="e.g. Encoded PowerShell looks like a download cradle; check proxy logs"
            value={hypothesis}
            onChange={e => setHypothesis(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) saveHypothesis(); }}
            className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-sans"
          />
          <div className="flex justify-end">
            <button onClick={saveHypothesis} disabled={!hypothesis.trim() || hypState === 'saving'} className="px-3 py-1 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs font-semibold disabled:opacity-40">
              {hypState === 'saving' ? 'Saving…' : 'Add hypothesis'}
            </button>
          </div>
        </div>

        {/* Verdict */}
        <div className="p-2.5 bg-slate-950/70 border border-slate-800 rounded-lg space-y-2">
          <span className="text-[10px] font-mono text-slate-400 block">ANALYST VERDICT (SAVED TO NOTES AND AUDIT LOG)</span>
          <div className="grid grid-cols-2 gap-2 text-xs">
            <button
              onClick={() => { setVerdictDraft('BENIGN'); setVerdictError(''); }}
              className={`py-1.5 rounded border font-semibold transition-colors ${verdictDraft === 'BENIGN' ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500' : 'border-slate-800 text-slate-300 hover:bg-slate-900'}`}
            >
              ✓ Mark benign
            </button>
            <button
              onClick={() => { setVerdictDraft('MALICIOUS'); setVerdictError(''); }}
              className={`py-1.5 rounded border font-semibold transition-colors ${verdictDraft === 'MALICIOUS' ? 'bg-red-500/20 text-red-400 border-red-500' : 'border-slate-800 text-slate-300 hover:bg-slate-900'}`}
            >
              ⚠ Mark malicious
            </button>
          </div>
          {verdictDraft && (
            <div data-testid="verdict-dialog" className="space-y-1.5 pt-1">
              <label className="text-[11px] text-slate-300 block">
                Why is <span className="font-semibold">{node.name}</span> {verdictDraft === 'BENIGN' ? 'benign' : 'malicious'}?
              </label>
              <textarea
                autoFocus
                rows={2}
                value={verdictReason}
                onChange={e => setVerdictReason(e.target.value)}
                placeholder={verdictDraft === 'BENIGN' ? 'e.g. Approved admin script, change ticket CHG-1234' : 'e.g. Encoded download cradle to known C2 IP'}
                className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-cyan-500"
              />
              {verdictError && <div className="text-[11px] text-red-400">{verdictError}</div>}
              <div className="flex justify-end gap-2">
                <button onClick={() => { setVerdictDraft(null); setVerdictReason(''); setVerdictError(''); }} className="px-3 py-1 rounded text-xs text-slate-300 hover:bg-slate-800">Cancel</button>
                <button onClick={saveVerdict} disabled={verdictState === 'saving'} className={`px-3 py-1 rounded text-xs font-semibold text-white disabled:opacity-50 ${verdictDraft === 'BENIGN' ? 'bg-emerald-600 hover:bg-emerald-500' : 'bg-red-600 hover:bg-red-500'}`}>
                  {verdictState === 'saving' ? 'Saving…' : 'Save verdict'}
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Notes on this entity */}
        {nodeNotes.length > 0 && (
          <div className="space-y-1.5">
            <h4 className="text-xs font-mono text-slate-400">NOTES ON THIS ENTITY ({nodeNotes.length})</h4>
            <div className="space-y-1 max-h-48 overflow-y-auto">
              {nodeNotes.map(n => (
                <div key={n.id} className="p-2 rounded border border-slate-800 bg-slate-950 text-[11px] select-text">
                  <div className="flex items-center gap-1.5 text-[10px] font-mono text-slate-500 mb-0.5">
                    <span className={`px-1 rounded ${n.kind === 'VERDICT' ? (n.verdict === 'MALICIOUS' ? 'bg-red-500/20 text-red-400' : 'bg-emerald-500/20 text-emerald-400') : 'bg-amber-500/20 text-amber-400'}`}>{n.kind === 'VERDICT' ? n.verdict : n.kind}</span>
                    <span>{n.analyst}</span>·<span>{fmtLocal(n.createdAt)}</span>
                  </div>
                  <div className="text-slate-200 whitespace-pre-wrap break-words">{n.text}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Connections */}
        <div className="space-y-1.5">
          <h4 className="text-xs font-mono text-slate-400">GRAPH CONNECTIONS ({connectedEdges.length})</h4>
          <div className="space-y-1 max-h-40 overflow-y-auto pr-1">
            {connectedEdges.map(edge => (
              <div key={edge.id} title={edge.details} className="p-1.5 bg-slate-950 border border-slate-800 rounded text-[11px] font-mono flex items-center justify-between gap-2">
                <span className="text-slate-300 truncate select-text">
                  {edge.action} {edge.source === node.id ? '→' : '←'} {nameOf(edge.source === node.id ? edge.target : edge.source)}
                </span>
                <span className="text-slate-500 shrink-0" title={fmtUtc(edge.firstSeen)}>{fmtLocal(edge.firstSeen)} · {edge.eventCount}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="p-4 border-t border-slate-800 bg-slate-950 space-y-2">
        <div className="grid grid-cols-2 gap-2 text-xs font-mono">
          {onExpandNode && (
            <button onClick={() => onExpandNode(node.id)} className="flex items-center justify-center gap-1.5 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 rounded-lg transition-colors font-semibold">
              <Maximize2 className="w-3.5 h-3.5" /> 1-Hop Pivot
            </button>
          )}
          <button onClick={() => onFilterToNodeTimeline(node.id)} className="flex items-center justify-center gap-1.5 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg transition-colors">
            <Activity className="w-3.5 h-3.5 text-cyan-400" /> Events Log
          </button>
          {onSearchEntity && ['host', 'ip', 'domain'].includes(node.type) && (
            <button onClick={() => onSearchEntity(node)} className="col-span-2 flex items-center justify-center gap-1.5 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg transition-colors">
              <Search className="w-3.5 h-3.5 text-cyan-400" /> Graph all activity on this {node.type}
            </button>
          )}
        </div>
      </div>
    </aside>
  );
};
