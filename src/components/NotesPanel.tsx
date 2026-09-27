import React, { useState } from 'react';
import { NotebookPen, Lightbulb, ShieldAlert, ShieldCheck, UserCheck, Lock, Sparkles, StickyNote } from 'lucide-react';
import type { InvestigationNote, NoteKind } from '../types';
import { fmtLocal, fmtUtc, tzLabel } from '../timefmt';

interface Props {
  notes: InvestigationNote[];
  onAddNote: (kind: 'NOTE' | 'HYPOTHESIS', text: string) => Promise<void>;
  onSelectNode: (nodeId: string) => void;
  caseRef?: string | null;
}

const KIND_META: Record<NoteKind, { label: string; cls: string; Icon: typeof NotebookPen }> = {
  NOTE: { label: 'Note', cls: 'bg-slate-500/15 text-slate-300 border-slate-600', Icon: StickyNote },
  HYPOTHESIS: { label: 'Hypothesis', cls: 'bg-amber-500/15 text-amber-400 border-amber-500/40', Icon: Lightbulb },
  VERDICT: { label: 'Verdict', cls: 'bg-red-500/15 text-red-400 border-red-500/40', Icon: ShieldAlert },
  ASSIGNMENT: { label: 'Assignment', cls: 'bg-sky-500/15 text-sky-400 border-sky-500/40', Icon: UserCheck },
  CLOSURE: { label: 'Closure', cls: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40', Icon: Lock },
  AI_STORYLINE: { label: 'AI storyline', cls: 'bg-purple-500/15 text-purple-400 border-purple-500/40', Icon: Sparkles },
};

export const NotesPanel: React.FC<Props> = ({ notes, onAddNote, onSelectNode, caseRef }) => {
  const [text, setText] = useState('');
  const [kind, setKind] = useState<'NOTE' | 'HYPOTHESIS'>('NOTE');
  const [state, setState] = useState<'idle' | 'saving' | 'error'>('idle');
  const [filter, setFilter] = useState<NoteKind | 'ALL'>('ALL');
  const shown = filter === 'ALL' ? notes : notes.filter(n => n.kind === filter);

  const save = async () => {
    if (!text.trim()) return;
    setState('saving');
    try {
      await onAddNote(kind, text.trim());
      setText('');
      setState('idle');
    } catch {
      setState('error');
    }
  };

  return (
    <div data-testid="notes-panel" className="w-full h-full overflow-y-auto p-5 space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2"><NotebookPen className="w-4 h-4 text-cyan-400" /> Investigation notes</h2>
          <p className="text-xs text-slate-400">Hypotheses, verdicts, assignment and closure for this investigation{caseRef ? ` (${caseRef})` : ''}. Notes are append-only and also written to the audit log. Times in {tzLabel()}.</p>
        </div>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl p-3 space-y-2">
        <div className="flex gap-1 text-xs">
          {(['NOTE', 'HYPOTHESIS'] as const).map(k => (
            <button key={k} onClick={() => setKind(k)} className={`px-2.5 py-1 rounded font-semibold ${kind === k ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:bg-slate-800'}`}>
              {k === 'NOTE' ? 'Note' : 'Hypothesis'}
            </button>
          ))}
        </div>
        <textarea
          data-testid="note-input"
          rows={3}
          value={text}
          onChange={e => setText(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) save(); }}
          placeholder={kind === 'HYPOTHESIS' ? 'What do you think happened, and what would confirm it?' : 'Add a note (Ctrl+Enter to save)'}
          className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-cyan-500"
        />
        <div className="flex items-center justify-between">
          <span className="text-[11px] text-red-400">{state === 'error' ? 'Save failed' : ''}</span>
          <button onClick={save} disabled={!text.trim() || state === 'saving'} className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-semibold disabled:opacity-40">
            {state === 'saving' ? 'Saving…' : `Add ${kind === 'NOTE' ? 'note' : 'hypothesis'}`}
          </button>
        </div>
      </div>

      <div className="flex flex-wrap gap-1 text-[11px]">
        {(['ALL', 'HYPOTHESIS', 'VERDICT', 'NOTE', 'ASSIGNMENT', 'CLOSURE', 'AI_STORYLINE'] as const).map(k => (
          <button key={k} onClick={() => setFilter(k)} className={`px-2 py-0.5 rounded border ${filter === k ? 'border-cyan-500 text-cyan-300' : 'border-slate-800 text-slate-400 hover:text-slate-200'}`}>
            {k === 'ALL' ? `All (${notes.length})` : `${KIND_META[k].label} (${notes.filter(n => n.kind === k).length})`}
          </button>
        ))}
      </div>

      <div className="space-y-2">
        {shown.length === 0 && <div className="text-xs text-slate-500 p-4 text-center border border-dashed border-slate-800 rounded-lg">No notes yet. Hypotheses and verdicts saved from an entity's detail panel appear here too.</div>}
        {shown.map(n => {
          const meta = KIND_META[n.kind];
          const Icon = n.kind === 'VERDICT' && n.verdict === 'BENIGN' ? ShieldCheck : meta.Icon;
          const cls = n.kind === 'VERDICT' && n.verdict === 'BENIGN' ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40' : meta.cls;
          return (
            <div key={n.id} data-testid="note-item" className="bg-slate-900 border border-slate-800 rounded-lg p-3">
              <div className="flex flex-wrap items-center gap-2 text-[11px] mb-1">
                <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded border font-semibold ${cls}`}>
                  <Icon className="w-3 h-3" />{n.kind === 'VERDICT' ? `Verdict: ${n.verdict}` : meta.label}
                </span>
                {n.nodeName && (
                  <button onClick={() => n.nodeId && onSelectNode(n.nodeId)} className="font-mono text-cyan-400 hover:underline truncate max-w-[18rem]">{n.nodeName}</button>
                )}
                <span className="text-slate-500 ml-auto" title={fmtUtc(n.createdAt)}>{n.analyst} · {fmtLocal(n.createdAt, { withZone: true })}</span>
              </div>
              <div className="text-sm text-slate-200 whitespace-pre-wrap break-words select-text">{n.text}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
