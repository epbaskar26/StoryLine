import React, { useState } from 'react';
import { X, UserCheck, Lock } from 'lucide-react';
import type { CaseRecord, Disposition } from '../types';

export interface AssignClosePayload {
  assignee: string;
  status: CaseRecord['status'];
  disposition?: Disposition;
  closureNotes?: string;
}

interface Props {
  caseRecord: CaseRecord | null; // null: a case is created on save
  defaultAssignee: string;
  investigationLabel: string;
  onCancel: () => void;
  onSave: (p: AssignClosePayload) => Promise<void>;
}

const DISPOSITIONS: { value: Disposition; label: string; hint: string }[] = [
  { value: 'TRUE_POSITIVE_MALICIOUS', label: 'True positive: malicious', hint: 'Confirmed attack or compromise' },
  { value: 'TRUE_POSITIVE_BENIGN', label: 'True positive: authorized', hint: 'Real activity, but expected (admin work, pentest)' },
  { value: 'FALSE_POSITIVE', label: 'False positive', hint: 'Detection or data was wrong' },
  { value: 'INCONCLUSIVE', label: 'Inconclusive', hint: 'Not enough data to decide' },
  { value: 'DUPLICATE', label: 'Duplicate', hint: 'Already handled in another case' },
];

export const AssignCloseDialog: React.FC<Props> = ({ caseRecord, defaultAssignee, investigationLabel, onCancel, onSave }) => {
  const [assignee, setAssignee] = useState(caseRecord?.assignee || defaultAssignee);
  const [status, setStatus] = useState<CaseRecord['status']>(caseRecord?.status === 'CLOSED' ? 'CLOSED' : 'CLOSED');
  const [disposition, setDisposition] = useState<Disposition | ''>(caseRecord?.disposition || '');
  const [closureNotes, setClosureNotes] = useState(caseRecord?.closureNotes || '');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const closing = status === 'CLOSED';

  const save = async () => {
    setError('');
    if (!assignee.trim()) return setError('Assign the investigation to someone.');
    if (closing && !disposition) return setError('Choose a disposition to close.');
    if (closing && !closureNotes.trim()) return setError('Closure notes are required: what was found and what was done.');
    setSaving(true);
    try {
      await onSave({ assignee: assignee.trim(), status, disposition: disposition || undefined, closureNotes: closureNotes.trim() || undefined });
    } catch (err: any) {
      setError(err.message || 'Save failed');
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/60 flex items-center justify-center p-4" onClick={onCancel}>
      <div data-testid="assign-close-dialog" onClick={e => e.stopPropagation()} className="w-full max-w-lg bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl">
        <div className="flex items-center justify-between px-5 py-3 border-b border-slate-800">
          <div>
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2"><UserCheck className="w-4 h-4 text-cyan-400" /> Assign & close investigation</h3>
            <p className="text-[11px] text-slate-400">{caseRecord ? `${caseRecord.caseRef} · ${investigationLabel}` : `${investigationLabel} (a case with a graph snapshot is created on save)`}</p>
          </div>
          <button onClick={onCancel} className="p-1.5 text-slate-400 hover:text-slate-100 rounded"><X className="w-4 h-4" /></button>
        </div>

        <div className="p-5 space-y-4 text-xs">
          <label className="block space-y-1">
            <span className="text-slate-300 font-semibold">Assignee</span>
            <input data-testid="assignee-input" value={assignee} onChange={e => setAssignee(e.target.value)} maxLength={100}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-500" />
          </label>

          <div className="space-y-1">
            <span className="text-slate-300 font-semibold">Status</span>
            <div className="grid grid-cols-3 gap-2">
              {(['INVESTIGATING', 'CONTAINED', 'CLOSED'] as const).map(s => (
                <button key={s} onClick={() => setStatus(s)} className={`py-1.5 rounded-lg border font-semibold ${status === s ? 'border-cyan-500 bg-cyan-500/10 text-cyan-300' : 'border-slate-800 text-slate-400 hover:bg-slate-800'}`}>
                  {s === 'INVESTIGATING' ? 'Investigating' : s === 'CONTAINED' ? 'Contained' : 'Closed'}
                </button>
              ))}
            </div>
          </div>

          {closing && (
            <>
              <div className="space-y-1">
                <span className="text-slate-300 font-semibold">Disposition</span>
                <div className="space-y-1">
                  {DISPOSITIONS.map(d => (
                    <label key={d.value} className={`flex items-start gap-2 p-2 rounded-lg border cursor-pointer ${disposition === d.value ? 'border-cyan-500 bg-cyan-500/10' : 'border-slate-800 hover:bg-slate-800/60'}`}>
                      <input type="radio" name="disposition" checked={disposition === d.value} onChange={() => setDisposition(d.value)} className="mt-0.5" />
                      <span><span className="text-slate-100 font-semibold">{d.label}</span><span className="block text-slate-400">{d.hint}</span></span>
                    </label>
                  ))}
                </div>
              </div>
              <label className="block space-y-1">
                <span className="text-slate-300 font-semibold">Closure notes</span>
                <textarea data-testid="closure-notes" rows={3} value={closureNotes} onChange={e => setClosureNotes(e.target.value)} maxLength={4000}
                  placeholder="What was found, what was done (reset, isolate, reimage), and any follow-up."
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-cyan-500" />
              </label>
            </>
          )}
          {error && <div className="text-red-400">{error}</div>}
        </div>

        <div className="flex justify-end gap-2 px-5 py-3 border-t border-slate-800">
          <button onClick={onCancel} className="px-3 py-1.5 rounded-lg text-xs text-slate-300 hover:bg-slate-800">Cancel</button>
          <button data-testid="assign-close-save" onClick={save} disabled={saving} className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white disabled:opacity-50">
            {closing && <Lock className="w-3.5 h-3.5" />}{saving ? 'Saving…' : closing ? 'Assign & close' : 'Save assignment'}
          </button>
        </div>
      </div>
    </div>
  );
};
