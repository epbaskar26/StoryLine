import React, { useState } from 'react';
import { 
  FolderArchive, 
  ExternalLink, 
  ShieldAlert, 
  Clock, 
  FileText, 
  Video, 
  Hash, 
  Check, 
  Copy,
  Download,
  Share2
} from 'lucide-react';
import { CaseRecord } from '../types';

interface Props {
  cases: CaseRecord[];
  activeCaseId: string | null;
  onOpenCase: (caseId: string) => void;
  onExportTimelineJson: () => void;
  onExportTimelineCsv: () => void;
}

export const CaseViewScreen: React.FC<Props> = ({
  cases,
  activeCaseId,
  onOpenCase,
  onExportTimelineJson,
  onExportTimelineCsv
}) => {
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const handleCopyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  return (
    <div className="w-full h-full flex flex-col p-6 space-y-6 overflow-y-auto">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs mb-1">
            <FolderArchive className="w-4 h-4" />
            <span>CASES & EVIDENCE</span>
          </div>
          <h2 className="text-xl font-bold text-slate-100">
            Case Snapshots, Handover & Export
          </h2>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            Each case stores a snapshot of the graph as it was when saved (including expansions and annotations), the snapshot's SHA-256, registered evidence files with their hashes, and ticket handovers. Exports below apply to the graph currently open.
          </p>
        </div>

        {/* FR-21 Export Buttons */}
        <div className="flex items-center gap-3">
          <button
            onClick={onExportTimelineCsv}
            className="flex items-center gap-2 px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-semibold transition-colors"
          >
            <Download className="w-4 h-4 text-cyan-400" />
            <span>Export current graph (CSV)</span>
          </button>
          <button
            onClick={onExportTimelineJson}
            className="flex items-center gap-2 px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-semibold transition-colors"
          >
            <Download className="w-4 h-4 text-cyan-400" />
            <span>Export current graph (JSON)</span>
          </button>
        </div>
      </div>

      {/* Cases List */}
      <div className="space-y-4">
        <h3 className="text-sm font-bold text-slate-200 font-mono">
          SAVED INVESTIGATION CASES ({cases.length})
        </h3>

        <div className="space-y-3">
          {cases.map(c => (
            <div
              key={c.id}
              className={`p-5 bg-slate-900 border rounded-xl space-y-3 hover:border-slate-700 transition-colors ${c.id === activeCaseId ? 'border-cyan-600' : 'border-slate-800'}`}
            >
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-2">
                <div className="flex items-center gap-3">
                  <span className="px-2.5 py-1 bg-red-500/20 text-red-400 border border-red-500/40 rounded font-mono text-xs font-bold">
                    {c.severity} · {c.status}
                  </span>
                  <h4 className="text-sm font-bold text-slate-100 font-mono">
                    {c.caseRef}: {c.title}
                  </h4>
                  {c.dataSource === 'demo' && <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-amber-500/20 text-amber-300 border border-amber-500/40">DEMO</span>}
                  {c.id === activeCaseId && <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">CURRENT</span>}
                </div>

                <div className="flex items-center gap-3 text-xs font-mono text-slate-400">
                  <span>Analyst: {c.analyst}</span>
                  {c.assignee && <><span>·</span><span data-testid="case-assignee">Assignee: <b className="text-slate-200">{c.assignee}</b></span></>}
                  <span>·</span>
                  <span>{new Date(c.createdAt).toLocaleString()}</span>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-4 gap-4 p-3 bg-slate-950 rounded-lg text-xs font-mono text-slate-300">
                <div>
                  <span className="text-slate-500 block">Root Entity:</span>
                  <span className="font-semibold text-cyan-300">{c.rootEntity}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Graph:</span>
                  <span className="text-red-400 font-semibold">{c.compromisedCount} high-risk / {c.nodeCount} nodes · {c.windowHours}h</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Verdict / disposition:</span>
                  <span className={`font-semibold ${c.verdict === 'MALICIOUS' ? 'text-red-400' : c.verdict === 'BENIGN' ? 'text-emerald-400' : 'text-amber-400'}`}>{c.verdict || 'INVESTIGATING'}</span>
                  {c.disposition && <span className="block text-slate-400">{c.disposition.replace(/_/g, ' ').toLowerCase()}</span>}
                </div>
                <div>
                  <span className="text-slate-500 block">Ticket handovers:</span>
                  <span className="text-emerald-400 font-semibold">
                    {c.pushedTo && c.pushedTo.length > 0 ? c.pushedTo.join(', ') : 'None yet'}
                  </span>
                </div>
              </div>

              {/* SHA-256 Hash and Handover Action */}
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pt-2 border-t border-slate-800/80 text-xs font-mono">
                <div className="flex items-center gap-2 text-slate-400 truncate max-w-lg">
                  <Hash className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                  <span className="shrink-0 text-slate-500">SNAPSHOT SHA-256:</span>
                  <span className="truncate text-slate-300">{c.sha256}</span>
                  <button
                    onClick={() => handleCopyHash(c.sha256 || '')}
                    className="p-1 hover:text-slate-200 transition-colors"
                  >
                    {copiedHash === c.sha256 ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  </button>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => onOpenCase(c.id)}
                    className="px-3 py-1 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold rounded text-xs transition-colors"
                  >
                    {c.hasSnapshot ? 'Open saved snapshot' : 'Open entity'}
                  </button>
                </div>
              </div>

              {c.notes && <p className="text-xs text-slate-400">{c.notes}</p>}

              {c.status === 'CLOSED' && (
                <div className="p-2.5 rounded-lg border border-emerald-500/30 bg-emerald-500/5 text-xs">
                  <div className="font-semibold text-emerald-400">Closed {c.closedAt ? new Date(c.closedAt).toLocaleString() : ''}{c.closedBy ? ` by ${c.closedBy}` : ''}</div>
                  {c.closureNotes && <div className="text-slate-300 whitespace-pre-wrap select-text mt-0.5">{c.closureNotes}</div>}
                </div>
              )}

              {c.storyline && (
                <div className="p-2.5 rounded-lg border border-purple-500/30 bg-purple-500/5 text-xs">
                  <div className="font-semibold text-purple-300">Approved storyline · {c.storyline.engine}{c.storyline.approvedBy ? ` · approved by ${c.storyline.approvedBy}` : ''}</div>
                  <div className="text-slate-200 mt-0.5">{c.storyline.headline}</div>
                  <div className="text-slate-400">{c.storyline.phases.map(p => p.name).join(' → ')}</div>
                  <div className="text-[10px] font-mono text-slate-500 mt-0.5">sha256 {c.storyline.sha256}</div>
                </div>
              )}

              {(c.evidence || []).length > 0 && (
                <div className="pt-2 border-t border-slate-800/80 space-y-1 text-[11px] font-mono">
                  <div className="text-slate-500">REGISTERED EVIDENCE:</div>
                  {(c.evidence || []).map(ev => (
                    <div key={ev.sha256 + ev.createdAt} className="flex flex-wrap items-center gap-2 text-slate-300">
                      <Video className="w-3 h-3 text-purple-400" />
                      <span>{ev.fileName}</span>
                      <span className="text-slate-500">{ev.mimeType} · {(ev.sizeBytes / 1048576).toFixed(2)} MB · {new Date(ev.createdAt).toLocaleString()}</span>
                      <span className="text-slate-400 truncate max-w-[280px]" title={ev.sha256}>sha256 {ev.sha256}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
