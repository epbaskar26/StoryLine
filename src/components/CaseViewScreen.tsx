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
  onOpenCase: (caseId: string) => void;
  onExportTimelineJson: () => void;
  onExportTimelineCsv: () => void;
}

export const CaseViewScreen: React.FC<Props> = ({
  cases,
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
            <span>FR-19 & FR-21: CASES & FORENSIC EVIDENCE REPOSITORY</span>
          </div>
          <h2 className="text-xl font-bold text-slate-100">
            Case Snapshots, Handover & Export
          </h2>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            Cases persist beyond the 48-hour Memgraph rolling window. Each case record seals graph snapshots, SHA-256 evidence hashes, annotations, and outbound ticket links.
          </p>
        </div>

        {/* FR-21 Export Buttons */}
        <div className="flex items-center gap-3">
          <button
            onClick={onExportTimelineCsv}
            className="flex items-center gap-2 px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-semibold transition-colors"
          >
            <Download className="w-4 h-4 text-cyan-400" />
            <span>Export CSV</span>
          </button>
          <button
            onClick={onExportTimelineJson}
            className="flex items-center gap-2 px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-semibold transition-colors"
          >
            <Download className="w-4 h-4 text-cyan-400" />
            <span>Export JSON</span>
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
              className="p-5 bg-slate-900 border border-slate-800 rounded-xl space-y-3 hover:border-slate-700 transition-colors"
            >
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-2">
                <div className="flex items-center gap-3">
                  <span className="px-2.5 py-1 bg-red-500/20 text-red-400 border border-red-500/40 rounded font-mono text-xs font-bold">
                    {c.severity} · {c.status}
                  </span>
                  <h4 className="text-sm font-bold text-slate-100 font-mono">
                    {c.caseRef}: {c.title}
                  </h4>
                </div>

                <div className="flex items-center gap-3 text-xs font-mono text-slate-400">
                  <span>Analyst: {c.analyst}</span>
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
                  <span className="text-slate-500 block">Blast Radius:</span>
                  <span className="text-red-400 font-semibold">{c.compromisedCount} Compromised Nodes / {c.nodeCount} Total</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Verdict:</span>
                  <span className="text-amber-400 font-semibold">{c.verdict || 'INVESTIGATING'}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Ticket Integrations:</span>
                  <span className="text-emerald-400 font-semibold">
                    {c.pushedTo && c.pushedTo.length > 0 ? c.pushedTo.join(', ') : 'None yet'}
                  </span>
                </div>
              </div>

              {/* SHA-256 Hash and Handover Action */}
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pt-2 border-t border-slate-800/80 text-xs font-mono">
                <div className="flex items-center gap-2 text-slate-400 truncate max-w-lg">
                  <Hash className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                  <span className="shrink-0 text-slate-500">EVIDENCE SHA-256:</span>
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
                    Resume Investigation Canvas
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
