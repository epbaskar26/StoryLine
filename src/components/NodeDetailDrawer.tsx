import React, { useState } from 'react';
import { 
  X, 
  ShieldAlert, 
  ShieldCheck, 
  Clock, 
  Activity, 
  Terminal, 
  Ban, 
  Lock, 
  FileCode, 
  Check, 
  ExternalLink,
  Laptop,
  Database,
  Globe,
  User,
  Key,
  Cloud,
  FileText,
  Tag,
  Pin,
  ChevronRight,
  Maximize2
} from 'lucide-react';
import { SecurityNode, SecurityEdge } from '../types';

interface Props {
  node: SecurityNode | null;
  nodes: SecurityNode[];
  edges: SecurityEdge[];
  onClose: () => void;
  onFilterToNodeTimeline: (nodeId: string) => void;
  onExpandNode?: (nodeId: string) => void;
  onPinNode?: (nodeId: string) => void;
  onTagVerdict?: (targetId: string, verdict: 'BENIGN' | 'MALICIOUS') => void;
  onSaveAnnotation?: (nodeId: string, text: string) => Promise<void>;
}

export const NodeDetailDrawer: React.FC<Props> = ({
  node,
  nodes,
  edges,
  onClose,
  onFilterToNodeTimeline,
  onExpandNode,
  onPinNode,
  onTagVerdict,
  onSaveAnnotation
}) => {
  const [annotationText, setAnnotationText] = useState(node?.annotation || '');
  const [annotationState, setAnnotationState] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle');
  const [verdictStatus, setVerdictStatus] = useState<'BENIGN' | 'MALICIOUS' | null>(null);

  if (!node) return null;

  const connectedEdges = edges.filter(e => e.source === node.id || e.target === node.id).sort((a, b) => b.hour - a.hour);
  const nameOf = (id: string) => nodes.find(n => n.id === id)?.name || id;

  const handleSaveAnnotation = async () => {
    if (!onSaveAnnotation) return;
    setAnnotationState('saving');
    try {
      await onSaveAnnotation(node.id, annotationText);
      setAnnotationState('saved');
      setTimeout(() => setAnnotationState('idle'), 2000);
    } catch {
      setAnnotationState('error');
    }
  };

  const handleVerdict = (v: 'BENIGN' | 'MALICIOUS') => {
    setVerdictStatus(v);
    if (onTagVerdict) onTagVerdict(node.id, v);
  };

  return (
    <aside className="w-80 md:w-96 bg-slate-900 border-l border-slate-800 h-full flex flex-col justify-between shadow-2xl z-20 select-none overflow-y-auto">
      <div className="p-5 space-y-4">
        {/* Top Header */}
        <div className="flex items-start justify-between">
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold text-slate-100 font-mono">{node.name}</h3>
              {node.isCrownJewel && (
                <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-purple-500/20 text-purple-300 border border-purple-500/40">
                  👑 CROWN JEWEL
                </span>
              )}
            </div>
            <span className="text-[11px] font-mono text-slate-400 capitalize">
              Type: {node.type} · {node.classification || 'Standard Asset'}
            </span>
          </div>

          <div className="flex items-center gap-1">
            {onPinNode && (
              <button
                onClick={() => onPinNode(node.id)}
                title="Pin / Unpin Node Position"
                className={`p-1.5 rounded transition-colors ${node.pinned ? 'bg-cyan-500 text-slate-950' : 'text-slate-400 hover:bg-slate-800'}`}
              >
                <Pin className="w-3.5 h-3.5" />
              </button>
            )}
            <button
              onClick={onClose}
              className="p-1.5 text-slate-400 hover:text-slate-100 hover:bg-slate-800 rounded transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* FR-01: Canonical Aliases Resolution Box */}
        {node.aliases && node.aliases.length > 0 && (
          <div className="p-2.5 bg-slate-950 border border-slate-800 rounded-lg">
            <span className="text-[10px] font-mono text-slate-400 block mb-1">
              RESOLVED CANONICAL ALIASES (IdP Truth):
            </span>
            <div className="flex flex-wrap gap-1">
              {node.aliases.map((al, idx) => (
                <span key={idx} className="px-1.5 py-0.5 bg-slate-900 border border-slate-800 rounded text-[10px] font-mono text-cyan-300">
                  {al}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* FR-14: Per-Entity Risk Score with Explainable Contributing Factors (Section 6) */}
        <div className={`p-3 rounded-lg border ${
          node.riskScore > 70 ? 'bg-red-950/40 border-red-500/30' : 'bg-slate-950/60 border-slate-800'
        }`}>
          <div className="flex items-center justify-between text-xs font-mono mb-1.5">
            <span className="text-slate-400">EXPLAINABLE RISK SCORE:</span>
            <span className={`font-bold tabular-nums ${
              node.riskScore > 70 ? 'text-red-400' : 'text-amber-400'
            }`}>
              {node.riskScore}/100 [{node.riskBand || 'HIGH'}]
            </span>
          </div>

          <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden mb-2">
            <div 
              className={`h-full ${node.riskScore > 70 ? 'bg-red-500' : 'bg-amber-400'}`}
              style={{ width: `${node.riskScore}%` }}
            />
          </div>

          {/* Section 6 Contributing Factors */}
          {node.contributingFactors && node.contributingFactors.length > 0 && (
            <div className="space-y-1.5 pt-2 border-t border-slate-800/80">
              <span className="text-[10px] font-mono text-slate-400 block font-semibold">
                CONTRIBUTING FACTORS (MITRE ATT&CK):
              </span>
              {node.contributingFactors.map((fac, idx) => (
                <div key={idx} className="flex items-start justify-between text-[10px] font-mono bg-slate-900/80 p-1.5 rounded">
                  <div>
                    <span className="text-slate-200 font-semibold">{fac.indicator}</span>
                    <span className="text-slate-400 ml-1">({fac.mitreTactic})</span>
                    <p className="text-[9px] text-slate-400 font-sans mt-0.5">{fac.description}</p>
                  </div>
                  <span className="text-red-400 font-bold ml-2">+{fac.weight}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Telemetry Attributes */}
        <div className="space-y-1.5">
          <h4 className="text-xs font-mono text-slate-400 flex items-center gap-1.5">
            <Terminal className="w-3.5 h-3.5 text-cyan-400" />
            TELEMETRY ATTRIBUTES
          </h4>
          <div className="p-2.5 bg-slate-950 border border-slate-800 rounded-lg space-y-1 text-xs font-mono max-h-36 overflow-y-auto">
            {node.firstSeen && (
              <div className="flex justify-between py-0.5 border-b border-slate-800/40">
                <span className="text-slate-400">First seen:</span>
                <span className="text-slate-200 text-right">{node.firstSeen.replace('T', ' ').slice(0, 16)} UTC</span>
              </div>
            )}
            <div className="flex justify-between py-0.5 border-b border-slate-800/40">
              <span className="text-slate-400">Baseline:</span>
              <span className="text-slate-200 text-right">{node.firstSeenInBaseline === undefined ? 'not available' : node.firstSeenInBaseline ? 'seen before' : 'FIRST SEEN'}</span>
            </div>
            {Object.entries(node.details).map(([key, val]) => (
              <div key={key} className="flex justify-between py-0.5 border-b border-slate-800/40 last:border-none">
                <span className="text-slate-400">{key}:</span>
                <span className="text-slate-200 text-right truncate max-w-[160px]">{val}</span>
              </div>
            ))}
          </div>
        </div>

        {/* FR-08: Persistent Node Annotation */}
        <div className="space-y-1.5">
          <h4 className="text-xs font-mono text-slate-400 flex items-center justify-between">
            <span>ANALYST ANNOTATION</span>
            {annotationState === 'saved' && <span className="text-[10px] text-emerald-400">Saved</span>}
            {annotationState === 'error' && <span className="text-[10px] text-red-400">Save failed</span>}
          </h4>
          <div className="flex gap-1.5">
            <input
              type="text"
              placeholder="Add hypothesis or context..."
              value={annotationText}
              onChange={(e) => setAnnotationText(e.target.value)}
              className="flex-1 bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono"
            />
            <button
              onClick={handleSaveAnnotation}
              disabled={annotationState === 'saving'}
              className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-mono disabled:opacity-50"
            >
              {annotationState === 'saving' ? '...' : 'Save'}
            </button>
          </div>
        </div>

        {/* FR-23: Analyst Feedback (Benign / Malicious Verdict) */}
        <div className="p-2.5 bg-slate-950/70 border border-slate-800 rounded-lg space-y-1.5">
          <span className="text-[10px] font-mono text-slate-400 block">
            ANALYST VERDICT (RECORDED IN AUDIT LOG):
          </span>
          <div className="grid grid-cols-2 gap-2 text-xs font-mono">
            <button
              onClick={() => handleVerdict('BENIGN')}
              className={`py-1 rounded border text-center font-semibold transition-colors ${
                verdictStatus === 'BENIGN'
                  ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500'
                  : 'border-slate-800 text-slate-400 hover:bg-slate-900'
              }`}
            >
              ✓ Mark Benign
            </button>
            <button
              onClick={() => handleVerdict('MALICIOUS')}
              className={`py-1 rounded border text-center font-semibold transition-colors ${
                verdictStatus === 'MALICIOUS'
                  ? 'bg-red-500/20 text-red-400 border-red-500'
                  : 'border-slate-800 text-slate-400 hover:bg-slate-900'
              }`}
            >
              ⚠ Mark Malicious
            </button>
          </div>
        </div>

        {/* Connected Edges */}
        <div className="space-y-1.5">
          <h4 className="text-xs font-mono text-slate-400 flex items-center justify-between">
            <span>GRAPH CONNECTIONS ({connectedEdges.length})</span>
          </h4>
          <div className="space-y-1 max-h-36 overflow-y-auto pr-1">
            {connectedEdges.map(edge => (
              <div key={edge.id} title={edge.details} className="p-1.5 bg-slate-950 border border-slate-800 rounded text-[11px] font-mono flex items-center justify-between gap-2">
                <span className="text-slate-300 truncate">
                  {edge.action} {edge.source === node.id ? '→' : '←'} {nameOf(edge.source === node.id ? edge.target : edge.source)}
                </span>
                <span className="text-slate-500 shrink-0">T-{edge.hour}h · {edge.eventCount}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Footer Controls: 1-Hop Expand & Filter */}
      <div className="p-4 border-t border-slate-800 bg-slate-950 space-y-2">
        {(
          <div className="grid grid-cols-2 gap-2 text-xs font-mono">
            {onExpandNode && (
              <button
                onClick={() => onExpandNode(node.id)}
                className="flex items-center justify-center gap-1.5 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 rounded-lg transition-colors font-semibold"
              >
                <Maximize2 className="w-3.5 h-3.5" />
                <span>1-Hop Pivot</span>
              </button>
            )}

            <button
              onClick={() => onFilterToNodeTimeline(node.id)}
              className="flex items-center justify-center gap-1.5 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg transition-colors"
            >
              <Activity className="w-3.5 h-3.5 text-cyan-400" />
              <span>Events Log</span>
            </button>
          </div>
        )}
      </div>
    </aside>
  );
};
