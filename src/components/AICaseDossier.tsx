import React, { useState } from 'react';
import { 
  Sparkles, 
  ShieldCheck, 
  Copy, 
  Check, 
  RefreshCw, 
  Lock, 
  FileText, 
  Terminal, 
  ExternalLink,
  Save,
  CheckCircle2,
  AlertTriangle
} from 'lucide-react';
import { UserProfile, CitationAudit } from '../types';
import { api, sha256Hex } from '../api';

interface Props {
  userProfile: UserProfile;
  entityKey: string;
  aiConfigured: boolean;
  onCitationClick?: (citationId: string) => void;
  onSaveCase?: () => void;
}

export const AICaseDossier: React.FC<Props> = ({
  userProfile,
  entityKey,
  aiConfigured,
  onCitationClick,
  onSaveCase
}) => {
  const [summary, setSummary] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [engineUsed, setEngineUsed] = useState<string | null>(null);
  const [privacyMode, setPrivacyMode] = useState(true);
  const [showPrivacyInspector, setShowPrivacyInspector] = useState(false);
  const [copied, setCopied] = useState(false);
  const [analystApproved, setAnalystApproved] = useState(false);
  const [citationAudit, setCitationAudit] = useState<CitationAudit | null>(null);
  const [sentContext, setSentContext] = useState<unknown>(null);
  const [sentToModel, setSentToModel] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleGenerateSummary = async () => {
    setLoading(true);
    setAnalystApproved(false);
    setError(null);
    try {
      const data = await api<{ summary: string; engine: string; citationAudit: CitationAudit; sanitizedContext: unknown; sentToModel: boolean }>('/api/gemini/case-summary', {
        method: 'POST',
        body: { profile: userProfile, privacyModeEnabled: privacyMode, tz: Intl.DateTimeFormat().resolvedOptions().timeZone },
      });
      setSummary(data.summary);
      setEngineUsed(data.engine);
      setCitationAudit(data.citationAudit);
      setSentContext(data.sanitizedContext);
      setSentToModel(data.sentToModel);
    } catch (err: any) {
      setError(err.message || 'Failed to generate summary');
    } finally {
      setLoading(false);
    }
  };

  const handleApprove = async () => {
    if (!summary) return;
    try {
      await api('/api/ai/approve', { method: 'POST', body: { entityKey, summarySha256: await sha256Hex(summary) } });
      setAnalystApproved(true);
    } catch (err: any) {
      setError(`Approval not recorded: ${err.message}`);
    }
  };

  const copyMarkdown = () => {
    if (!summary) return;
    navigator.clipboard.writeText(summary);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Citing Node/Edge Handler (FR-18: Click citation highlights node/edge on canvas)
  const renderParagraphWithCitations = (text: string) => {
    // Matches [e1], [e4], [u_jsmith], [app_hr], etc.
    const parts = text.split(/(\[[a-zA-Z0-9_\-]+\])/g);

    return parts.map((part, pIdx) => {
      const match = part.match(/^\[([a-zA-Z0-9_\-]+)\]$/);
      if (match) {
        const citationId = match[1];
        return (
          <button
            key={pIdx}
            onClick={() => onCitationClick && onCitationClick(citationId)}
            title={`Click to highlight ${citationId} on the graph`}
            className="inline-flex items-center px-1.5 py-0.2 mx-0.5 rounded font-mono text-[11px] font-semibold bg-cyan-950/80 text-cyan-300 border border-cyan-800 hover:border-cyan-400 hover:bg-cyan-900 transition-colors"
          >
            [{citationId}]
          </button>
        );
      }
      return part;
    });
  };

  return (
    <div className="w-full h-full flex flex-col p-6 space-y-6 overflow-y-auto">
      {/* Header & Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs mb-1">
            <Sparkles className="w-4 h-4 text-cyan-400" />
            <span>PRIVACY-PRESERVING CASE SUMMARY</span>
          </div>
          <h2 className="text-xl font-bold text-slate-100">
            Targeted Context Injection & AI Case Summary
          </h2>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            {aiConfigured
              ? 'Sends a tokenized summary of the graph (no raw logs, entity names replaced by tokens) to the configured AI model, then restores the names locally. Citations are checked against the graph.'
              : 'No AI model is configured (set GEMINI_API_KEY), so the summary is generated deterministically from the graph. Nothing leaves this server.'}
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowPrivacyInspector(!showPrivacyInspector)}
            className="flex items-center gap-2 px-3.5 py-2 bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 rounded-lg text-xs font-semibold transition-colors"
          >
            <Lock className="w-4 h-4 text-emerald-400" />
            <span>Privacy Inspector</span>
          </button>

          <button
            onClick={handleGenerateSummary}
            disabled={loading}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold rounded-lg text-xs transition-all shadow-sm disabled:opacity-50"
          >
            {loading ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Synthesizing Context...</span>
              </>
            ) : (
              <>
                <Sparkles className="w-4 h-4" />
                <span>{summary ? 'Regenerate Case Dossier' : 'Generate AI Case Summary'}</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Enterprise Privacy Boundary Modal / Accordion */}
      {showPrivacyInspector && (
        <div className="bg-slate-900 border border-emerald-500/40 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-emerald-400" />
              <h3 className="text-sm font-bold text-slate-100 font-mono">
                PRIVACY BOUNDARY INSPECTOR
              </h3>
            </div>
            <div className="flex items-center gap-2 text-xs font-mono">
              <span className="text-slate-400">PII SANITIZATION:</span>
              <button
                onClick={() => setPrivacyMode(!privacyMode)}
                className={`px-2.5 py-1 rounded text-xs font-semibold ${
                  privacyMode 
                    ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40' 
                    : 'bg-red-500/20 text-red-400 border border-red-500/40'
                }`}
              >
                {privacyMode ? 'TOKENIZED' : 'PASSTHROUGH (real names sent)'}
              </button>
            </div>
          </div>

          <div className="text-xs font-mono space-y-2">
            <div className="text-slate-400">
              {sentContext
                ? sentToModel
                  ? `This is the exact payload sent to the model in the last request (${privacyMode ? 'tokenized' : 'PASSTHROUGH: real names'}):`
                  : 'Last request did not reach an AI model. This is the payload that would have been sent:'
                : 'Generate a summary to see the exact payload sent to the model.'}
            </div>
            {sentContext != null && (
              <pre className="p-3.5 bg-slate-950 border border-slate-800 rounded-lg text-slate-300 overflow-auto max-h-80 whitespace-pre-wrap leading-relaxed text-[11px]">
                {JSON.stringify(sentContext, null, 2)}
              </pre>
            )}
          </div>
        </div>
      )}

      {/* Main Dossier Content */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Dossier Markdown */}
        <div className="lg:col-span-8 bg-slate-900 border border-slate-800 rounded-xl p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-4 mb-4 border-b border-slate-800">
              <div className="flex items-center gap-3">
                <FileText className="w-5 h-5 text-cyan-400" />
                <div>
                  <h3 className="text-base font-bold text-slate-100">
                    Case Summary: {userProfile.fullName}
                  </h3>
                  <div className="text-xs text-slate-400 font-mono mt-0.5">
                    ENGINE: {engineUsed || (aiConfigured ? 'AI model (not run yet)' : 'Deterministic (no AI model configured)')}
                  </div>
                </div>
              </div>

              {summary && (
                <div className="flex items-center gap-2">
                  <button
                    onClick={copyMarkdown}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition-colors"
                  >
                    {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                    <span>{copied ? 'Copied' : 'Copy Markdown'}</span>
                  </button>
                  {onSaveCase && (
                    <button
                      onClick={onSaveCase}
                      className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold rounded-lg text-xs transition-colors"
                    >
                      <Save className="w-4 h-4" />
                      <span>Save as Case</span>
                    </button>
                  )}
                </div>
              )}
            </div>

            {/* AI Review Status Notice (Section 7 Extended Spec) */}
            {summary && (
              <div className="mb-4 p-2.5 rounded-lg border flex items-center justify-between text-xs font-mono bg-slate-950/80 border-slate-800">
                <div className="flex items-center gap-2">
                  {analystApproved ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  ) : (
                    <AlertTriangle className="w-4 h-4 text-amber-400" />
                  )}
                  <span className={analystApproved ? 'text-emerald-400 font-bold' : 'text-amber-400'}>
                    {analystApproved ? 'Approved by analyst (recorded in audit log)' : 'Generated summary: analyst review required before handover'}
                  </span>
                </div>
                {!analystApproved && (
                  <button
                    onClick={handleApprove}
                    className="px-2.5 py-1 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-[11px] font-semibold transition-colors"
                  >
                    Approve Summary
                  </button>
                )}
              </div>
            )}

            {error && <div className="mb-3 p-2.5 rounded-lg border border-red-800 bg-red-950/40 text-red-300 text-xs font-mono">{error}</div>}

            {summary ? (
              <div className="prose prose-invert max-w-none text-xs leading-relaxed space-y-3 font-sans text-slate-300">
                {summary.split('\n\n').map((paragraph, idx) => {
                  if (paragraph.startsWith('# ')) {
                    return (
                      <h2 key={idx} className="text-lg font-bold text-red-400 mt-4 mb-2 pb-1 border-b border-red-500/30">
                        {paragraph.replace('# ', '')}
                      </h2>
                    );
                  }
                  if (paragraph.startsWith('### ')) {
                    return (
                      <h4 key={idx} className="text-sm font-semibold text-cyan-300 mt-4 mb-1">
                        {paragraph.replace('### ', '')}
                      </h4>
                    );
                  }
                  if (paragraph.startsWith('- ')) {
                    return (
                      <ul key={idx} className="list-disc pl-5 space-y-1 text-slate-300">
                        {paragraph.split('\n').map((item, itemIdx) => (
                          <li key={itemIdx}>{renderParagraphWithCitations(item.replace(/^- /, ''))}</li>
                        ))}
                      </ul>
                    );
                  }
                  if (paragraph.startsWith('1. ') || paragraph.match(/^\d+\./)) {
                    return (
                      <ol key={idx} className="list-decimal pl-5 space-y-1 text-slate-300 font-mono text-[11px]">
                        {paragraph.split('\n').map((item, itemIdx) => (
                          <li key={itemIdx}>{renderParagraphWithCitations(item.replace(/^\d+\.\s*/, ''))}</li>
                        ))}
                      </ol>
                    );
                  }
                  return <p key={idx} className="text-slate-300 text-xs leading-relaxed">{renderParagraphWithCitations(paragraph)}</p>;
                })}
              </div>
            ) : (
              <div className="py-16 text-center flex flex-col items-center justify-center">
                <div className="w-12 h-12 rounded-full bg-slate-800/80 border border-slate-700 flex items-center justify-center mb-3">
                  <Sparkles className="w-6 h-6 text-cyan-400" />
                </div>
                <h4 className="text-sm font-semibold text-slate-200 mb-1">No AI Dossier Generated Yet</h4>
                <p className="text-xs text-slate-400 max-w-md mb-5">
                  Click below to generate a sanitized case summary conforming to Section 7 of the Extended Spec with strict node/edge citations.
                </p>
                <button
                  onClick={handleGenerateSummary}
                  disabled={loading}
                  className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs rounded-lg transition-all shadow-sm"
                >
                  Generate AI Case Summary Now
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Contributing Indicators & Citation Guide */}
        <div className="lg:col-span-4 space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
            <h4 className="text-xs font-mono font-semibold text-slate-200 mb-3 flex items-center gap-1.5">
              <ShieldCheck className="w-4 h-4 text-cyan-400" />
              FR-18 INTERACTIVE CITATIONS
            </h4>
            <p className="text-xs text-slate-400 mb-3">
              Clicking any citation in the summary text (e.g. <span className="font-mono text-cyan-400">[e4]</span>, <span className="font-mono text-cyan-400">[app_hr]</span>) immediately focuses and highlights that element on the 48-Hour Graph Canvas.
            </p>
            <div className="p-2.5 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono space-y-1">
              <div className="text-slate-400">Citation check (last summary):</div>
              {!citationAudit ? (
                <div className="text-slate-500">Not run yet</div>
              ) : (
                <>
                  <div className={citationAudit.invalidCitations.length || citationAudit.uncitedLines ? 'text-amber-400 font-semibold' : 'text-emerald-400 font-semibold'}>
                    {citationAudit.validCitations}/{citationAudit.totalCitations} citations match graph ids
                  </div>
                  <div className={citationAudit.uncitedLines ? 'text-amber-400' : 'text-slate-500'}>
                    {citationAudit.uncitedLines} uncited timeline/blast-radius line(s)
                  </div>
                  {citationAudit.invalidCitations.length > 0 && (
                    <div className="text-red-400 text-[10px]">Unknown ids: {citationAudit.invalidCitations.join(', ')}</div>
                  )}
                </>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
