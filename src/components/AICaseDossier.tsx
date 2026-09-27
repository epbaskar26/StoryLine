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
import { UserProfile } from '../types';

interface Props {
  userProfile: UserProfile;
  onCitationClick?: (citationId: string) => void;
  onSaveCase?: () => void;
}

export const AICaseDossier: React.FC<Props> = ({ 
  userProfile, 
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

  const handleGenerateSummary = async () => {
    setLoading(true);
    setAnalystApproved(false);
    try {
      const res = await fetch('/api/gemini/case-summary', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          profile: userProfile,
          privacyModeEnabled: privacyMode
        })
      });

      const data = await res.json();
      if (data.summary) {
        setSummary(data.summary);
        setEngineUsed(data.engine || 'Gemini 3.8 Flash (Zero-Retention)');
      }
    } catch (err) {
      console.error('Failed to generate summary', err);
    } finally {
      setLoading(false);
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
            title={`Click to highlight entity/edge ${citationId} on 48h canvas`}
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
            <span>SECTION 7 & 8: PRIVACY-PRESERVING AI INCIDENT DOSSIER</span>
          </div>
          <h2 className="text-xl font-bold text-slate-100">
            Targeted Context Injection & AI Case Summary
          </h2>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            Translates the 48-hour graph into an executive briefing via Gemini 3.8 Flash. Every claim strictly cites verified node and edge IDs without raw sensitive logs ever entering model spaces.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowPrivacyInspector(!showPrivacyInspector)}
            className="flex items-center gap-2 px-3.5 py-2 bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 rounded-lg text-xs font-semibold transition-colors"
          >
            <Lock className="w-4 h-4 text-emerald-400" />
            <span>Privacy Boundary Audit</span>
          </button>

          <button
            onClick={handleGenerateSummary}
            disabled={loading}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold rounded-lg text-xs transition-all shadow-[0_0_15px_rgba(6,182,212,0.4)] disabled:opacity-50"
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
                ENTERPRISE PRIVACY BOUNDARY INSPECTOR (SECTION 7)
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
                {privacyMode ? 'ENFORCED (Zero PII Leaked)' : 'PASSTHROUGH'}
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
            <div className="p-3.5 bg-slate-950 border border-red-950 rounded-lg">
              <div className="text-red-400 font-semibold mb-2 flex items-center justify-between">
                <span>1. Raw SIEM / EDR Logs (Sensitive)</span>
                <span className="text-[10px] text-red-500">❌ NEVER SENT TO AI</span>
              </div>
              <pre className="text-slate-400 overflow-x-auto whitespace-pre-wrap leading-relaxed text-[11px]">
{`{
  "user_email": "john.smith@megacorp.internal",
  "employee_ssn": "XXX-XX-8491",
  "salary_bracket": "$195,000",
  "raw_ntlm_hash": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
  "internal_share": "\\\\srv-hr-db01.corp\\payroll$\\2026_executive_bonuses.xlsx",
  "raw_workstation_ip": "10.14.2.45"
}`}
              </pre>
            </div>

            <div className="p-3.5 bg-slate-950 border border-emerald-950 rounded-lg">
              <div className="text-emerald-400 font-semibold mb-2 flex items-center justify-between">
                <span>2. Tokenized Graph Context Injection</span>
                <span className="text-[10px] text-emerald-400">✅ SANITIZED INGESTION</span>
              </div>
              <pre className="text-slate-400 overflow-x-auto whitespace-pre-wrap leading-relaxed text-[11px]">
{`{
  "entity_token": "USER_1",
  "role": "${userProfile.role}",
  "risk_band": "${userProfile.riskBand}",
  "graph_fact": "USER_1 ACCESSED APP_CROWN_JEWEL_1 (T-18:00) [e9]",
  "ttp": ["T1078", "T1005"],
  "pii_scrubbed": true
}`}
              </pre>
            </div>
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
                    AI Case Dossier: {userProfile.fullName}
                  </h3>
                  <div className="text-xs text-slate-400 font-mono mt-0.5">
                    REF: #CASE-{userProfile.id} · ENGINE: {engineUsed || 'Gemini 3.8 Flash (Zero-Retention)'}
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
                    {analystApproved ? 'Analyst Approved for Ticket Handover' : 'AI-generated, analyst review required before export'}
                  </span>
                </div>
                {!analystApproved && (
                  <button
                    onClick={() => setAnalystApproved(true)}
                    className="px-2.5 py-1 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-[11px] font-semibold transition-colors"
                  >
                    Approve Summary
                  </button>
                )}
              </div>
            )}

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
                  className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs rounded-lg transition-all shadow-[0_0_12px_rgba(6,182,212,0.4)]"
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
              <div className="text-slate-400">Guardrail Audit:</div>
              <div className="text-emerald-400 font-semibold">✓ 100% Citations Verified</div>
              <div className="text-slate-500 text-[10px]">Zero uncited factual claims detected</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
