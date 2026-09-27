import React, { useState, useEffect } from 'react';
import { Settings, Crown, Code, Check, Copy, Activity, X, Plus, ScrollText, Sliders } from 'lucide-react';
import { AuditLogEntry } from '../types';
import { api } from '../api';

interface Props {
  userKey: string;
  windowDays: number;
  t0: string;
  onConfigSaved?: () => void;
}

interface Connector {
  id: string;
  name: string;
  type: string;
  status: string;
  simulated: boolean;
  endpoint: string;
}

interface AdminConfig {
  crownJewelTags: string[];
  vipEntities: string[];
  riskWeights: Record<string, number>;
  connectors: Connector[];
}

const TagEditor: React.FC<{ label: string; tags: string[]; onChange: (t: string[]) => void; chipClass: string; placeholder: string }> = ({ label, tags, onChange, chipClass, placeholder }) => {
  const [draft, setDraft] = useState('');
  const add = () => {
    const v = draft.trim();
    if (v && !tags.includes(v)) onChange([...tags, v]);
    setDraft('');
  };
  return (
    <div>
      <span className="text-slate-400 block mb-1">{label}</span>
      <div className="flex flex-wrap gap-1.5 p-2 bg-slate-950 rounded border border-slate-800">
        {tags.map(tag => (
          <span key={tag} className={`flex items-center gap-1 px-2 py-0.5 border rounded text-[11px] ${chipClass}`}>
            {tag}
            <button onClick={() => onChange(tags.filter(t => t !== tag))} title="Remove" className="hover:text-white">
              <X className="w-3 h-3" />
            </button>
          </span>
        ))}
        <div className="flex items-center gap-1">
          <input
            value={draft}
            onChange={e => setDraft(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && add()}
            placeholder={placeholder}
            className="bg-transparent border-b border-slate-700 text-[11px] text-slate-200 px-1 w-40 focus:outline-none focus:border-cyan-500"
          />
          <button onClick={add} className="text-cyan-400 hover:text-cyan-300" title="Add">
            <Plus className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
};

export const AdminConfigScreen: React.FC<Props> = ({ userKey, windowDays, t0, onConfigSaved }) => {
  const [config, setConfig] = useState<AdminConfig | null>(null);
  const [auditLog, setAuditLog] = useState<AuditLogEntry[]>([]);
  const [yaraL, setYaraL] = useState<string>('');
  const [kql, setKql] = useState<string>('');
  const [ruleBasis, setRuleBasis] = useState<{ user: string; targets: string[]; ttps: string[] } | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);
  const [dirty, setDirty] = useState(false);
  const [auditFilter, setAuditFilter] = useState('');

  const load = () => {
    api<{ config: AdminConfig; auditLog: AuditLogEntry[] }>('/api/admin/config')
      .then(data => {
        setConfig(data.config);
        setAuditLog(data.auditLog);
        setDirty(false);
      })
      .catch(err => setMessage({ ok: false, text: err.message }));
  };

  useEffect(load, []);

  useEffect(() => {
    const q = new URLSearchParams({ windowDays: String(windowDays) });
    if (t0) q.set('t0', t0);
    api<{ yaraL: string; kql: string; basedOn: { user: string; targets: string[]; ttps: string[] } }>(`/api/detection/export-rule/${encodeURIComponent(userKey)}?${q}`)
      .then(data => {
        setYaraL(data.yaraL);
        setKql(data.kql);
        setRuleBasis(data.basedOn);
      })
      .catch(err => setMessage({ ok: false, text: `Rule export: ${err.message}` }));
  }, [userKey, windowDays, t0]);

  const copyText = (txt: string, key: string) => {
    navigator.clipboard.writeText(txt);
    setCopied(key);
    setTimeout(() => setCopied(null), 2000);
  };

  const update = (patch: Partial<AdminConfig>) => {
    if (!config) return;
    setConfig({ ...config, ...patch });
    setDirty(true);
  };

  const handleSave = async () => {
    if (!config) return;
    try {
      await api('/api/admin/config', {
        method: 'POST',
        body: { crownJewelTags: config.crownJewelTags, vipEntities: config.vipEntities, riskWeights: config.riskWeights },
      });
      setMessage({ ok: true, text: 'Saved. Graphs are re-scored with the new settings.' });
      setDirty(false);
      load();
      onConfigSaved?.();
    } catch (err: any) {
      setMessage({ ok: false, text: err.message });
    }
  };

  const filteredAudit = auditLog.filter(a => !auditFilter || `${a.action} ${a.entityId} ${a.details} ${a.analyst}`.toLowerCase().includes(auditFilter.toLowerCase()));

  return (
    <div className="w-full h-full flex flex-col p-6 space-y-6 overflow-y-auto">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs mb-1">
            <Settings className="w-4 h-4" />
            <span>ADMIN, TAGS, SCORING & AUDIT</span>
          </div>
          <h2 className="text-xl font-bold text-slate-100">Administration</h2>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            Crown jewel and VIP tags and risk weights feed the risk engine. Detection rules below are generated from the current graph.
          </p>
        </div>
        <div className="flex items-center gap-3">
          {message && (
            <div className={`px-3 py-1.5 border rounded-lg text-xs font-mono ${message.ok ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40' : 'bg-red-500/20 text-red-300 border-red-500/40'}`}>
              {message.text}
            </div>
          )}
          <button
            onClick={handleSave}
            disabled={!dirty}
            className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold rounded text-xs transition-colors font-mono disabled:opacity-40"
          >
            Save changes
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <h3 className="text-sm font-bold text-slate-200 font-mono flex items-center gap-2 pb-2 border-b border-slate-800">
            <Crown className="w-4 h-4 text-purple-400" />
            <span>CROWN JEWEL & VIP TAGS</span>
          </h3>
          {config && (
            <div className="space-y-3 text-xs font-mono">
              <TagEditor
                label="Crown jewel assets (matched as a substring of host/app/file names):"
                tags={config.crownJewelTags}
                onChange={t => update({ crownJewelTags: t })}
                chipClass="bg-purple-950/80 text-purple-300 border-purple-800"
                placeholder="e.g. srv-hr-db01"
              />
              <TagEditor
                label="VIP identities (1.2x risk multiplier):"
                tags={config.vipEntities}
                onChange={t => update({ vipEntities: t })}
                chipClass="bg-amber-950/80 text-amber-300 border-amber-800"
                placeholder="e.g. ceo@corp.com"
              />
            </div>
          )}
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <h3 className="text-sm font-bold text-slate-200 font-mono flex items-center gap-2 pb-2 border-b border-slate-800">
            <Sliders className="w-4 h-4 text-cyan-400" />
            <span>RISK WEIGHTS (0-100)</span>
          </h3>
          {config && (
            <div className="grid grid-cols-2 gap-2 text-xs font-mono">
              {Object.entries(config.riskWeights).map(([k, v]) => (
                <label key={k} className="flex items-center justify-between gap-2 p-1.5 bg-slate-950 rounded border border-slate-800">
                  <span className="text-slate-400 truncate" title={k}>{k}</span>
                  <input
                    type="number"
                    min={0}
                    max={100}
                    step={k === 'crownJewelMultiplier' ? 0.1 : 1}
                    value={v}
                    onChange={e => update({ riskWeights: { ...config.riskWeights, [k]: Number(e.target.value) } })}
                    className="w-16 bg-slate-900 border border-slate-700 rounded px-1 text-right text-slate-200"
                  />
                </label>
              ))}
            </div>
          )}
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <h3 className="text-sm font-bold text-slate-200 font-mono flex items-center gap-2 pb-2 border-b border-slate-800">
            <Activity className="w-4 h-4 text-emerald-400" />
            <span>CONNECTORS</span>
          </h3>
          <div className="space-y-2">
            {config?.connectors?.map(conn => (
              <div key={conn.id} className="p-3 bg-slate-950 border border-slate-800 rounded-lg flex items-center justify-between text-xs font-mono">
                <div>
                  <span className="text-slate-200 font-semibold">{conn.name}</span>
                  <div className="text-[10px] text-slate-500">{conn.type} · {conn.endpoint}</div>
                </div>
                {conn.simulated ? (
                  <span className="px-1.5 py-0.5 rounded text-[10px] bg-amber-500/20 text-amber-300 border border-amber-500/40">SIMULATED</span>
                ) : (
                  <span className="text-emerald-400 font-semibold">{conn.status}</span>
                )}
              </div>
            ))}
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <h3 className="text-sm font-bold text-slate-200 font-mono flex items-center gap-2 pb-2 border-b border-slate-800">
            <ScrollText className="w-4 h-4 text-cyan-400" />
            <span>AUDIT LOG ({auditLog.length})</span>
          </h3>
          <input
            value={auditFilter}
            onChange={e => setAuditFilter(e.target.value)}
            placeholder="Filter by action, entity, analyst..."
            className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-xs text-slate-200 font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500"
          />
          <div className="max-h-72 overflow-y-auto space-y-1 text-[11px] font-mono">
            {filteredAudit.map(a => (
              <div key={a.id} className="p-1.5 bg-slate-950 border border-slate-800 rounded">
                <div className="flex justify-between gap-2">
                  <span className="text-cyan-300">{a.action}</span>
                  <span className="text-slate-500 shrink-0">{a.timestamp.replace('T', ' ').slice(0, 19)}</span>
                </div>
                <div className="text-slate-400">{a.analyst} · {a.entityId}</div>
                <div className="text-slate-300">{a.details}</div>
                {a.sha256 && <div className="text-slate-500 truncate" title={a.sha256}>sha256 {a.sha256}</div>}
              </div>
            ))}
          </div>
        </div>

        {([
          ['yara', 'GOOGLE SECOPS YARA-L 2.0 RULE', yaraL, 'text-cyan-300'],
          ['kql', 'MICROSOFT SENTINEL KQL RULE', kql, 'text-amber-300'],
        ] as const).map(([key, title, text, color]) => (
          <div key={key} className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
            <div className="flex items-center justify-between pb-2 border-b border-slate-800">
              <h3 className="text-sm font-bold text-slate-200 font-mono flex items-center gap-2">
                <Code className="w-4 h-4 text-cyan-400" />
                <span>{title}</span>
              </h3>
              <button onClick={() => copyText(text, key)} className="flex items-center gap-1 px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-mono">
                {copied === key ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied === key ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
            {ruleBasis && (
              <div className="text-[10px] font-mono text-slate-500">
                Generated for {ruleBasis.user}; targets: {ruleBasis.targets.length ? ruleBasis.targets.join(', ') : 'none flagged'}. Review and test before deploying.
              </div>
            )}
            <pre className={`p-3 bg-slate-950 border border-slate-800 rounded-lg text-[11px] font-mono ${color} overflow-x-auto whitespace-pre-wrap leading-relaxed max-h-56`}>{text}</pre>
          </div>
        ))}
      </div>
    </div>
  );
};
