import React, { useState, useEffect } from 'react';
import { 
  Settings, 
  Database, 
  ShieldCheck, 
  Crown, 
  Users, 
  Sliders, 
  Code, 
  Terminal, 
  Check, 
  Copy,
  Cpu,
  Activity
} from 'lucide-react';

interface Props {
  userKey: string;
}

export const AdminConfigScreen: React.FC<Props> = ({ userKey }) => {
  const [config, setConfig] = useState<any>(null);
  const [auditLog, setAuditLog] = useState<any[]>([]);
  const [yaraL, setYaraL] = useState<string>('');
  const [kql, setKql] = useState<string>('');
  const [copiedYara, setCopiedYara] = useState(false);
  const [copiedKql, setCopiedKql] = useState(false);
  const [savedSettings, setSavedSettings] = useState(false);

  useEffect(() => {
    fetch('/api/admin/config')
      .then(res => res.json())
      .then(data => {
        if (data.config) setConfig(data.config);
        if (data.auditLog) setAuditLog(data.auditLog);
      });

    fetch(`/api/detection/export-rule/${userKey}`)
      .then(res => res.json())
      .then(data => {
        if (data.yaraL) setYaraL(data.yaraL);
        if (data.kql) setKql(data.kql);
      });
  }, [userKey]);

  const copyText = (txt: string, isYara: boolean) => {
    navigator.clipboard.writeText(txt);
    if (isYara) {
      setCopiedYara(true);
      setTimeout(() => setCopiedYara(false), 2000);
    } else {
      setCopiedKql(true);
      setTimeout(() => setCopiedKql(false), 2000);
    }
  };

  const handleSaveConfig = () => {
    fetch('/api/admin/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config)
    }).then(() => {
      setSavedSettings(true);
      setTimeout(() => setSavedSettings(false), 2000);
    });
  };

  return (
    <div className="w-full h-full flex flex-col p-6 space-y-6 overflow-y-auto">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs mb-1">
            <Settings className="w-4 h-4" />
            <span>SECTION 10 & 12: ADMIN CONFIGURATION & DETECTION RULES</span>
          </div>
          <h2 className="text-xl font-bold text-slate-100">
            System Administration, Connectors & Tuning
          </h2>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            Configure connector pipelines, crown jewels and VIP tags, risk scoring weights, and export edge patterns as YARA-L 2.0 or KQL detection rules for upstream SIEM/EDR tuning.
          </p>
        </div>

        {savedSettings && (
          <div className="flex items-center gap-2 px-3 py-1.5 bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 rounded-lg text-xs font-mono">
            <Check className="w-4 h-4" />
            <span>Configuration saved!</span>
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Connector Health (Section 4 & 10) */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <h3 className="text-sm font-bold text-slate-200 font-mono flex items-center gap-2">
              <Activity className="w-4 h-4 text-emerald-400" />
              <span>INGESTION PIPELINES & CONNECTOR HEALTH</span>
            </h3>
            <span className="text-xs font-mono text-slate-500">Kafka 72h buffer</span>
          </div>

          <div className="space-y-2">
            {config?.connectors?.map((conn: any, idx: number) => (
              <div key={idx} className="p-3 bg-slate-950 border border-slate-800 rounded-lg flex items-center justify-between text-xs font-mono">
                <div>
                  <span className="text-slate-200 font-semibold">{conn.name}</span>
                  <div className="text-[10px] text-slate-500">Category: {conn.type}</div>
                </div>
                <div className="text-right">
                  <span className="text-emerald-400 font-semibold">{conn.status}</span>
                  <div className="text-[10px] text-slate-400">{conn.eps} EPS · {conn.lagMs}ms lag</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Crown Jewels & VIP Entities Tagging (FR-24) */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <h3 className="text-sm font-bold text-slate-200 font-mono flex items-center gap-2">
              <Crown className="w-4 h-4 text-purple-400" />
              <span>FR-24 CROWN JEWEL & VIP ENTITY TAGS</span>
            </h3>
            <button
              onClick={handleSaveConfig}
              className="px-2.5 py-1 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold rounded text-xs transition-colors font-mono"
            >
              Save Tags
            </button>
          </div>

          <div className="space-y-3 text-xs font-mono">
            <div>
              <span className="text-slate-400 block mb-1">Crown Jewel Datastores & Bastions:</span>
              <div className="flex flex-wrap gap-1.5 p-2 bg-slate-950 rounded border border-slate-800">
                {config?.crownJewelTags?.map((tag: string, idx: number) => (
                  <span key={idx} className="px-2 py-0.5 bg-purple-950/80 text-purple-300 border border-purple-800 rounded text-[11px]">
                    👑 {tag}
                  </span>
                ))}
              </div>
            </div>

            <div>
              <span className="text-slate-400 block mb-1">VIP & Executive Monitored Identities:</span>
              <div className="flex flex-wrap gap-1.5 p-2 bg-slate-950 rounded border border-slate-800">
                {config?.vipEntities?.map((vip: string, idx: number) => (
                  <span key={idx} className="px-2 py-0.5 bg-amber-950/80 text-amber-300 border border-amber-800 rounded text-[11px]">
                    ⭐ {vip}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Detection Engineer Rules Export: YARA-L 2.0 (Section 2 & 14) */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <h3 className="text-sm font-bold text-slate-200 font-mono flex items-center gap-2">
              <Code className="w-4 h-4 text-cyan-400" />
              <span>GOOGLE SECOPS YARA-L 2.0 DETECTION RULE</span>
            </h3>
            <button
              onClick={() => copyText(yaraL, true)}
              className="flex items-center gap-1 px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-mono"
            >
              {copiedYara ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedYara ? 'Copied' : 'Copy YARA-L'}</span>
            </button>
          </div>
          <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-[11px] font-mono text-cyan-300 overflow-x-auto whitespace-pre-wrap leading-relaxed max-h-56">
            {yaraL}
          </pre>
        </div>

        {/* Detection Engineer Rules Export: Microsoft Sentinel KQL (Section 2 & 14) */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <h3 className="text-sm font-bold text-slate-200 font-mono flex items-center gap-2">
              <Code className="w-4 h-4 text-amber-400" />
              <span>MICROSOFT SENTINEL KQL DETECTION RULE</span>
            </h3>
            <button
              onClick={() => copyText(kql, false)}
              className="flex items-center gap-1 px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-mono"
            >
              {copiedKql ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedKql ? 'Copied' : 'Copy KQL'}</span>
            </button>
          </div>
          <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-[11px] font-mono text-amber-300 overflow-x-auto whitespace-pre-wrap leading-relaxed max-h-56">
            {kql}
          </pre>
        </div>
      </div>
    </div>
  );
};
