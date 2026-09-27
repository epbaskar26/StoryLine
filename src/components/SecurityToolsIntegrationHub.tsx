import React, { useState, useEffect } from 'react';
import { 
  Network, 
  Database, 
  CheckCircle2, 
  AlertCircle, 
  RefreshCw, 
  Send, 
  Radio, 
  Key, 
  ShieldCheck, 
  Clock, 
  ArrowUpRight, 
  ExternalLink,
  SlidersHorizontal,
  Server,
  Cloud,
  Lock,
  Zap,
  Globe,
  Plus,
  Terminal,
  ShieldAlert,
  Ban,
  Check,
  Code,
  Copy,
  Layers,
  ChevronRight,
  Search,
  Filter,
  Trash2,
  Share2,
  FileText
} from 'lucide-react';
import { SystemStatus } from '../types';

interface Connector {
  id: string;
  name: string;
  vendor: string;
  category: 'SIEM' | 'EDR' | 'IdP' | 'Firewall' | 'Proxy' | 'SOAR';
  status: 'CONNECTED' | 'STANDBY' | 'ERROR';
  eps: number;
  lagMs: number;
  lastSync: string;
  authType: string;
  endpoint: string;
  eventsConsumed: string;
  health: string;
  alertsBuffered: number;
  simulated?: boolean;
}

interface ContainmentLog {
  id: string;
  timestamp: string;
  action: string;
  target: string;
  tool: string;
  status: 'SIMULATED' | 'FAILED';
  latencyMs: number;
  details: string;
}

interface Props {
  currentEntity: string;
  status: SystemStatus | null;
  graphNodeCount: number;
  lastBuildMs: number | null;
  hosts: string[];
  ips: string[];
  windowDays: number;
  t0: string;
  onGraphChanged: () => void;
}

export const SecurityToolsIntegrationHub: React.FC<Props> = ({
  currentEntity,
  status,
  graphNodeCount,
  lastBuildMs,
  hosts,
  ips,
  windowDays,
  t0,
  onGraphChanged
}) => {
  const [activeSubTab, setActiveSubTab] = useState<'connectors' | 'query' | 'containment' | 'schema'>('connectors');
  const [connectors, setConnectors] = useState<Connector[]>([]);
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [testingId, setTestingId] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ id: string; success: boolean; msg: string } | null>(null);
  const [isSyncingEntity, setIsSyncingEntity] = useState(false);
  const [syncSuccessMsg, setSyncSuccessMsg] = useState<string | null>(null);

  // Webhook Simulator State
  const [showWebhookModal, setShowWebhookModal] = useState(false);
  const [webhookSource, setWebhookSource] = useState('Microsoft Sentinel');
  const [webhookAlert, setWebhookAlert] = useState('Anomalous Credential Access / Impossible Travel');
  const [webhookSeverity, setWebhookSeverity] = useState('HIGH');
  const [isDispatchingWebhook, setIsDispatchingWebhook] = useState(false);

  // Add Connector Modal State
  const [showAddModal, setShowAddModal] = useState(false);
  const [newConnName, setNewConnName] = useState('');
  const [newConnVendor, setNewConnVendor] = useState('Google Cloud');
  const [newConnCategory, setNewConnCategory] = useState<'SIEM' | 'EDR' | 'IdP' | 'Firewall' | 'Proxy' | 'SOAR'>('SIEM');
  const [newConnEndpoint, setNewConnEndpoint] = useState('https://');
  const [newConnAuth, setNewConnAuth] = useState('API Key / Bearer');

  // SIEM Query Console State
  const [queryTool, setQueryTool] = useState<'sentinel' | 'splunk' | 'chronicle'>('splunk');
  const [queryText, setQueryText] = useState(`search (user="${currentEntity}" OR Account_Name="${currentEntity}") EventCode IN (4624, 4625)
| table _time host EventCode Logon_Type src_ip`);
  const [isExecutingQuery, setIsExecutingQuery] = useState(false);
  const [queryResults, setQueryResults] = useState<any[] | null>(null);
  const [querySimulated, setQuerySimulated] = useState(false);
  const [queryError, setQueryError] = useState<string | null>(null);

  // Containment Action Center State
  const [containmentLogs, setContainmentLogs] = useState<ContainmentLog[]>([]);
  const [selectedHostToIsolate, setSelectedHostToIsolate] = useState(hosts[0] || '');
  const [isolateTool, setIsolateTool] = useState('CrowdStrike Falcon');
  const [isIsolating, setIsIsolating] = useState(false);

  const [selectedUserToRevoke, setSelectedUserToRevoke] = useState(currentEntity);
  const [revokeTool, setRevokeTool] = useState('Okta Identity Cloud');
  const [isRevoking, setIsRevoking] = useState(false);

  const [indicatorToBlock, setIndicatorToBlock] = useState(ips[0] || '');
  const [indicatorType, setIndicatorType] = useState<'ip' | 'domain'>('ip');
  const [blockTool, setBlockTool] = useState('Palo Alto Panorama');
  const [isBlocking, setIsBlocking] = useState(false);

  const [copiedText, setCopiedText] = useState<string | null>(null);

  useEffect(() => {
    fetch('/api/admin/config')
      .then(res => res.json())
      .then(data => {
        if (data.config?.connectors) {
          setConnectors(data.config.connectors);
        }
      })
      .catch(err => console.error('Failed to load connectors', err));
  }, []);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(id);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const handleTestConnection = async (connId: string) => {
    setTestingId(connId);
    setTestResult(null);
    try {
      const res = await fetch(`/api/integrations/test/${connId}`, { method: 'POST' });
      const data = await res.json();
      if (data.success) {
        setTestResult({ id: connId, success: true, msg: `${data.message} (${data.latencyMs} ms)` });
        setConnectors(prev => prev.map(c => c.id === connId ? { ...c, status: 'CONNECTED', lastSync: 'Just now' } : c));
      } else {
        setTestResult({ id: connId, success: false, msg: data.error || 'Connection failed' });
      }
    } catch (err: any) {
      setTestResult({ id: connId, success: false, msg: err.message || 'Network error' });
    } finally {
      setTestingId(null);
    }
  };

  const handleSyncEntity = async () => {
    setIsSyncingEntity(true);
    setSyncSuccessMsg(null);
    try {
      const res = await fetch('/api/integrations/sync-entity', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ entityId: currentEntity, windowDays, t0 })
      });
      const data = await res.json();
      if (data.success) {
        setSyncSuccessMsg(data.message);
        onGraphChanged();
      } else {
        setSyncSuccessMsg(`Refresh failed: ${data.error}`);
      }
    } catch (err: any) {
      console.error(err);
    } finally {
      setIsSyncingEntity(false);
    }
  };

  const handleSendSimulatedWebhook = async () => {
    setIsDispatchingWebhook(true);
    try {
      const res = await fetch('/api/integrations/webhook', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          source: webhookSource,
          alertType: webhookAlert,
          severity: webhookSeverity,
          entity: currentEntity
        })
      });
      const data = await res.json();
      if (data.success) {
        setShowWebhookModal(false);
        setSyncSuccessMsg(`Test alert ${data.alertId} sent through the webhook and attached to ${currentEntity}'s graph.`);
        onGraphChanged();
      } else {
        setSyncSuccessMsg(`Webhook rejected: ${data.error}`);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setIsDispatchingWebhook(false);
    }
  };

  const handleAddConnector = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newConnName) return;
    try {
      const res = await fetch('/api/integrations/connectors', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: newConnName,
          vendor: newConnVendor,
          category: newConnCategory,
          endpoint: newConnEndpoint,
          authType: newConnAuth
        })
      });
      const data = await res.json();
      if (data.success && data.connector) {
        setConnectors(prev => [...prev, data.connector]);
        setShowAddModal(false);
        setNewConnName('');
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleDeleteConnector = async (id: string) => {
    try {
      await fetch(`/api/integrations/connectors/${id}`, { method: 'DELETE' });
      setConnectors(prev => prev.filter(c => c.id !== id));
    } catch (err) {
      console.error(err);
    }
  };

  // Run SIEM Query
  const handleExecuteQuery = async () => {
    setIsExecutingQuery(true);
    setQueryError(null);
    try {
      const res = await fetch('/api/integrations/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tool: queryTool, query: queryText, entityId: currentEntity, windowDays, t0 })
      });
      const data = await res.json();
      if (data.success) {
        setQueryResults(data.logs);
        setQuerySimulated(!!data.simulated);
        if (data.message) setQueryError(data.message);
      } else {
        setQueryError(data.error || `HTTP ${res.status}`);
      }
    } catch (err: any) {
      setQueryError(err.message);
    } finally {
      setIsExecutingQuery(false);
    }
  };

  // Preset Queries
  const handleSetPresetQuery = (preset: 'signin' | 'lateral' | 'database' | 'powershell') => {
    if (preset === 'signin') {
      setQueryTool('sentinel');
      setQueryText(`SigninLogs
| where TimeGenerated >= ago(48h)
| where UserPrincipalName =~ "${currentEntity}@corp.com"
| where ResultType != "0"
| summarize FailedCount = count() by IPAddress, bin(TimeGenerated, 1h)
| order by TimeGenerated desc`);
    } else if (preset === 'lateral') {
      setQueryTool('sentinel');
      setQueryText(`SecurityEvent
| where TimeGenerated >= ago(48h)
| where EventID in (4624, 4625, 4672)
| where Account =~ "${currentEntity}"
| where LogonType in (3, 10)
| project TimeGenerated, Computer, Account, LogonType, IpAddress`);
    } else if (preset === 'database') {
      setQueryTool('chronicle');
      setQueryText(`principal.user.userid = "${currentEntity}"
and target.resource.name = "SRV-HR-DB01.corp"
and metadata.event_type = "USER_RESOURCE_ACCESS"
and security_result.action = "ALLOW"`);
    } else if (preset === 'powershell') {
      setQueryTool('splunk');
      setQueryText(`search sourcetype=*sysmon* EventCode=1 (Image="*powershell.exe" OR Image="*pwsh.exe") User="*${currentEntity}"
| eval is_encoded=if(match(CommandLine, "(?i)\\s-e(nc|ncodedcommand)?\\s"), "YES", "NO")
| table _time host User CommandLine is_encoded ParentImage`);
    }
  };

  // Containment Execution
  const handleIsolateHost = async () => {
    setIsIsolating(true);
    try {
      const res = await fetch('/api/integrations/contain/isolate-host', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hostId: selectedHostToIsolate, tool: isolateTool })
      });
      const data = await res.json();
      if (data.success) {
        setContainmentLogs(prev => [
          {
            id: `cont-${Date.now()}`,
            timestamp: 'Just now',
            action: 'ISOLATE_HOST',
            target: selectedHostToIsolate,
            tool: isolateTool,
            status: data.simulated ? 'SIMULATED' : 'FAILED',
            latencyMs: data.latencyMs,
            details: data.message
          },
          ...prev
        ]);
        setSyncSuccessMsg(data.message);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setIsIsolating(false);
    }
  };

  const handleRevokeUser = async () => {
    setIsRevoking(true);
    try {
      const res = await fetch('/api/integrations/contain/revoke-user', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: selectedUserToRevoke, tool: revokeTool })
      });
      const data = await res.json();
      if (data.success) {
        setContainmentLogs(prev => [
          {
            id: `cont-${Date.now()}`,
            timestamp: 'Just now',
            action: 'REVOKE_USER',
            target: selectedUserToRevoke,
            tool: revokeTool,
            status: data.simulated ? 'SIMULATED' : 'FAILED',
            latencyMs: data.latencyMs,
            details: data.message
          },
          ...prev
        ]);
        setSyncSuccessMsg(data.message);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setIsRevoking(false);
    }
  };

  const handleBlockIndicator = async () => {
    setIsBlocking(true);
    try {
      const res = await fetch('/api/integrations/contain/block-indicator', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ indicator: indicatorToBlock, type: indicatorType, tool: blockTool })
      });
      const data = await res.json();
      if (data.success) {
        setContainmentLogs(prev => [
          {
            id: `cont-${Date.now()}`,
            timestamp: 'Just now',
            action: 'BLOCK_INDICATOR',
            target: indicatorToBlock,
            tool: blockTool,
            status: data.simulated ? 'SIMULATED' : 'FAILED',
            latencyMs: data.latencyMs,
            details: data.message
          },
          ...prev
        ]);
        setSyncSuccessMsg(data.message);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setIsBlocking(false);
    }
  };

  const filteredConnectors = connectors.filter(c => selectedCategory === 'ALL' || c.category === selectedCategory);

  return (
    <div className="w-full h-full flex flex-col p-6 space-y-6 overflow-y-auto font-sans bg-slate-50 dark:bg-slate-950 text-slate-800 dark:text-slate-100 transition-colors">
      {/* Top Banner Matching Modern SaaS Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-5 border-b border-slate-200 dark:border-slate-800">
        <div>
          <div className="flex items-center gap-2 text-slate-500 dark:text-cyan-400 font-mono text-xs mb-1">
            <Network className="w-4 h-4 text-cyan-500" />
            <span className="font-semibold uppercase tracking-wider">SIEM & SECURITY ECOSYSTEM INTEGRATIONS</span>
          </div>
          <h2 className="text-2xl font-extrabold tracking-tight text-slate-900 dark:text-slate-100">
            Connected Telemetry & Security SOAR Hub
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 max-w-3xl leading-relaxed">
            {status?.splunkConfigured
              ? 'Splunk is connected and queried on demand to build graphs. Other connectors, containment actions and ticket pushes are simulated placeholders.'
              : 'No live data source is configured (demo mode). Connector cards, containment actions and non-Splunk queries are simulated placeholders.'}
          </p>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2.5">
          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-1.5 px-3 py-2 bg-white dark:bg-slate-900 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-200 border border-slate-200 dark:border-slate-700/80 rounded-lg text-xs font-semibold shadow-sm transition-all"
          >
            <Plus className="w-3.5 h-3.5 text-cyan-500" />
            <span>Add Connector</span>
          </button>

          <button
            onClick={() => setShowWebhookModal(true)}
            className="flex items-center gap-1.5 px-3 py-2 bg-white dark:bg-slate-900 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-200 border border-slate-200 dark:border-slate-700/80 rounded-lg text-xs font-semibold shadow-sm transition-all"
          >
            <Zap className="w-3.5 h-3.5 text-amber-500" />
            <span>Send Test Alert (webhook)</span>
          </button>

          <button
            onClick={handleSyncEntity}
            disabled={isSyncingEntity}
            className="flex items-center gap-2 px-3.5 py-2 bg-slate-900 hover:bg-slate-800 dark:bg-cyan-500 dark:hover:bg-cyan-400 text-white dark:text-slate-950 rounded-lg text-xs font-bold shadow-sm transition-all disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isSyncingEntity ? 'animate-spin' : ''}`} />
            <span>{isSyncingEntity ? 'Querying...' : `Re-query data (${currentEntity})`}</span>
          </button>
        </div>
      </div>

      {/* Sync Success Feedback Notice */}
      {syncSuccessMsg && (
        <div className="p-3 bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-500/40 rounded-xl flex items-center justify-between text-xs text-emerald-800 dark:text-emerald-300 font-mono shadow-sm animate-in fade-in">
          <div className="flex items-center gap-2.5">
            <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
            <span>{syncSuccessMsg}</span>
          </div>
          <button onClick={() => setSyncSuccessMsg(null)} className="text-emerald-700 dark:text-emerald-300 font-semibold hover:underline">
            ✕ Dismiss
          </button>
        </div>
      )}

      {/* Overview metrics: real values from this session */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800/80 rounded-xl p-4 shadow-sm">
          <div className="text-slate-500 dark:text-slate-400 text-[11px] font-semibold tracking-wider uppercase mb-1">Data source</div>
          <div className="text-2xl font-extrabold text-slate-900 dark:text-slate-100 font-mono">
            {status?.dataSource === 'splunk' ? 'Splunk' : 'Demo'} <span className="text-xs text-slate-500 dark:text-slate-400 font-normal"></span>
          </div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">{status?.splunkConfigured ? 'Queried on demand (no streaming ingest)' : 'Fictional dataset'}</div>
        </div>
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800/80 rounded-xl p-4 shadow-sm">
          <div className="text-slate-500 dark:text-slate-400 text-[11px] font-semibold tracking-wider uppercase mb-1">Live connectors</div>
          <div className="text-2xl font-extrabold text-slate-900 dark:text-slate-100 font-mono">
            {connectors.filter(c => !c.simulated).length} <span className="text-xs text-slate-500 dark:text-slate-400 font-normal">{`of ${connectors.length} (others simulated)`}</span>
          </div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">Only live connectors reach real systems</div>
        </div>
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800/80 rounded-xl p-4 shadow-sm">
          <div className="text-slate-500 dark:text-slate-400 text-[11px] font-semibold tracking-wider uppercase mb-1">Last graph load</div>
          <div className="text-2xl font-extrabold text-slate-900 dark:text-slate-100 font-mono">
            {lastBuildMs === null ? '-' : lastBuildMs < 1000 ? lastBuildMs : (lastBuildMs / 1000).toFixed(1)} <span className="text-xs text-slate-500 dark:text-slate-400 font-normal">{lastBuildMs === null ? '' : lastBuildMs < 1000 ? 'ms' : 's'}</span>
          </div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">Measured in this browser for the open graph</div>
        </div>
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800/80 rounded-xl p-4 shadow-sm">
          <div className="text-slate-500 dark:text-slate-400 text-[11px] font-semibold tracking-wider uppercase mb-1">Nodes in graph</div>
          <div className="text-2xl font-extrabold text-slate-900 dark:text-slate-100 font-mono">
            {graphNodeCount} <span className="text-xs text-slate-500 dark:text-slate-400 font-normal">nodes</span>
          </div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">{`Storage: ${status?.storage === 'postgres' ? 'PostgreSQL' : 'in-memory (lost on restart)'}`}</div>
        </div>
      </div>

      {/* Sub-Navigation Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-200 dark:border-slate-800 pt-2 pb-0">
        <button
          onClick={() => setActiveSubTab('connectors')}
          className={`flex items-center gap-2 px-3.5 py-2 text-xs font-semibold border-b-2 transition-all ${
            activeSubTab === 'connectors'
              ? 'border-slate-900 dark:border-cyan-400 text-slate-900 dark:text-cyan-300 font-bold'
              : 'border-transparent text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200'
          }`}
        >
          <Network className="w-3.5 h-3.5" />
          <span>Security Connectors ({connectors.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('query')}
          className={`flex items-center gap-2 px-3.5 py-2 text-xs font-semibold border-b-2 transition-all ${
            activeSubTab === 'query'
              ? 'border-slate-900 dark:border-cyan-400 text-slate-900 dark:text-cyan-300 font-bold'
              : 'border-transparent text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200'
          }`}
        >
          <Terminal className="w-3.5 h-3.5" />
          <span>SIEM Query Console (KQL / SPL / UDM)</span>
        </button>

        <button
          onClick={() => setActiveSubTab('containment')}
          className={`flex items-center gap-2 px-3.5 py-2 text-xs font-semibold border-b-2 transition-all ${
            activeSubTab === 'containment'
              ? 'border-slate-900 dark:border-cyan-400 text-slate-900 dark:text-cyan-300 font-bold'
              : 'border-transparent text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200'
          }`}
        >
          <ShieldAlert className="w-3.5 h-3.5 text-red-500" />
          <span>Containment (simulated)</span>
        </button>

        <button
          onClick={() => setActiveSubTab('schema')}
          className={`flex items-center gap-2 px-3.5 py-2 text-xs font-semibold border-b-2 transition-all ${
            activeSubTab === 'schema'
              ? 'border-slate-900 dark:border-cyan-400 text-slate-900 dark:text-cyan-300 font-bold'
              : 'border-transparent text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200'
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          <span>OCSF Normalization Mapping</span>
        </button>
      </div>

      {/* TAB 1: CONNECTORS GRID */}
      {activeSubTab === 'connectors' && (
        <div className="space-y-4">
          {/* Category Filter Segments */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-1 p-1 bg-slate-200/70 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg text-xs font-medium">
              {['ALL', 'SIEM', 'EDR', 'IdP', 'Firewall', 'Proxy'].map(cat => (
                <button
                  key={cat}
                  onClick={() => setSelectedCategory(cat)}
                  className={`px-3 py-1.5 rounded-md transition-all ${
                    selectedCategory === cat
                      ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 shadow-xs font-bold'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                  }`}
                >
                  {cat}
                </button>
              ))}
            </div>

            <span className="text-xs text-slate-500 dark:text-slate-400 font-mono">
              Showing {filteredConnectors.length} configured connectors
            </span>
          </div>

          {/* Connected Tools Cards Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filteredConnectors.map(conn => {
              const isTesting = testingId === conn.id;
              const currentResult = testResult?.id === conn.id ? testResult : null;

              return (
                <div
                  key={conn.id}
                  className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800/80 rounded-xl p-5 flex flex-col justify-between shadow-xs hover:border-slate-300 dark:hover:border-slate-700 transition-all"
                >
                  <div>
                    {/* Header */}
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-lg bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 flex items-center justify-center font-bold text-sm text-slate-700 dark:text-slate-200">
                          {conn.vendor[0]}
                        </div>
                        <div>
                          <h4 className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                            <span>{conn.name}</span>
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-500">
                              {conn.category}
                            </span>
                          </h4>
                          <div className="text-xs text-slate-500 dark:text-slate-400 font-mono">
                            Vendor: {conn.vendor}
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center gap-2">
                        <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-mono font-semibold ${
                          conn.status === 'CONNECTED' && !conn.simulated
                            ? 'bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800'
                            : 'bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400 border border-amber-200 dark:border-amber-800'
                        }`}>
                          <span className={`w-2 h-2 rounded-full ${conn.status === 'CONNECTED' && !conn.simulated ? 'bg-emerald-500 animate-pulse' : 'bg-amber-500'}`} />
                          {conn.simulated ? 'SIMULATED' : conn.status}
                        </span>

                        {conn.simulated && <button
                          onClick={() => handleDeleteConnector(conn.id)}
                          title="Remove connector"
                          className="p-1 text-slate-400 hover:text-red-500 rounded transition-colors"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>}
                      </div>
                    </div>

                    {/* Details Attributes */}
                    <div className="space-y-2 p-3 bg-slate-50 dark:bg-slate-950/60 rounded-lg text-xs font-mono text-slate-600 dark:text-slate-400 mb-3 border border-slate-200/60 dark:border-slate-800/80">
                      <div className="flex justify-between items-center">
                        <span className="text-slate-400">Endpoint:</span>
                        <span className="text-slate-800 dark:text-slate-200 truncate max-w-[240px] font-sans text-[11px]">{conn.endpoint}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Auth Method:</span>
                        <span className="text-slate-800 dark:text-slate-200">{conn.authType}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Events Stream:</span>
                        <span className="text-slate-800 dark:text-slate-200 truncate max-w-[240px]">{conn.eventsConsumed}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Metrics:</span>
                        <span className="text-slate-800 dark:text-slate-200 font-semibold">{conn.simulated ? 'n/a (simulated connector)' : conn.health}</span>
                      </div>
                    </div>

                    {currentResult && (
                      <div className={`p-2.5 mb-3 rounded-lg text-xs font-mono flex items-center gap-2 ${
                        currentResult.success 
                          ? 'bg-emerald-50 dark:bg-emerald-950/40 text-emerald-800 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800' 
                          : 'bg-red-50 dark:bg-red-950/40 text-red-800 dark:text-red-300 border border-red-200 dark:border-red-800'
                      }`}>
                        {currentResult.success ? <CheckCircle2 className="w-3.5 h-3.5" /> : <AlertCircle className="w-3.5 h-3.5" />}
                        <span>{currentResult.msg}</span>
                      </div>
                    )}
                  </div>

                  {/* Card Footer Actions */}
                  <div className="pt-3 border-t border-slate-100 dark:border-slate-800 flex items-center justify-between text-xs font-mono">
                    <span className="text-slate-400 text-[11px]">
                      Last sync: {conn.lastSync}
                    </span>

                    <button
                      onClick={() => handleTestConnection(conn.id)}
                      disabled={isTesting}
                      className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 rounded-md font-semibold transition-colors disabled:opacity-50"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${isTesting ? 'animate-spin' : ''}`} />
                      <span>{isTesting ? 'Verifying...' : 'Test Connection'}</span>
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* TAB 2: SIEM QUERY CONSOLE (KQL / SPL / UDM) */}
      {activeSubTab === 'query' && (
        <div className="space-y-4">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 shadow-xs space-y-4">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
              <div>
                <h3 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-cyan-500" />
                  <span>SIEM Query Console</span>
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                  {status?.splunkConfigured ? 'Splunk (SPL) queries run for real over the current window; results are capped at 200 rows. KQL and UDM engines are not connected (sample rows only).' : 'No SIEM is connected: all engines return sample rows.'}
                </p>
              </div>

              {/* Tool Selector */}
              <div className="flex items-center gap-2">
                <span className="text-xs text-slate-400 font-mono">Engine:</span>
                <select
                  value={queryTool}
                  onChange={(e) => setQueryTool(e.target.value as any)}
                  className="bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-800 dark:text-slate-200 cursor-pointer"
                >
                  <option value="sentinel">Microsoft Sentinel (KQL)</option>
                  <option value="splunk">Splunk ES (SPL)</option>
                  <option value="chronicle">Google SecOps Chronicle (UDM)</option>
                </select>
              </div>
            </div>

            {/* Presets */}
            <div className="flex flex-wrap items-center gap-2 pt-1">
              <span className="text-xs text-slate-500 font-mono">Presets:</span>
              <button
                onClick={() => handleSetPresetQuery('signin')}
                className="px-2.5 py-1 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 rounded text-xs font-mono transition-colors"
              >
                Failed Sign-ins (KQL)
              </button>
              <button
                onClick={() => handleSetPresetQuery('lateral')}
                className="px-2.5 py-1 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 rounded text-xs font-mono transition-colors"
              >
                Lateral SMB/RDP (KQL)
              </button>
              <button
                onClick={() => handleSetPresetQuery('database')}
                className="px-2.5 py-1 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 rounded text-xs font-mono transition-colors"
              >
                Crown Jewel DB Access (UDM)
              </button>
              <button
                onClick={() => handleSetPresetQuery('powershell')}
                className="px-2.5 py-1 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 rounded text-xs font-mono transition-colors"
              >
                Encoded PowerShell (SPL)
              </button>
            </div>

            {/* Code Query Editor */}
            <div className="relative">
              <textarea
                value={queryText}
                onChange={(e) => setQueryText(e.target.value)}
                rows={7}
                className="w-full bg-slate-900 text-slate-100 border border-slate-700 rounded-xl p-3.5 font-mono text-xs leading-relaxed focus:outline-none focus:ring-1 focus:ring-cyan-500 selection:bg-cyan-500 selection:text-slate-950"
              />
              <button
                onClick={() => handleCopy(queryText, 'query_text')}
                className="absolute top-3 right-3 p-1.5 bg-slate-800/80 hover:bg-slate-700 text-slate-300 rounded transition-colors text-xs flex items-center gap-1 font-mono"
              >
                {copiedText === 'query_text' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedText === 'query_text' ? 'Copied' : 'Copy'}</span>
              </button>
            </div>

            {/* Actions Bar */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-2">
              <span className="text-xs text-slate-500 font-mono">
                Target Identity: <strong className="text-slate-800 dark:text-slate-200">{currentEntity}</strong>
              </span>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleExecuteQuery()}
                  disabled={isExecutingQuery}
                  className="flex items-center gap-1.5 px-4 py-2 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 rounded-lg text-xs font-bold transition-all disabled:opacity-50"
                >
                  <Search className={`w-3.5 h-3.5 ${isExecutingQuery ? 'animate-spin' : ''}`} />
                  <span>{isExecutingQuery ? 'Querying...' : 'Run Query'}</span>
                </button>


              </div>
            </div>
          </div>

          {queryError && (
            <div className="p-3 rounded-xl text-xs font-mono bg-amber-50 dark:bg-amber-950/40 text-amber-800 dark:text-amber-300 border border-amber-200 dark:border-amber-800">{queryError}</div>
          )}

          {/* Results Table */}
          {queryResults && (
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 shadow-xs space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                  <span className="text-sm font-bold text-slate-900 dark:text-slate-100">
                    Query Results ({queryResults.length} rows from {queryTool.toUpperCase()})
                  </span>
                </div>
                {querySimulated && (
                  <span className="text-xs font-mono font-semibold text-amber-600 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/40 px-2 py-0.5 rounded border border-amber-300 dark:border-amber-800">
                    SAMPLE ROWS (not real data)
                  </span>
                )}
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono border-collapse">
                  <thead>
                    <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-400 bg-slate-50 dark:bg-slate-950/40">
                      <th className="py-2 px-3">Timestamp</th>
                      <th className="py-2 px-3">Log Source</th>
                      <th className="py-2 px-3">Action</th>
                      <th className="py-2 px-3">Host / Asset</th>
                      <th className="py-2 px-3">IP Address</th>
                      <th className="py-2 px-3">Details</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60">
                    {queryResults.map((row, i) => (
                      <tr key={i} className="hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors">
                        <td className="py-2.5 px-3 text-slate-500 whitespace-nowrap">{row.timestamp ? new Date(row.timestamp).toISOString().replace('T', ' ').slice(0, 19) : '-'}</td>
                        <td className="py-2.5 px-3 text-cyan-600 dark:text-cyan-400">{row.source}</td>
                        <td className="py-2.5 px-3 font-semibold">{row.action}</td>
                        <td className="py-2.5 px-3 text-slate-800 dark:text-slate-200">{row.host}</td>
                        <td className="py-2.5 px-3">{row.ip}</td>
                        <td className="py-2.5 px-3 text-slate-500 max-w-xs truncate">{row.details || row.commandLine}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: ACTIVE CONTAINMENT (SOAR) */}
      {activeSubTab === 'containment' && (
        <div className="space-y-6">
          <div className="p-3 rounded-xl text-xs font-mono bg-amber-50 dark:bg-amber-950/40 text-amber-800 dark:text-amber-300 border border-amber-200 dark:border-amber-800">
            SIMULATED: WatchMe v1 does not call EDR, IdP or firewall APIs. These buttons record the request in the audit log only; perform the action in the tool itself.
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Action 1: EDR Host Isolation */}
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 shadow-xs space-y-4 flex flex-col justify-between">
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <div className="p-2 rounded-lg bg-red-50 dark:bg-red-950/40 text-red-600 dark:text-red-400 border border-red-200 dark:border-red-900">
                    <Ban className="w-4 h-4" />
                  </div>
                  <div>
                    <h4 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                      EDR Host Isolation
                    </h4>
                    <p className="text-[11px] text-slate-500">Sever network communication</p>
                  </div>
                </div>

                <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">
                  Instructs EDR agents to instantly drop all inbound/outbound packets to prevent lateral traversal.
                </p>

                <div className="space-y-2 text-xs font-mono">
                  <div>
                    <label className="text-slate-400 block text-[11px] mb-1">Target Host Entity:</label>
                    <select
                      value={selectedHostToIsolate}
                      onChange={(e) => setSelectedHostToIsolate(e.target.value)}
                      className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-lg p-2 text-slate-800 dark:text-slate-200"
                    >
                      {hosts.length === 0 && <option value="">No hosts in the current graph</option>}
                      {hosts.map(h => <option key={h} value={h}>{h}</option>)}
                    </select>
                  </div>

                  <div>
                    <label className="text-slate-400 block text-[11px] mb-1">EDR Platform:</label>
                    <select
                      value={isolateTool}
                      onChange={(e) => setIsolateTool(e.target.value)}
                      className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-lg p-2 text-slate-800 dark:text-slate-200"
                    >
                      <option value="CrowdStrike Falcon">CrowdStrike Falcon (RTR Host Containment)</option>
                      <option value="Microsoft Defender">Microsoft Defender for Endpoint (Isolate Device)</option>
                      <option value="SentinelOne">SentinelOne (Network Quarantine)</option>
                    </select>
                  </div>
                </div>
              </div>

              <button
                onClick={handleIsolateHost}
                disabled={isIsolating}
                className="w-full flex items-center justify-center gap-1.5 py-2 px-3 bg-red-600 hover:bg-red-700 text-white rounded-lg text-xs font-bold shadow-sm transition-all disabled:opacity-50"
              >
                <Ban className={`w-3.5 h-3.5 ${isIsolating ? 'animate-spin' : ''}`} />
                <span>{isIsolating ? 'Isolating...' : 'Isolate Endpoint Now'}</span>
              </button>
            </div>

            {/* Action 2: IdP User Revocation */}
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 shadow-xs space-y-4 flex flex-col justify-between">
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <div className="p-2 rounded-lg bg-amber-50 dark:bg-amber-950/40 text-amber-600 dark:text-amber-400 border border-amber-200 dark:border-amber-900">
                    <Key className="w-4 h-4" />
                  </div>
                  <div>
                    <h4 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                      IdP Session Revocation
                    </h4>
                    <p className="text-[11px] text-slate-500">Invalidate tokens & reset pass</p>
                  </div>
                </div>

                <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">
                  Revokes active OAuth refresh tokens, terminates browser sessions, and marks account for password change.
                </p>

                <div className="space-y-2 text-xs font-mono">
                  <div>
                    <label className="text-slate-400 block text-[11px] mb-1">Target Account:</label>
                    <input
                      type="text"
                      value={selectedUserToRevoke}
                      onChange={(e) => setSelectedUserToRevoke(e.target.value)}
                      className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-lg p-2 text-slate-800 dark:text-slate-200"
                    />
                  </div>

                  <div>
                    <label className="text-slate-400 block text-[11px] mb-1">Identity Provider:</label>
                    <select
                      value={revokeTool}
                      onChange={(e) => setRevokeTool(e.target.value)}
                      className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-lg p-2 text-slate-800 dark:text-slate-200"
                    >
                      <option value="Okta Identity Cloud">Okta Identity Cloud (Clear User Sessions)</option>
                      <option value="Microsoft Entra ID">Microsoft Entra ID (Revoke SignIn Sessions)</option>
                      <option value="Ping Identity">PingFederate / PingOne</option>
                    </select>
                  </div>
                </div>
              </div>

              <button
                onClick={handleRevokeUser}
                disabled={isRevoking}
                className="w-full flex items-center justify-center gap-1.5 py-2 px-3 bg-amber-600 hover:bg-amber-700 text-white rounded-lg text-xs font-bold shadow-sm transition-all disabled:opacity-50"
              >
                <Key className={`w-3.5 h-3.5 ${isRevoking ? 'animate-spin' : ''}`} />
                <span>{isRevoking ? 'Revoking...' : 'Terminate User Sessions'}</span>
              </button>
            </div>

            {/* Action 3: Firewall Block Indicator */}
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 shadow-xs space-y-4 flex flex-col justify-between">
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <div className="p-2 rounded-lg bg-blue-50 dark:bg-blue-950/40 text-blue-600 dark:text-blue-400 border border-blue-200 dark:border-blue-900">
                    <Globe className="w-4 h-4" />
                  </div>
                  <div>
                    <h4 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                      Firewall & Proxy Sinkhole
                    </h4>
                    <p className="text-[11px] text-slate-500">Block C2 IP or exfil domain</p>
                  </div>
                </div>

                <p className="text-xs text-slate-500 dark:text-slate-400 mb-3">
                  Pushes malicious IP or FQDN to Dynamic Block Lists (DBL) across perimeter edge firewalls.
                </p>

                <div className="space-y-2 text-xs font-mono">
                  <div>
                    <label className="text-slate-400 block text-[11px] mb-1">Indicator Value:</label>
                    <input
                      type="text"
                      value={indicatorToBlock}
                      onChange={(e) => setIndicatorToBlock(e.target.value)}
                      className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-lg p-2 text-slate-800 dark:text-slate-200"
                    />
                  </div>

                  <div>
                    <label className="text-slate-400 block text-[11px] mb-1">Firewall / SASE Platform:</label>
                    <select
                      value={blockTool}
                      onChange={(e) => setBlockTool(e.target.value)}
                      className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-lg p-2 text-slate-800 dark:text-slate-200"
                    >
                      <option value="Palo Alto Panorama">Palo Alto Panorama (Dynamic Block List)</option>
                      <option value="Zscaler Internet Access">Zscaler ZIA (URL Categorization / Block)</option>
                      <option value="Cloudflare Gateway">Cloudflare One Gateway (DNS Sinkhole)</option>
                    </select>
                  </div>
                </div>
              </div>

              <button
                onClick={handleBlockIndicator}
                disabled={isBlocking}
                className="w-full flex items-center justify-center gap-1.5 py-2 px-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-bold shadow-sm transition-all disabled:opacity-50"
              >
                <Globe className={`w-3.5 h-3.5 ${isBlocking ? 'animate-spin' : ''}`} />
                <span>{isBlocking ? 'Blocking...' : 'Block on Perimeter'}</span>
              </button>
            </div>
          </div>

          {/* Containment Audit Trail */}
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 shadow-xs space-y-3">
            <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-500" />
              <span>Containment requests this session (simulated; also written to the audit log)</span>
            </h3>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-400 bg-slate-50 dark:bg-slate-950/40">
                    <th className="py-2 px-3">Time</th>
                    <th className="py-2 px-3">Action</th>
                    <th className="py-2 px-3">Target</th>
                    <th className="py-2 px-3">Security Tool</th>
                    <th className="py-2 px-3">Status</th>
                    <th className="py-2 px-3">Response Latency</th>
                    <th className="py-2 px-3">Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60">
                  {containmentLogs.map(log => (
                    <tr key={log.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/40">
                      <td className="py-2.5 px-3 text-slate-500">{log.timestamp}</td>
                      <td className="py-2.5 px-3 font-semibold text-slate-800 dark:text-slate-200">{log.action}</td>
                      <td className="py-2.5 px-3 text-cyan-600 dark:text-cyan-400">{log.target}</td>
                      <td className="py-2.5 px-3">{log.tool}</td>
                      <td className="py-2.5 px-3">
                        <span className="inline-flex items-center gap-1 text-[11px] px-2 py-0.5 rounded bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-300 font-semibold border border-amber-300 dark:border-amber-800">
                          {log.status}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-slate-500">-</td>
                      <td className="py-2.5 px-3 text-slate-600 dark:text-slate-400 max-w-sm truncate">{log.details}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: OCSF / UDM SCHEMA MAPPING */}
      {activeSubTab === 'schema' && (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 shadow-xs space-y-4">
          <div>
            <h3 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-500" />
              <span>OCSF (Open Cybersecurity Schema Framework) Normalization Pipeline</span>
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 max-w-3xl leading-relaxed">
              Every inbound log line from Microsoft Sentinel, Splunk, Google SecOps, CrowdStrike, and Okta is intended to pass through WatchMe's normalizer, converting heterogeneous schemas into 8 standard node entities and 10 relationship edge types.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
            <div className="p-4 bg-slate-50 dark:bg-slate-950/60 rounded-xl border border-slate-200 dark:border-slate-800 font-mono text-xs space-y-2">
              <div className="font-bold text-slate-800 dark:text-slate-200 flex items-center justify-between pb-1 border-b border-slate-200 dark:border-slate-800">
                <span>Raw SIEM Ingestion Field</span>
                <span>WatchMe Graph Entity</span>
              </div>
              <div className="flex justify-between py-1 text-slate-600 dark:text-slate-400">
                <span>user.name / TargetUserName / suser</span>
                <span className="text-cyan-600 dark:text-cyan-400 font-bold">Node: User</span>
              </div>
              <div className="flex justify-between py-1 text-slate-600 dark:text-slate-400">
                <span>device.hostname / Computer / host</span>
                <span className="text-blue-600 dark:text-blue-400 font-bold">Node: Host</span>
              </div>
              <div className="flex justify-between py-1 text-slate-600 dark:text-slate-400">
                <span>src_ip / IpAddress / c-ip</span>
                <span className="text-emerald-600 dark:text-emerald-400 font-bold">Node: IP</span>
              </div>
              <div className="flex justify-between py-1 text-slate-600 dark:text-slate-400">
                <span>app / target.resource.name</span>
                <span className="text-purple-600 dark:text-purple-400 font-bold">Node: Application</span>
              </div>
              <div className="flex justify-between py-1 text-slate-600 dark:text-slate-400">
                <span>file.name / TargetFilename</span>
                <span className="text-amber-600 dark:text-amber-400 font-bold">Node: File</span>
              </div>
              <div className="flex justify-between py-1 text-slate-600 dark:text-slate-400">
                <span>process.name / NewProcessName</span>
                <span className="text-pink-600 dark:text-pink-400 font-bold">Node: Process</span>
              </div>
              <div className="flex justify-between py-1 text-slate-600 dark:text-slate-400">
                <span>dns.query.name / destination.domain</span>
                <span className="text-indigo-600 dark:text-indigo-400 font-bold">Node: Domain</span>
              </div>
              <div className="flex justify-between py-1 text-slate-600 dark:text-slate-400">
                <span>alert.name / rule.name / signature</span>
                <span className="text-red-600 dark:text-red-400 font-bold">Node: Alert</span>
              </div>
            </div>

            <div className="p-4 bg-slate-50 dark:bg-slate-950/60 rounded-xl border border-slate-200 dark:border-slate-800 font-mono text-xs space-y-2">
              <div className="font-bold text-slate-800 dark:text-slate-200 flex items-center justify-between pb-1 border-b border-slate-200 dark:border-slate-800">
                <span>Event Action & Verdict</span>
                <span>WatchMe Directed Edge</span>
              </div>
              <div className="flex justify-between py-1 text-slate-600 dark:text-slate-400">
                <span>Logon Failure (Event 4625 / 0x18)</span>
                <span className="text-red-500 font-semibold">AUTH_FAIL</span>
              </div>
              <div className="flex justify-between py-1 text-slate-600 dark:text-slate-400">
                <span>Logon Success (Event 4624 / 0x0)</span>
                <span className="text-emerald-500 font-semibold">AUTH_SUCCESS</span>
              </div>
              <div className="flex justify-between py-1 text-slate-600 dark:text-slate-400">
                <span>Inbound Network Flow from IP</span>
                <span className="text-cyan-500 font-semibold">FROM_IP</span>
              </div>
              <div className="flex justify-between py-1 text-slate-600 dark:text-slate-400">
                <span>Lateral SMB / SSH Session</span>
                <span className="text-blue-500 font-semibold">CONNECTED_TO</span>
              </div>
              <div className="flex justify-between py-1 text-slate-600 dark:text-slate-400">
                <span>Database / Cloud App Query</span>
                <span className="text-purple-500 font-semibold">ACCESSED</span>
              </div>
              <div className="flex justify-between py-1 text-slate-600 dark:text-slate-400">
                <span>Binary / Script Execution</span>
                <span className="text-amber-500 font-semibold">EXECUTED</span>
              </div>
              <div className="flex justify-between py-1 text-slate-600 dark:text-slate-400">
                <span>Exfiltration to External S3/Cloud</span>
                <span className="text-rose-500 font-semibold">EXFILTRATED_TO</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* MODAL 1: Add Custom Connector */}
      {showAddModal && (
        <div className="fixed inset-0 bg-slate-950/60 backdrop-blur-xs z-50 flex items-center justify-center p-4">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl w-full max-w-md p-6 shadow-xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100 dark:border-slate-800">
              <div className="flex items-center gap-2">
                <Plus className="w-5 h-5 text-cyan-500" />
                <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">
                  Connect New Security Tool
                </h3>
              </div>
              <button
                onClick={() => setShowAddModal(false)}
                className="text-slate-400 hover:text-slate-600 text-sm font-mono"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleAddConnector} className="space-y-3 text-xs font-mono">
              <div>
                <label className="text-slate-500 block mb-1">Connector Name:</label>
                <input
                  type="text"
                  placeholder="e.g. Elastic Security SIEM"
                  value={newConnName}
                  onChange={(e) => setNewConnName(e.target.value)}
                  required
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg p-2 text-slate-800 dark:text-slate-200 font-sans"
                />
              </div>

              <div>
                <label className="text-slate-500 block mb-1">Vendor:</label>
                <input
                  type="text"
                  placeholder="e.g. Elastic, IBM, Cloudflare"
                  value={newConnVendor}
                  onChange={(e) => setNewConnVendor(e.target.value)}
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg p-2 text-slate-800 dark:text-slate-200 font-sans"
                />
              </div>

              <div>
                <label className="text-slate-500 block mb-1">Category:</label>
                <select
                  value={newConnCategory}
                  onChange={(e) => setNewConnCategory(e.target.value as any)}
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg p-2 text-slate-800 dark:text-slate-200"
                >
                  <option value="SIEM">SIEM (Log Analytics & Detections)</option>
                  <option value="EDR">EDR / XDR (Endpoint Telemetry & Isolation)</option>
                  <option value="IdP">IdP / IAM (Identity, MFA, Sessions)</option>
                  <option value="Firewall">Firewall / Gateway (Traffic & Rulebase)</option>
                  <option value="Proxy">Proxy / SASE (Web Filter & DLP)</option>
                  <option value="SOAR">SOAR / Ticketing (Jira, ServiceNow, Slack)</option>
                </select>
              </div>

              <div>
                <label className="text-slate-500 block mb-1">API Endpoint URL:</label>
                <input
                  type="text"
                  value={newConnEndpoint}
                  onChange={(e) => setNewConnEndpoint(e.target.value)}
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg p-2 text-slate-800 dark:text-slate-200 font-sans"
                />
              </div>

              <div>
                <label className="text-slate-500 block mb-1">Auth Credentials Type:</label>
                <input
                  type="text"
                  value={newConnAuth}
                  onChange={(e) => setNewConnAuth(e.target.value)}
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg p-2 text-slate-800 dark:text-slate-200 font-sans"
                />
              </div>

              <div className="pt-3 border-t border-slate-100 dark:border-slate-800 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 rounded-lg text-xs font-semibold"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 bg-slate-900 hover:bg-slate-800 dark:bg-cyan-500 dark:hover:bg-cyan-400 text-white dark:text-slate-950 rounded-lg text-xs font-bold"
                >
                  Save Connector
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL 2: Simulate SIEM Webhook */}
      {showWebhookModal && (
        <div className="fixed inset-0 bg-slate-950/60 backdrop-blur-xs z-50 flex items-center justify-center p-4">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl w-full max-w-md p-6 shadow-xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100 dark:border-slate-800">
              <div className="flex items-center gap-2">
                <Zap className="w-5 h-5 text-amber-500" />
                <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">
                  Simulate SIEM Alert Ingestion
                </h3>
              </div>
              <button
                onClick={() => setShowWebhookModal(false)}
                className="text-slate-400 hover:text-slate-600 text-sm font-mono"
              >
                ✕
              </button>
            </div>

            <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
              Trigger a realistic inbound SIEM alert webhook (`POST /api/integrations/webhook`). WatchMe will immediately instantiate an alert node and attach it to the 48-hour graph canvas.
            </p>

            <div className="space-y-3 text-xs font-mono">
              <div>
                <label className="text-slate-500 block mb-1">SIEM Source System:</label>
                <select
                  value={webhookSource}
                  onChange={(e) => setWebhookSource(e.target.value)}
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg p-2 text-slate-800 dark:text-slate-200"
                >
                  <option value="Microsoft Sentinel">Microsoft Sentinel (SigninLogs / Incident)</option>
                  <option value="Google SecOps">Google SecOps Chronicle (UDM Detection)</option>
                  <option value="Splunk ES">Splunk Enterprise Security (Notable Event)</option>
                  <option value="CrowdStrike Falcon">CrowdStrike Falcon (EDR Detection)</option>
                  <option value="Okta Identity Cloud">Okta Identity Cloud (MFA Fatigue Alert)</option>
                </select>
              </div>

              <div>
                <label className="text-slate-500 block mb-1">Alert Detection Title:</label>
                <input
                  type="text"
                  value={webhookAlert}
                  onChange={(e) => setWebhookAlert(e.target.value)}
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg p-2 text-slate-800 dark:text-slate-200 font-sans"
                />
              </div>

              <div>
                <label className="text-slate-500 block mb-1">Severity Band:</label>
                <select
                  value={webhookSeverity}
                  onChange={(e) => setWebhookSeverity(e.target.value)}
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg p-2 text-slate-800 dark:text-slate-200"
                >
                  <option value="CRITICAL">CRITICAL (Risk 95+)</option>
                  <option value="HIGH">HIGH (Risk 80-94)</option>
                  <option value="MEDIUM">MEDIUM (Risk 50-79)</option>
                </select>
              </div>

              <div>
                <label className="text-slate-500 block mb-1">Target Entity Under Investigation:</label>
                <input
                  type="text"
                  value={currentEntity}
                  disabled
                  className="w-full bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg p-2 text-slate-600 dark:text-slate-400 cursor-not-allowed"
                />
              </div>
            </div>

            <div className="pt-3 border-t border-slate-100 dark:border-slate-800 flex justify-end gap-2">
              <button
                onClick={() => setShowWebhookModal(false)}
                className="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 rounded-lg text-xs font-semibold"
              >
                Cancel
              </button>
              <button
                onClick={handleSendSimulatedWebhook}
                disabled={isDispatchingWebhook}
                className="flex items-center gap-1.5 px-4 py-1.5 bg-slate-900 hover:bg-slate-800 dark:bg-cyan-500 dark:hover:bg-cyan-400 text-white dark:text-slate-950 rounded-lg text-xs font-bold disabled:opacity-50"
              >
                <Send className="w-3.5 h-3.5" />
                <span>{isDispatchingWebhook ? 'Dispatching...' : 'Dispatch Alert Webhook'}</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
