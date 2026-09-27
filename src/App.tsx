import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { Sparkles, Search, Network, Settings, FolderArchive, Video, AlertTriangle, Table2, Share2, Route, NotebookPen, Wand2 } from 'lucide-react';
import { UserProfile, SecurityNode, ViewTab, WatchlistItem, CaseRecord, EntitySummary, SystemStatus, InvestigationNote, Storyline } from './types';
import { TopNav } from './components/TopNav';
import { SIEMAlertBanner } from './components/SIEMAlertBanner';
import { WindowBar } from './components/WindowBar';
import { TemporalGraphCanvas } from './components/TemporalGraphCanvas';
import { AttackPathCanvas } from './components/AttackPathCanvas';
import { TimeScrubber } from './components/TimeScrubber';
import { NodeDetailDrawer } from './components/NodeDetailDrawer';
import { TimelineLogTable } from './components/TimelineLogTable';
import { ReplayVideoStudio, type RecordedVideo, type ReplaySettings } from './components/ReplayVideoStudio';
import { AICaseDossier } from './components/AICaseDossier';
import { WatchlistHome } from './components/WatchlistHome';
import { CaseViewScreen } from './components/CaseViewScreen';
import { AdminConfigScreen } from './components/AdminConfigScreen';
import { SecurityToolsIntegrationHub } from './components/SecurityToolsIntegrationHub';
import { NotesPanel } from './components/NotesPanel';
import { StorylineView } from './components/StorylineView';
import { AssignCloseDialog, type AssignClosePayload } from './components/AssignCloseDialog';
import { api, sha256Hex } from './api';

// What the investigation shows. t0 is the end of the window: '' means "now" (it is frozen after the first load
// unless live mode is on, so nodes never drop out of the window as time passes).
type GraphSource =
  | { kind: 'live'; key: string; windowHours: number; t0: string; live: boolean; nonce: number }
  | { kind: 'search'; query: string; windowHours: number; t0: string; live: boolean; nonce: number }
  | { kind: 'case'; caseId: string };

type InvestigationView = 'path' | 'story' | 'graph' | 'timeline' | 'notes';

const LIVE_REFRESH_MS = 30_000;

// Recording formats in order of preference. Chrome and Edge support MP4 in MediaRecorder; Firefox records WebM.
const RECORDING_MIME_TYPES = ['video/mp4;codecs=avc1.42E01E', 'video/mp4', 'video/webm;codecs=vp9', 'video/webm'];

function pickRecordingMime(): string {
  if (typeof MediaRecorder === 'undefined') return '';
  return RECORDING_MIME_TYPES.find(t => MediaRecorder.isTypeSupported(t)) || '';
}

const sourceKey = (g: GraphSource) => (g.kind === 'live' ? `e:${g.key}` : g.kind === 'search' ? `s:${g.query}` : `c:${g.caseId}`);

export default function App() {
  const params = new URLSearchParams(window.location.search);
  const initialEntity = params.get('entity') || 'jsmith';
  const initialQuery = params.get('q');
  const initialAlertHour = params.get('alert_time');
  const initialHours = Math.min(168, Math.max(1, (parseInt(params.get('window') || '2', 10) || 2) * 24));

  const [activeTab, setActiveTab] = useState<ViewTab>('investigation');
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [graphSource, setGraphSource] = useState<GraphSource>(
    initialQuery
      ? { kind: 'search', query: initialQuery, windowHours: initialHours, t0: params.get('t0') || '', live: false, nonce: 0 }
      : { kind: 'live', key: initialEntity, windowHours: initialHours, t0: params.get('t0') || '', live: params.get('live') === '1', nonce: 0 },
  );
  const [userProfile, setUserProfile] = useState<UserProfile | null>(null);
  const [investigationKey, setInvestigationKey] = useState<string>('');
  const [availableUsers, setAvailableUsers] = useState<EntitySummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [timeToContextMs, setTimeToContextMs] = useState<number | null>(null);
  const [lastRefreshMs, setLastRefreshMs] = useState<number | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [isDarkMode, setIsDarkMode] = useState<boolean>(() => {
    try { return localStorage.getItem('watchme-theme') === 'dark'; } catch { return false; }
  });
  const [globalSearchOpen, setGlobalSearchOpen] = useState<boolean>(false);
  const [globalSearchTerm, setGlobalSearchTerm] = useState<string>('');
  const [dossierOpen, setDossierOpen] = useState(false);
  const [assignOpen, setAssignOpen] = useState(false);

  const [watchlist, setWatchlist] = useState<WatchlistItem[]>([]);
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [activeCaseId, setActiveCaseId] = useState<string | null>(null);
  const [notes, setNotes] = useState<InvestigationNote[]>([]);

  const [storyline, setStoryline] = useState<Storyline | null>(null);
  const [storyLoading, setStoryLoading] = useState(false);
  const [storyError, setStoryError] = useState<string | null>(null);

  const [investigationView, setInvestigationView] = useState<InvestigationView>(() => {
    try {
      const v = localStorage.getItem('watchme-view');
      return v === 'graph' || v === 'timeline' || v === 'story' || v === 'notes' ? v : 'path';
    } catch { return 'path'; }
  });
  useEffect(() => {
    try { localStorage.setItem('watchme-view', investigationView); } catch { /* storage unavailable */ }
  }, [investigationView]);
  // Replays and citation jumps use the last picture view (path by default)
  const pictureView: 'path' | 'graph' = investigationView === 'graph' ? 'graph' : 'path';
  const [timelineNodeFilter, setTimelineNodeFilter] = useState<string | null>(null);

  // Time scrubber & replay
  const [currentHour, setCurrentHour] = useState<number>(0);
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [playbackSpeed, setPlaybackSpeed] = useState<number>(1);

  const [selectedNode, setSelectedNode] = useState<SecurityNode | null>(null);
  const [highlightedCitationId, setHighlightedCitationId] = useState<string | null>(null);

  // Recording
  const canvasElementRef = useRef<HTMLCanvasElement | null>(null);
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const replayTimerRef = useRef<number | null>(null);
  const recordedChunksRef = useRef<Blob[]>([]);
  const [isRecording, setIsRecording] = useState<boolean>(false);
  const [recordingProgress, setRecordingProgress] = useState<number>(0);
  const [recordedVideo, setRecordedVideo] = useState<RecordedVideo | null>(null);
  const [replaySettings, setReplaySettings] = useState<ReplaySettings>({ durationSecs: 30, redact: false, titleText: '' });

  const profileRef = useRef<UserProfile | null>(null);
  profileRef.current = userProfile;
  const loadedSourceKeyRef = useRef<string>('');
  const skipLoadRef = useRef<string | null>(null); // freezing t0 after a load must not trigger another load

  const entityKey = graphSource.kind === 'live' ? graphSource.key : userProfile?.username || '';
  const windowHours = userProfile?.windowHours ?? (graphSource.kind !== 'case' ? graphSource.windowHours : 48);
  const t0Param = graphSource.kind !== 'case' ? graphSource.t0 : userProfile?.t0 || '';
  const isLive = graphSource.kind !== 'case' && graphSource.live;
  const searchQuery = graphSource.kind === 'search' ? graphSource.query : userProfile?.kind === 'search' ? userProfile.query : undefined;
  const activeCase = cases.find(c => c.id === activeCaseId) || null;

  // `dark` stays on so the components' dark: variants apply; `theme-dark` picks the palette (see index.css)
  useEffect(() => {
    document.documentElement.classList.add('dark');
    document.documentElement.classList.toggle('theme-dark', isDarkMode);
    try { localStorage.setItem('watchme-theme', isDarkMode ? 'dark' : 'light'); } catch { /* storage unavailable */ }
  }, [isDarkMode]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setGlobalSearchOpen(prev => !prev);
      } else if (e.key === 'Escape') {
        setGlobalSearchOpen(false);
        setDossierOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const refreshLists = useCallback(() => {
    api<{ users: EntitySummary[] }>('/api/users').then(d => setAvailableUsers(d.users)).catch(err => setNotice(err.message));
    api<{ items: WatchlistItem[] }>('/api/watchlist').then(d => setWatchlist(d.items)).catch(err => setNotice(err.message));
    api<{ cases: CaseRecord[] }>('/api/cases').then(d => setCases(d.cases)).catch(err => setNotice(err.message));
  }, []);

  useEffect(() => {
    api<SystemStatus>('/api/status').then(setStatus).catch(err => setNotice(err.message));
    refreshLists();
  }, [refreshLists]);

  // Load the graph (entity, log search, or saved case snapshot)
  useEffect(() => {
    const key = sourceKey(graphSource);
    const stateKey = JSON.stringify(graphSource);
    if (skipLoadRef.current === stateKey) { skipLoadRef.current = null; return; }
    let cancelled = false;
    const started = performance.now();
    const refreshOfSame = loadedSourceKeyRef.current === key && !!profileRef.current;
    setLoading(true);
    setLoadError(null);

    const load = async (): Promise<{ profile: UserProfile; invKey: string }> => {
      if (graphSource.kind === 'case') {
        const d = await api<{ case: CaseRecord; snapshot: UserProfile | null }>(`/api/cases/${graphSource.caseId}`);
        if (!d.snapshot) throw new Error(`Case ${d.case.caseRef} has no saved graph snapshot (demo seed case). Open the entity live instead.`);
        return {
          profile: { ...d.snapshot, dataSource: 'snapshot' as const, notes: [...(d.snapshot.notes || []), `Snapshot from case ${d.case.caseRef}, saved ${new Date(d.case.createdAt).toLocaleString()}.`] },
          invKey: d.case.entityKey || d.snapshot.username,
        };
      }
      const q = new URLSearchParams({ windowHours: String(graphSource.windowHours) });
      if (graphSource.t0 && !graphSource.live) q.set('t0', graphSource.t0);
      if (graphSource.nonce > 0 || graphSource.live) q.set('refresh', '1');
      if (graphSource.kind === 'search') {
        q.set('q', graphSource.query);
        const d = await api<{ profile: UserProfile; investigationKey: string }>(`/api/graph/search?${q}`);
        return { profile: d.profile, invKey: d.investigationKey };
      }
      const d = await api<{ profile: UserProfile }>(`/api/graph/${encodeURIComponent(graphSource.key)}?${q}`);
      return { profile: d.profile, invKey: graphSource.key.toLowerCase() };
    };

    load()
      .then(({ profile, invKey }) => {
        if (cancelled) return;
        const prev = profileRef.current;
        if (refreshOfSame && prev && graphSource.kind !== 'case' && graphSource.live) {
          // Live refresh: keep the analyst's place, mark what is new since the last refresh
          const before = new Set(prev.nodes.map(n => n.id));
          profile = { ...profile, nodes: profile.nodes.map(n => ({ ...n, isNew: !before.has(n.id) })) };
          const added = profile.nodes.filter(n => n.isNew).length;
          if (added) setNotice(`Live: ${added} new entit${added === 1 ? 'y' : 'ies'} since the last refresh.`);
          setUserProfile(profile);
          setCurrentHour(0);
        } else {
          setUserProfile(profile);
          const alertHour = initialAlertHour ? parseInt(initialAlertHour, 10) : NaN;
          if (!refreshOfSame) {
            setCurrentHour(Number.isFinite(alertHour) ? Math.min(profile.windowHours ?? 48, Math.max(0, alertHour)) : 0);
            setSelectedNode(null);
            setHighlightedCitationId(null);
            setTimelineNodeFilter(null);
            setRecordedVideo(null);
            setStoryline(null);
            setStoryError(null);
          }
          setReplaySettings(s => ({ ...s, titleText: `INCIDENT EVIDENCE // ${profile.kind === 'search' ? 'log search' : profile.username}` }));
        }
        loadedSourceKeyRef.current = key;
        setInvestigationKey(invKey);
        setTimeToContextMs(Math.round(performance.now() - started));
        setLastRefreshMs(Date.now());
        // Freeze the window: "now" becomes a fixed end time, so re-queries and expansions use the same window
        if (graphSource.kind !== 'case' && !graphSource.live && !graphSource.t0 && profile.t0) {
          const frozen = { ...graphSource, t0: profile.t0 };
          skipLoadRef.current = JSON.stringify(frozen);
          setGraphSource(frozen);
        }
      })
      .catch(err => {
        if (!cancelled) setLoadError(err.message || String(err));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graphSource]);

  // Live mode: re-query every 30 s with the window ending "now"
  useEffect(() => {
    if (!isLive) return;
    const t = window.setInterval(() => {
      setGraphSource(prev => (prev.kind !== 'case' && prev.live ? { ...prev, nonce: prev.nonce + 1 } : prev));
    }, LIVE_REFRESH_MS);
    return () => window.clearInterval(t);
  }, [isLive]);

  // Notes and the case for the current investigation
  const reloadNotes = useCallback((key: string) => {
    if (!key) return;
    api<{ notes: InvestigationNote[] }>(`/api/notes?entityKey=${encodeURIComponent(key)}`).then(d => setNotes(d.notes)).catch(err => setNotice(err.message));
  }, []);
  useEffect(() => { reloadNotes(investigationKey); }, [investigationKey, reloadNotes]);
  useEffect(() => {
    if (!investigationKey) return;
    if (graphSource.kind === 'case') { setActiveCaseId(graphSource.caseId); return; }
    const existing = cases.find(c => c.entityKey === investigationKey && c.hasSnapshot);
    setActiveCaseId(existing?.id || null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [investigationKey]);

  // Latest verdict per node (notes are newest first)
  const verdicts = useMemo(() => {
    const out: Record<string, 'BENIGN' | 'MALICIOUS'> = {};
    for (const n of notes) if (n.kind === 'VERDICT' && n.nodeId && n.verdict && !out[n.nodeId]) out[n.nodeId] = n.verdict;
    return out;
  }, [notes]);

  const openEntity = (key: string) => {
    setGraphSource(prev => ({ kind: 'live', key, windowHours: prev.kind !== 'case' ? prev.windowHours : 48, t0: prev.kind !== 'case' ? prev.t0 : '', live: prev.kind !== 'case' ? prev.live : false, nonce: 0 }));
    setActiveTab('investigation');
  };

  const openSearch = (query: string) => {
    setGraphSource(prev => ({ kind: 'search', query, windowHours: prev.kind !== 'case' ? prev.windowHours : 48, t0: prev.kind !== 'case' ? prev.t0 : '', live: false, nonce: 0 }));
    setActiveTab('investigation');
    setInvestigationView('path');
  };

  const reloadGraph = () => {
    setGraphSource(prev => (prev.kind !== 'case' ? { ...prev, nonce: prev.nonce + 1 } : prev));
  };

  const applyWindow = (w: { t0: string; windowHours: number }) => {
    setGraphSource(prev => (prev.kind !== 'case' ? { ...prev, t0: w.t0, windowHours: w.windowHours, live: false, nonce: prev.nonce + 1 } : prev));
  };

  const toggleLive = () => {
    setGraphSource(prev => {
      if (prev.kind === 'case') return prev;
      if (prev.live) return { ...prev, live: false, t0: profileRef.current?.t0 || new Date().toISOString() };
      return { ...prev, live: true, t0: '', nonce: prev.nonce + 1 };
    });
  };

  const handleCanvasRef = useCallback((canvas: HTMLCanvasElement | null) => {
    canvasElementRef.current = canvas;
  }, []);

  // FR-06: 1-hop expansion
  const handleExpandNode = async (nodeId: string) => {
    if (!userProfile) return;
    try {
      const data = await api<{ nodes: SecurityNode[]; edges: UserProfile['edges']; message?: string }>('/api/graph/expand', {
        method: 'POST',
        body: { nodeId, userKey: entityKey, searchQuery: userProfile.kind === 'search' ? userProfile.query : undefined, windowHours, t0: userProfile.t0 || t0Param },
      });
      if (data.message) setNotice(data.message);
      if (data.nodes.length || data.edges.length) {
        setUserProfile(p => (p ? { ...p, nodes: [...p.nodes, ...data.nodes], edges: [...p.edges, ...data.edges] } : p));
        setNotice(`Added ${data.nodes.length} related entities from 1-hop expansion.`);
      } else if (!data.message) {
        setNotice('No additional related entities found in this window.');
      }
    } catch (err: any) {
      setNotice(`Expansion failed: ${err.message}`);
    }
  };

  const handlePinNode = (nodeId: string) => {
    setUserProfile(p => (p ? { ...p, nodes: p.nodes.map(n => (n.id === nodeId ? { ...n, pinned: !n.pinned } : n)) } : p));
    setSelectedNode(n => (n && n.id === nodeId ? { ...n, pinned: !n.pinned } : n));
  };

  const handleSaveVerdict = async (node: SecurityNode, verdict: 'BENIGN' | 'MALICIOUS', reason: string) => {
    const d = await api<{ note: InvestigationNote }>('/api/feedback', {
      method: 'POST',
      body: { targetId: node.id, nodeName: node.name, entityKey: investigationKey, caseId: activeCaseId || undefined, verdict, note: reason },
    });
    setNotes(prev => [d.note, ...prev]);
    setNotice(`Verdict saved: ${node.name} marked ${verdict}. Recorded in the notes and the audit log.`);
  };

  const handleSaveHypothesis = async (node: SecurityNode, text: string) => {
    const d = await api<{ note: InvestigationNote | null }>('/api/annotations', {
      method: 'POST',
      body: { entityKey: investigationKey, nodeId: node.id, nodeName: node.name, caseId: activeCaseId || undefined, text },
    });
    if (d.note) setNotes(prev => [d.note!, ...prev]);
    setUserProfile(p => (p ? { ...p, nodes: p.nodes.map(n => (n.id === node.id ? { ...n, annotation: text } : n)) } : p));
  };

  const handleAddNote = async (kind: 'NOTE' | 'HYPOTHESIS', text: string) => {
    const d = await api<{ note: InvestigationNote }>('/api/notes', { method: 'POST', body: { entityKey: investigationKey, caseId: activeCaseId || undefined, kind, text } });
    setNotes(prev => [d.note, ...prev]);
  };

  // FR-19: save the current graph (including expansions and annotations) as a case
  const createCase = async (): Promise<CaseRecord | null> => {
    if (!userProfile) return null;
    const title = userProfile.kind === 'search' ? `Log search: ${userProfile.query}` : `${userProfile.triggerEvent} - ${userProfile.username}`;
    const data = await api<{ case: CaseRecord }>('/api/cases', {
      method: 'POST',
      body: { entityKey: investigationKey || entityKey, title, profile: userProfile },
    });
    setCases(prev => [data.case, ...prev]);
    setActiveCaseId(data.case.id);
    return data.case;
  };

  const handleSaveCase = async () => {
    try {
      const c = await createCase();
      if (c) {
        setNotice(`Saved case ${c.caseRef}.`);
        setDossierOpen(false);
        setActiveTab('cases');
      }
    } catch (err: any) {
      setNotice(`Could not save case: ${err.message}`);
    }
  };

  const ensureCase = async (): Promise<CaseRecord | null> => {
    const existing = cases.find(c => c.id === activeCaseId);
    return existing || createCase();
  };

  // Assign & close: creates the case (with graph snapshot) if needed, then records assignment and closure
  const handleAssignClose = async (p: AssignClosePayload) => {
    const c = await ensureCase();
    if (!c) throw new Error('No graph loaded');
    const d = await api<{ case: CaseRecord; notes: InvestigationNote[] }>(`/api/cases/${c.id}`, { method: 'PATCH', body: p });
    setCases(prev => prev.map(x => (x.id === c.id ? d.case : x)));
    setNotes(prev => [...d.notes, ...prev]);
    setAssignOpen(false);
    setNotice(p.status === 'CLOSED' ? `${d.case.caseRef} closed (${d.case.disposition?.replace(/_/g, ' ').toLowerCase()}), assigned to ${d.case.assignee}.` : `${d.case.caseRef} assigned to ${d.case.assignee} (${d.case.status}).`);
  };

  // AI Storyline
  const generateStoryline = async () => {
    if (!userProfile) return;
    setStoryLoading(true);
    setStoryError(null);
    try {
      const d = await api<{ storyline: Storyline }>('/api/ai/storyline', { method: 'POST', body: { profile: userProfile, privacyModeEnabled: true } });
      setStoryline(d.storyline);
    } catch (err: any) {
      setStoryError(err.message);
    } finally {
      setStoryLoading(false);
    }
  };

  const approveStoryline = async () => {
    if (!storyline) return;
    try {
      const c = await ensureCase();
      if (!c) return;
      const d = await api<{ case: CaseRecord; note: InvestigationNote }>(`/api/cases/${c.id}/storyline`, { method: 'POST', body: { storyline } });
      setCases(prev => prev.map(x => (x.id === c.id ? d.case : x)));
      setNotes(prev => [d.note, ...prev]);
      setNotice(`Storyline approved and saved to ${c.caseRef} (hash in the audit log).`);
    } catch (err: any) {
      setNotice(`Could not save the storyline: ${err.message}`);
    }
  };

  // FR-20: push to ticketing for the case that belongs to the current investigation
  const handlePushToTicket = async (system: 'jira' | 'slack' | 'servicenow') => {
    try {
      const c = await ensureCase();
      if (!c) return;
      const data = await api<{ pushedTo: string[]; message: string }>(`/api/cases/${c.id}/push`, { method: 'POST', body: { target: system } });
      setCases(prev => prev.map(x => (x.id === c.id ? { ...x, pushedTo: data.pushedTo } : x)));
      setNotice(`${c.caseRef}: ${data.message}`);
    } catch (err: any) {
      setNotice(`Push failed: ${err.message}`);
    }
  };

  const registerEvidence = async (video: RecordedVideo) => {
    try {
      const c = await ensureCase();
      if (!c) return;
      const data = await api<{ case: CaseRecord }>(`/api/cases/${c.id}/evidence`, {
        method: 'POST',
        body: { kind: 'REPLAY_VIDEO', fileName: video.fileName, mimeType: video.mimeType, sizeBytes: video.sizeBytes, sha256: video.sha256 },
      });
      setCases(prev => prev.map(x => (x.id === c.id ? data.case : x)));
      setRecordedVideo(v => (v ? { ...v, registeredCaseRef: c.caseRef } : v));
      setNotice(`Replay registered with ${c.caseRef} (SHA-256 recorded in the audit log).`);
    } catch (err: any) {
      setNotice(`Could not register evidence: ${err.message}`);
    }
  };

  // Search graph around a host / IP / domain, in the live source's query language
  const handleSearchEntity = (node: SecurityNode) => {
    const v = node.name.replace(/"/g, '');
    const ds = status?.dataSource;
    let q = v;
    if (ds === 'elastic') {
      q = node.type === 'host' ? `host.name:"${v}" OR winlog.computer_name:"${v}"` : node.type === 'ip' ? `source.ip:"${v}" OR destination.ip:"${v}"` : `destination.domain:"${v}" OR dns.question.name:"${v}" OR url.domain:"${v}"`;
    } else if (ds === 'splunk') {
      q = node.type === 'host' ? `(host="${v}" OR ComputerName="${v}")` : node.type === 'ip' ? `(src_ip="${v}" OR dest_ip="${v}" OR DestinationIp="${v}")` : `(QueryName="${v}" OR url="*${v}*" OR DestinationHostname="${v}")`;
    }
    openSearch(q);
  };

  const stopReplayTimer = () => {
    if (replayTimerRef.current !== null) {
      window.clearInterval(replayTimerRef.current);
      replayTimerRef.current = null;
    }
  };

  // Automated replay recording. Recording runs on the investigation view so the canvas is mounted and drawing.
  const startAutomatedRecording = () => {
    if (!userProfile || isRecording) return;
    if (typeof MediaRecorder === 'undefined') {
      setNotice('This browser does not support MediaRecorder, so replay recording is unavailable.');
      return;
    }
    setActiveTab('investigation');
    setInvestigationView(pictureView);
    setIsPlaying(false);
    setRecordedVideo(null);

    // Wait one frame for the canvas to mount before capturing it
    window.setTimeout(() => {
      const canvas = canvasElementRef.current;
      if (!canvas || !canvas.isConnected) {
        setNotice('Replay failed: the graph canvas is not available.');
        return;
      }
      try {
        const steps = windowHours;
        setCurrentHour(steps);
        setRecordingProgress(0);
        setIsRecording(true);
        recordedChunksRef.current = [];

        const mimeType = pickRecordingMime();
        const stream = canvas.captureStream(30);
        const recorder = new MediaRecorder(stream, mimeType ? { mimeType, videoBitsPerSecond: 2_000_000 } : undefined);
        mediaRecorderRef.current = recorder;

        recorder.ondataavailable = event => {
          if (event.data && event.data.size > 0) recordedChunksRef.current.push(event.data);
        };

        recorder.onstop = async () => {
          stopReplayTimer();
          setIsRecording(false);
          const chunks = recordedChunksRef.current;
          if (!chunks.length) return; // cancelled before any data
          const type = recorder.mimeType || mimeType || 'video/webm';
          const blob = new Blob(chunks, { type });
          const ext = type.includes('mp4') ? 'mp4' : 'webm';
          const hash = await sha256Hex(await blob.arrayBuffer());
          const stamp = new Date().toISOString().replace(/[:.]/g, '-');
          setRecordedVideo({
            url: URL.createObjectURL(blob),
            mimeType: type.split(';')[0],
            sizeBytes: blob.size,
            sha256: hash,
            fileName: `watchme_${userProfile.username.replace(/[^A-Za-z0-9._-]/g, '_')}_${stamp}.${ext}`,
            width: canvas.width,
            height: canvas.height,
            durationSecs: replaySettings.durationSecs,
          });
          setActiveTab('replay');
        };

        recorder.start(250);

        let current = steps;
        const stepMs = Math.max(50, Math.round((replaySettings.durationSecs * 1000) / (steps + 1)));
        replayTimerRef.current = window.setInterval(() => {
          current -= 1;
          if (current < 0) {
            stopReplayTimer();
            setCurrentHour(0);
            setRecordingProgress(100);
            window.setTimeout(() => {
              if (recorder.state !== 'inactive') recorder.stop();
            }, 600);
          } else {
            setCurrentHour(current);
            setRecordingProgress(((steps - current) / steps) * 100);
          }
        }, stepMs);
      } catch (err: any) {
        stopReplayTimer();
        setIsRecording(false);
        setNotice(`Replay recording failed: ${err.message || err}`);
      }
    }, 150);
  };

  const cancelRecording = () => {
    stopReplayTimer();
    recordedChunksRef.current = [];
    if (mediaRecorderRef.current && mediaRecorderRef.current.state !== 'inactive') {
      mediaRecorderRef.current.ondataavailable = null;
      mediaRecorderRef.current.stop();
    }
    setIsRecording(false);
    setRecordingProgress(0);
  };

  // FR-21: exports
  const download = (blob: Blob, name: string) => {
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = name;
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 5000);
  };

  const handleExportTimelineJson = () => {
    if (!userProfile) return;
    download(new Blob([JSON.stringify(userProfile, null, 2)], { type: 'application/json' }), `watchme_timeline_${userProfile.username}_${windowHours}h.json`);
  };

  const handleExportTimelineCsv = () => {
    if (!userProfile) return;
    const nameOf = (id: string) => userProfile.nodes.find(n => n.id === id)?.name || id;
    const q = (v: unknown) => `"${String(v ?? '').replace(/"/g, '""')}"`;
    const headers = 'ID,First_Seen_UTC,Last_Seen_UTC,Type,Protocol,Source,Target,Event_Count,Status,MITRE_TTP,Details\n';
    const rows = userProfile.edges
      .map(e => [e.id, e.firstSeen, e.lastSeen, e.type, e.protocol, nameOf(e.source), nameOf(e.target), e.eventCount, e.status, (e.ttp || []).join(';'), e.details].map(q).join(','))
      .join('\n');
    download(new Blob([headers + rows], { type: 'text/csv' }), `watchme_timeline_${userProfile.username}_${windowHours}h.csv`);
  };

  const handleOpenCase = (caseId: string) => {
    const c = cases.find(x => x.id === caseId);
    setActiveCaseId(caseId);
    if (c && !c.hasSnapshot && c.entityKey) {
      openEntity(c.entityKey); // seeded demo case has no snapshot
    } else {
      setGraphSource({ kind: 'case', caseId });
      setActiveTab('investigation');
    }
  };

  const jumpToCitation = (edgeId: string, nodeId?: string) => {
    if (!userProfile) return;
    setHighlightedCitationId(edgeId);
    setInvestigationView('path');
    const edge = userProfile.edges.find(e => e.id === edgeId);
    if (edge) setCurrentHour(Math.max(0, edge.hour - 0));
    const node = userProfile.nodes.find(n => n.id === (nodeId || edgeId));
    if (node) setSelectedNode(node);
  };

  // --------- Render ---------
  if (loading && !userProfile) {
    return (
      <div className="w-screen h-screen bg-slate-950 flex flex-col items-center justify-center text-slate-400 font-mono text-sm space-y-3">
        <div className="w-8 h-8 rounded-full border-2 border-cyan-400 border-t-transparent animate-spin" />
        <span>Building {windowHours}h graph for {graphSource.kind === 'search' ? `search "${graphSource.query}"` : entityKey}...</span>
      </div>
    );
  }

  if (!userProfile) {
    return (
      <div className="w-screen h-screen bg-slate-950 flex flex-col items-center justify-center text-slate-300 font-mono text-sm p-8 space-y-4">
        <AlertTriangle className="w-8 h-8 text-amber-400" />
        <div className="max-w-xl text-center">{loadError || 'No graph loaded.'}</div>
        <div className="flex gap-2">
          {availableUsers.slice(0, 5).map(u => (
            <button key={u.id} onClick={() => openEntity(u.id)} className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 rounded text-xs">
              Open {u.username}
            </button>
          ))}
        </div>
      </div>
    );
  }

  const visibleNodes = userProfile.nodes.filter(n => n.firstSeenHour >= currentHour);
  const nodeById = new Map(userProfile.nodes.map(n => [n.id, n]));
  const visibleEdges = userProfile.edges.filter(e => {
    const src = nodeById.get(e.source);
    const tgt = nodeById.get(e.target);
    return src && tgt && src.firstSeenHour >= currentHour && tgt.firstSeenHour >= currentHour && e.hour >= currentHour;
  });
  const storyApprovedRef = storyline && activeCase?.storyline?.sha256 === storyline.sha256 ? activeCase.caseRef : null;
  const windowDaysApprox = Math.max(1, Math.round(windowHours / 24));

  const tabButton = (view: InvestigationView, label: string, Icon: typeof Network) => (
    <button
      data-testid={`view-${view}`}
      onClick={() => setInvestigationView(view)}
      className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono transition-colors ${
        investigationView === view ? 'bg-cyan-500 text-slate-950 font-bold' : 'text-slate-400 hover:text-slate-100'
      }`}
    >
      <Icon className="w-3.5 h-3.5" />
      {label}
    </button>
  );

  const selected = selectedNode ? userProfile.nodes.find(n => n.id === selectedNode.id) || selectedNode : null;

  return (
    <div className="flex flex-col w-screen h-screen overflow-hidden bg-slate-100 dark:bg-slate-950 text-slate-900 dark:text-slate-100 font-sans transition-colors duration-200">
      <TopNav
        activeTab={activeTab}
        onChangeTab={setActiveTab}
        selectedUser={userProfile}
        selectedKey={entityKey}
        availableUsers={availableUsers}
        onSelectUser={openEntity}
        onGenerateReplayClick={startAutomatedRecording}
        isRecording={isRecording}
        isDarkMode={isDarkMode}
        onToggleDarkMode={() => setIsDarkMode(prev => !prev)}
        onOpenGlobalSearch={() => setGlobalSearchOpen(true)}
      />

      <SIEMAlertBanner
        userProfile={userProfile}
        timeToContextMs={timeToContextMs}
        loading={loading}
        onRefresh={graphSource.kind !== 'case' ? reloadGraph : undefined}
        onQuickReplay={() => {
          setActiveTab('investigation');
          setInvestigationView(pictureView);
          setCurrentHour(windowHours);
          setIsPlaying(true);
        }}
      />

      <WindowBar
        windowStart={userProfile.windowStart || (userProfile.t0 ? new Date(Date.parse(userProfile.t0) - windowHours * 3_600_000).toISOString() : undefined)}
        windowEnd={userProfile.t0}
        windowHours={windowHours}
        isLive={isLive}
        isSnapshot={graphSource.kind === 'case'}
        lastRefreshMs={lastRefreshMs}
        loading={loading}
        searchQuery={searchQuery}
        demoMode={status?.dataSource === 'demo'}
        caseRecord={activeCase}
        onApply={applyWindow}
        onRequery={reloadGraph}
        onToggleLive={toggleLive}
        onAssignClose={() => setAssignOpen(true)}
        onExitSearch={graphSource.kind === 'search' ? () => openEntity(availableUsers[0]?.id || initialEntity) : undefined}
      />

      {(notice || loadError) && (
        <div data-testid="notice" className="px-6 py-2 text-xs font-mono flex items-center justify-between bg-amber-50 dark:bg-amber-950/40 text-amber-800 dark:text-amber-300 border-b border-amber-200 dark:border-amber-900">
          <span>{loadError ? `Could not load graph: ${loadError}` : notice}</span>
          <button onClick={() => { setNotice(null); setLoadError(null); }} className="font-semibold hover:underline">Dismiss</button>
        </div>
      )}

      <main className="flex-1 relative flex overflow-hidden">
        {activeTab === 'watchlist' && (
          <WatchlistHome
            watchlist={watchlist}
            onSelectEntity={openEntity}
            onRemoveFromWatchlist={id => {
              api(`/api/watchlist/${id}`, { method: 'DELETE' }).catch(err => setNotice(err.message));
              setWatchlist(prev => prev.filter(w => w.id !== id));
            }}
            onAddToWatchlist={(entityId, reason) => {
              api<{ item: WatchlistItem }>('/api/watchlist', { method: 'POST', body: { entityId, reason, windowHours, t0: t0Param } })
                .then(d => {
                  setWatchlist(prev => [d.item, ...prev.filter(w => w.entityId !== d.item.entityId)]);
                  refreshLists();
                })
                .catch(err => setNotice(`Could not add to watchlist: ${err.message}`));
            }}
            searchParams={{ windowDays: windowDaysApprox, t0: t0Param }}
          />
        )}

        {activeTab === 'investigation' && (
          <div className="flex-1 flex flex-col h-full relative overflow-hidden">
            <div className="flex items-center gap-1 px-3 py-1.5 bg-slate-900 border-b border-slate-800">
              {tabButton('path', 'Attack Path', Route)}
              {tabButton('story', 'AI Storyline', Wand2)}
              {tabButton('graph', 'Relationship Graph', Share2)}
              {tabButton('timeline', `Event Timeline (${userProfile.edges.length})`, Table2)}
              {tabButton('notes', `Notes (${notes.length})`, NotebookPen)}
              {timelineNodeFilter && investigationView === 'timeline' && (
                <button onClick={() => setTimelineNodeFilter(null)} className="ml-2 px-2 py-0.5 rounded bg-slate-800 text-[11px] font-mono text-cyan-300">
                  Filtered to {nodeById.get(timelineNodeFilter)?.name || timelineNodeFilter} ✕
                </button>
              )}
              {loading && <span className="ml-auto text-[11px] font-mono text-slate-400">Refreshing...</span>}
            </div>
            <div className="flex-1 relative overflow-hidden">
              {investigationView === 'path' ? (
                <AttackPathCanvas
                  profile={userProfile}
                  currentHour={currentHour}
                  windowHours={windowHours}
                  onSelectNode={setSelectedNode}
                  selectedNodeId={selectedNode?.id || null}
                  highlightedCitationId={highlightedCitationId}
                  canvasRefCallback={handleCanvasRef}
                  isRecording={isRecording}
                  recordingWatermarkText={replaySettings.titleText || `CASE ${userProfile.id} // ${userProfile.username}`}
                  redactNames={replaySettings.redact}
                  theme={isDarkMode ? 'dark' : 'light'}
                  verdicts={verdicts}
                />
              ) : investigationView === 'graph' ? (
                <TemporalGraphCanvas
                  nodes={userProfile.nodes}
                  edges={userProfile.edges}
                  currentHour={currentHour}
                  windowHours={windowHours}
                  t0={userProfile.t0}
                  onSelectNode={setSelectedNode}
                  selectedNodeId={selectedNode?.id || null}
                  highlightedCitationId={highlightedCitationId}
                  canvasRefCallback={handleCanvasRef}
                  isRecording={isRecording}
                  recordingWatermarkText={replaySettings.titleText || `CASE ${userProfile.id} // ${userProfile.username}`}
                  redactNames={replaySettings.redact}
                  theme={isDarkMode ? 'dark' : 'light'}
                  truncated={userProfile.truncated}
                  totalNodeCount={userProfile.totalNodeCount}
                  totalEdgeCount={userProfile.totalEdgeCount}
                  onExpandNode={handleExpandNode}
                  onPinNode={handlePinNode}
                />
              ) : investigationView === 'story' ? (
                <StorylineView
                  storyline={storyline}
                  loading={storyLoading}
                  error={storyError}
                  status={status}
                  approvedCaseRef={storyApprovedRef}
                  onGenerate={generateStoryline}
                  onApprove={approveStoryline}
                  onCite={jumpToCitation}
                />
              ) : investigationView === 'notes' ? (
                <NotesPanel
                  notes={notes}
                  onAddNote={handleAddNote}
                  onSelectNode={id => { const n = nodeById.get(id); if (n) { setSelectedNode(n); } }}
                  caseRef={activeCase?.caseRef}
                />
              ) : (
                <TimelineLogTable
                  edges={timelineNodeFilter ? userProfile.edges.filter(e => e.source === timelineNodeFilter || e.target === timelineNodeFilter) : userProfile.edges}
                  nodes={userProfile.nodes}
                  currentHour={currentHour}
                  onJumpToHour={h => {
                    setCurrentHour(h);
                    setInvestigationView(pictureView);
                  }}
                  onSelectNode={setSelectedNode}
                />
              )}

              {(investigationView === 'path' || investigationView === 'graph') && (
                <button
                  onClick={() => setDossierOpen(true)}
                  className={`absolute bottom-16 ${selectedNode ? 'right-[27rem]' : 'right-4'} z-20 flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold rounded-xl shadow-sm text-xs font-mono transition-all`}
                >
                  <Sparkles className="w-4 h-4" />
                  <span>AI Case Summary</span>
                </button>
              )}

              {selected && (
                <div className="absolute top-0 right-0 h-full z-20">
                  <NodeDetailDrawer
                    key={selected.id}
                    node={selected}
                    nodes={userProfile.nodes}
                    edges={userProfile.edges}
                    notes={notes.filter(n => n.nodeId === selected.id)}
                    onClose={() => setSelectedNode(null)}
                    onFilterToNodeTimeline={nodeId => {
                      setTimelineNodeFilter(nodeId);
                      setInvestigationView('timeline');
                    }}
                    onExpandNode={handleExpandNode}
                    onPinNode={handlePinNode}
                    onSaveVerdict={handleSaveVerdict}
                    onSaveHypothesis={handleSaveHypothesis}
                    onSearchEntity={handleSearchEntity}
                  />
                </div>
              )}
            </div>

            {investigationView !== 'notes' && investigationView !== 'story' && (
              <TimeScrubber
                currentHour={currentHour}
                onChangeHour={setCurrentHour}
                isPlaying={isPlaying}
                onTogglePlay={() => setIsPlaying(p => !p)}
                playbackSpeed={playbackSpeed}
                onChangeSpeed={setPlaybackSpeed}
                milestones={userProfile.milestones}
                edges={userProfile.edges}
                windowHours={windowHours}
                t0={userProfile.t0}
                visibleNodeCount={visibleNodes.length}
                totalNodeCount={userProfile.nodes.length}
                visibleEdgeCount={visibleEdges.length}
              />
            )}
          </div>
        )}

        {activeTab === 'replay' && (
          <ReplayVideoStudio
            userProfile={userProfile}
            canvasElement={canvasElementRef.current}
            isRecording={isRecording}
            recordingProgress={recordingProgress}
            recordedVideo={recordedVideo}
            settings={replaySettings}
            onChangeSettings={setReplaySettings}
            recordingMime={pickRecordingMime()}
            activeCaseRef={activeCase?.caseRef || null}
            onStartRecording={startAutomatedRecording}
            onCancelRecording={cancelRecording}
            onRegisterEvidence={registerEvidence}
            onPushToTicket={handlePushToTicket}
          />
        )}

        {activeTab === 'cases' && (
          <CaseViewScreen
            cases={cases}
            activeCaseId={activeCaseId}
            onOpenCase={handleOpenCase}
            onExportTimelineJson={handleExportTimelineJson}
            onExportTimelineCsv={handleExportTimelineCsv}
          />
        )}

        {activeTab === 'integrations' && (
          <SecurityToolsIntegrationHub
            currentEntity={entityKey}
            status={status}
            graphNodeCount={userProfile.nodes.length}
            lastBuildMs={timeToContextMs}
            hosts={userProfile.nodes.filter(n => n.type === 'host').map(n => n.name)}
            ips={userProfile.nodes.filter(n => n.type === 'ip' || n.type === 'domain').map(n => n.name)}
            windowHours={windowHours}
            t0={userProfile.t0 || t0Param}
            onGraphChanged={reloadGraph}
            onBuildGraph={openSearch}
          />
        )}

        {activeTab === 'admin' && <AdminConfigScreen userKey={entityKey} windowDays={windowDaysApprox} t0={t0Param} onConfigSaved={reloadGraph} />}
      </main>

      {assignOpen && (
        <AssignCloseDialog
          caseRecord={activeCase}
          defaultAssignee={status?.analyst || ''}
          investigationLabel={userProfile.kind === 'search' ? `Log search: ${userProfile.query}` : userProfile.username}
          onCancel={() => setAssignOpen(false)}
          onSave={handleAssignClose}
        />
      )}

      {dossierOpen && (
        <div className="fixed inset-8 bg-white/95 dark:bg-slate-950/95 backdrop-blur-xl border border-slate-200 dark:border-slate-800 rounded-2xl shadow-2xl z-40 overflow-hidden flex flex-col text-slate-800 dark:text-slate-100">
          <div className="flex justify-end p-3 border-b border-slate-200 dark:border-slate-800">
            <button onClick={() => setDossierOpen(false)} className="px-3 py-1 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 rounded text-xs font-mono">
              ✕ Close
            </button>
          </div>
          <div className="flex-1 overflow-y-auto">
            <AICaseDossier
              userProfile={userProfile}
              entityKey={investigationKey || entityKey}
              aiConfigured={!!status?.aiConfigured}
              onCitationClick={citId => {
                setHighlightedCitationId(citId);
                setDossierOpen(false);
                setInvestigationView(pictureView);
                const edge = userProfile.edges.find(e => e.id === citId);
                if (edge) setCurrentHour(edge.hour);
                const node = userProfile.nodes.find(n => n.id === citId);
                if (node) setSelectedNode(node);
              }}
              onSaveCase={handleSaveCase}
            />
          </div>
        </div>
      )}

      {globalSearchOpen && (
        <div className="fixed inset-0 bg-slate-950/60 backdrop-blur-xs z-50 flex items-start justify-center pt-20 p-4" onClick={() => setGlobalSearchOpen(false)}>
          <div onClick={e => e.stopPropagation()} className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl w-full max-w-lg shadow-2xl overflow-hidden">
            <div className="flex items-center px-4 py-3 border-b border-slate-200 dark:border-slate-800 gap-3">
              <Search className="w-5 h-5 text-slate-400" />
              <input
                data-testid="global-search"
                type="text"
                autoFocus
                placeholder="Username, or a log search (e.g. powershell, host.name:pc01)..."
                value={globalSearchTerm}
                onChange={e => setGlobalSearchTerm(e.target.value)}
                onKeyDown={e => {
                  if (e.key === 'Enter' && globalSearchTerm.trim()) {
                    const t = globalSearchTerm.trim();
                    // Plain word: open that identity. Anything with field:value, quotes, spaces or wildcards: log search graph
                    if (/[:"*\s=()]/.test(t)) openSearch(t);
                    else openEntity(t);
                    setGlobalSearchOpen(false);
                    setGlobalSearchTerm('');
                  }
                }}
                className="w-full bg-transparent text-sm text-slate-900 dark:text-slate-100 placeholder-slate-400 focus:outline-none font-sans"
              />
              <kbd className="px-1.5 py-0.5 text-[10px] font-mono bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded text-slate-400">ESC</kbd>
            </div>

            <div className="p-3 max-h-96 overflow-y-auto space-y-1 text-xs font-mono">
              {globalSearchTerm.trim() && (
                <div
                  data-testid="search-graph-option"
                  onClick={() => { openSearch(globalSearchTerm.trim()); setGlobalSearchOpen(false); setGlobalSearchTerm(''); }}
                  className="flex items-center gap-2.5 p-2 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800/80 cursor-pointer text-slate-700 dark:text-slate-200"
                >
                  <Share2 className="w-4 h-4 text-cyan-500" />
                  <span>Graph log search: <b>{globalSearchTerm.trim()}</b> <span className="text-slate-400">({status?.queryLanguage || 'demo data'}, current window)</span></span>
                </div>
              )}
              <div className="text-[10px] uppercase font-bold text-slate-400 px-2 py-1 tracking-wider">Entities</div>
              {availableUsers
                .filter(u => !globalSearchTerm || u.username.toLowerCase().includes(globalSearchTerm.toLowerCase()) || u.fullName.toLowerCase().includes(globalSearchTerm.toLowerCase()))
                .map(u => (
                  <div
                    key={u.id}
                    onClick={() => {
                      openEntity(u.id);
                      setGlobalSearchOpen(false);
                      setGlobalSearchTerm('');
                    }}
                    className="flex items-center justify-between p-2 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800/80 cursor-pointer transition-colors"
                  >
                    <div className="flex items-center gap-2.5">
                      <div className="w-6 h-6 rounded-full bg-cyan-100 dark:bg-cyan-950 text-cyan-600 dark:text-cyan-400 font-bold flex items-center justify-center text-[10px]">
                        {u.username[0]?.toUpperCase()}
                      </div>
                      <div>
                        <div className="font-semibold text-slate-900 dark:text-slate-100">{u.fullName !== u.username ? `${u.fullName} (${u.username})` : u.username}</div>
                        <div className="text-[10px] text-slate-400">{u.triggerEvent}</div>
                      </div>
                    </div>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-100 dark:bg-red-950/60 text-red-600 dark:text-red-400 font-bold">Risk {u.riskScore}</span>
                  </div>
                ))}

              <div className="text-[10px] uppercase font-bold text-slate-400 px-2 pt-3 pb-1 tracking-wider">Quick Navigation</div>
              {[
                { tab: 'integrations' as ViewTab, label: 'Integrations & query console', Icon: Network, color: 'text-cyan-500' },
                { tab: 'replay' as ViewTab, label: 'Replay Studio', Icon: Video, color: 'text-purple-500' },
                { tab: 'cases' as ViewTab, label: 'Cases & Exports', Icon: FolderArchive, color: 'text-blue-500' },
                { tab: 'admin' as ViewTab, label: 'Admin, Tags & Audit Log', Icon: Settings, color: 'text-slate-400' },
              ].map(({ tab, label, Icon, color }) => (
                <div
                  key={tab}
                  onClick={() => { setActiveTab(tab); setGlobalSearchOpen(false); }}
                  className="flex items-center gap-2.5 p-2 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800/80 cursor-pointer text-slate-700 dark:text-slate-300"
                >
                  <Icon className={`w-4 h-4 ${color}`} />
                  <span>{label}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
