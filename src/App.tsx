import React, { useState, useEffect, useRef } from 'react';
import { Sparkles, Search, Command, X, ArrowRight, ShieldCheck, Activity, Users, Video, Network, Settings, FolderArchive } from 'lucide-react';
import { UserProfile, SecurityNode, SecurityEdge, ViewTab, WatchlistItem, CaseRecord } from './types';
import { TopNav } from './components/TopNav';
import { SIEMAlertBanner } from './components/SIEMAlertBanner';
import { TemporalGraphCanvas } from './components/TemporalGraphCanvas';
import { TimeScrubber } from './components/TimeScrubber';
import { NodeDetailDrawer } from './components/NodeDetailDrawer';
import { TimelineLogTable } from './components/TimelineLogTable';
import { ReplayVideoStudio } from './components/ReplayVideoStudio';
import { AICaseDossier } from './components/AICaseDossier';
import { WatchlistHome } from './components/WatchlistHome';
import { CaseViewScreen } from './components/CaseViewScreen';
import { AdminConfigScreen } from './components/AdminConfigScreen';
import { SecurityToolsIntegrationHub } from './components/SecurityToolsIntegrationHub';

export default function App() {
  const [activeTab, setActiveTab] = useState<ViewTab>('investigation');
  const [selectedUserId, setSelectedUserId] = useState<string>('jsmith');
  const [userProfile, setUserProfile] = useState<UserProfile | null>(null);
  const [availableUsers, setAvailableUsers] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  // Dual-Theme Support (Light / Dark)
  const [isDarkMode, setIsDarkMode] = useState<boolean>(true);
  const [globalSearchOpen, setGlobalSearchOpen] = useState<boolean>(false);
  const [globalSearchTerm, setGlobalSearchTerm] = useState<string>('');

  useEffect(() => {
    if (isDarkMode) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [isDarkMode]);

  // Ctrl+K Shortcut Handler
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setGlobalSearchOpen(prev => !prev);
      } else if (e.key === 'Escape') {
        setGlobalSearchOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // FR-03: Watchlist state
  const [watchlist, setWatchlist] = useState<WatchlistItem[]>([]);

  // FR-19: Cases state
  const [cases, setCases] = useState<CaseRecord[]>([]);

  // Configurable Window (48h default, up to 7 days)
  const [activeWindowDays, setActiveWindowDays] = useState<number>(2);

  // FR-09: Multi-entity overlay (overlay 2-5 entities to find shared infrastructure)
  const [multiEntityOverlayActive, setMultiEntityOverlayActive] = useState<boolean>(false);

  // Time Scrubber & Replay State
  const [currentHour, setCurrentHour] = useState<number>(0);
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [playbackSpeed, setPlaybackSpeed] = useState<number>(1);

  // Selected Node for Detail Drawer & Citation Highlights (FR-18)
  const [selectedNode, setSelectedNode] = useState<SecurityNode | null>(null);
  const [highlightedCitationId, setHighlightedCitationId] = useState<string | null>(null);

  // Canvas Reference & Client-Side Video Recording
  const canvasElementRef = useRef<HTMLCanvasElement | null>(null);
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const recordedChunksRef = useRef<Blob[]>([]);
  const [isRecording, setIsRecording] = useState<boolean>(false);
  const [recordingProgress, setRecordingProgress] = useState<number>(0);
  const [recordedVideoUrl, setRecordedVideoUrl] = useState<string | null>(null);

  // Fetch watchlist & cases on mount
  useEffect(() => {
    fetch('/api/users')
      .then(res => res.json())
      .then(data => {
        if (data.users) setAvailableUsers(data.users);
      });

    fetch('/api/watchlist')
      .then(res => res.json())
      .then(data => {
        if (data.items) setWatchlist(data.items);
      });

    fetch('/api/cases')
      .then(res => res.json())
      .then(data => {
        if (data.cases) setCases(data.cases);
      });
  }, []);

  // Fetch user profile subgraph
  useEffect(() => {
    setLoading(true);
    fetch(`/api/graph/${selectedUserId}?windowDays=${activeWindowDays}`)
      .then(res => res.json())
      .then(data => {
        if (data.profile) {
          setUserProfile(data.profile);
          setCurrentHour(0);
          setSelectedNode(null);
          setHighlightedCitationId(null);
        }
      })
      .catch(err => console.error('Failed to fetch user graph', err))
      .finally(() => setLoading(false));
  }, [selectedUserId, activeWindowDays]);

  // Deep Link support (FR-02: /?entity=jsmith&alert_time=48)
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const entityParam = params.get('entity');
    const alertTime = params.get('alert_time');
    if (entityParam) {
      setSelectedUserId(entityParam.toLowerCase().replace(/[^a-z0-9]/g, ''));
    }
    if (alertTime) {
      setCurrentHour(parseInt(alertTime, 10) || 0);
    }
  }, []);

  const handleCanvasRef = (canvas: HTMLCanvasElement | null) => {
    canvasElementRef.current = canvas;
  };

  const handleSelectNode = (node: SecurityNode) => {
    setSelectedNode(node);
  };

  // FR-06: 1-Hop Expand Node On-Demand
  const handleExpandNode = async (nodeId: string) => {
    try {
      const res = await fetch('/api/graph/expand', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ nodeId, userKey: selectedUserId })
      });
      const data = await res.json();
      if (data.nodes && data.edges && userProfile) {
        setUserProfile({
          ...userProfile,
          nodes: [...userProfile.nodes, ...data.nodes],
          edges: [...userProfile.edges, ...data.edges]
        });
      }
    } catch (err) {
      console.error('Failed to expand node', err);
    }
  };

  const handlePinNode = (nodeId: string) => {
    if (!userProfile) return;
    setUserProfile({
      ...userProfile,
      nodes: userProfile.nodes.map(n => n.id === nodeId ? { ...n, pinned: !n.pinned } : n)
    });
  };

  const handleTagVerdict = (targetId: string, verdict: 'BENIGN' | 'MALICIOUS') => {
    fetch('/api/feedback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targetId, verdict, note: 'Tagged from Entity Detail Drawer' })
    });
  };

  // FR-19: Save Investigation as Case
  const handleSaveCase = () => {
    if (!userProfile) return;
    fetch('/api/cases', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title: `${userProfile.triggerEvent} - ${userProfile.username}`,
        rootEntity: `${userProfile.username} (${userProfile.id})`,
        severity: 'P1',
        userKey: selectedUserId
      })
    })
      .then(res => res.json())
      .then(data => {
        if (data.case) {
          setCases(prev => [data.case, ...prev]);
          setActiveTab('cases');
        }
      });
  };

  // FR-20: Push to Ticketing System
  const handlePushToTicket = (system: 'jira' | 'slack' | 'servicenow') => {
    if (cases.length > 0) {
      fetch(`/api/cases/${cases[0].id}/push`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: system })
      })
        .then(res => res.json())
        .then(data => {
          if (data.pushedTo) {
            setCases(prev => prev.map((c, i) => i === 0 ? { ...c, pushedTo: data.pushedTo } : c));
          }
        });
    }
  };

  // Automated Replay Video Recording
  const startAutomatedRecording = () => {
    const canvas = canvasElementRef.current;
    if (!canvas) return;

    try {
      setCurrentHour(48);
      setRecordingProgress(0);
      setIsRecording(true);
      recordedChunksRef.current = [];

      const stream = canvas.captureStream(30);
      let mimeType = 'video/webm;codecs=vp9';
      if (!MediaRecorder.isTypeSupported(mimeType)) mimeType = 'video/webm';
      if (!MediaRecorder.isTypeSupported(mimeType)) mimeType = '';

      const recorder = new MediaRecorder(stream, mimeType ? { mimeType } : undefined);
      mediaRecorderRef.current = recorder;

      recorder.ondataavailable = (event) => {
        if (event.data && event.data.size > 0) {
          recordedChunksRef.current.push(event.data);
        }
      };

      recorder.onstop = () => {
        const blob = new Blob(recordedChunksRef.current, { type: 'video/webm' });
        const videoUrl = URL.createObjectURL(blob);
        setRecordedVideoUrl(videoUrl);
        setIsRecording(false);
        setActiveTab('replay');
      };

      recorder.start(100);

      let currentStep = 48;
      const stepDuration = 250;

      const replayTimer = setInterval(() => {
        currentStep -= 1;
        if (currentStep < 0) {
          clearInterval(replayTimer);
          setCurrentHour(0);
          setRecordingProgress(100);
          setTimeout(() => {
            if (recorder.state !== 'inactive') recorder.stop();
          }, 500);
        } else {
          setCurrentHour(currentStep);
          setRecordingProgress(((48 - currentStep) / 48) * 100);
        }
      }, stepDuration);

    } catch (err) {
      console.error('Error starting recording', err);
      setIsRecording(false);
    }
  };

  const cancelRecording = () => {
    if (mediaRecorderRef.current && mediaRecorderRef.current.state !== 'inactive') {
      mediaRecorderRef.current.stop();
    }
    setIsRecording(false);
    setRecordingProgress(0);
  };

  // FR-21: Export Timeline CSV / JSON
  const handleExportTimelineJson = () => {
    if (!userProfile) return;
    const blob = new Blob([JSON.stringify(userProfile, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `watchme_timeline_${userProfile.username}_48h.json`;
    link.click();
  };

  const handleExportTimelineCsv = () => {
    if (!userProfile) return;
    const headers = 'ID,Hour_Offset,Action,Protocol,Source,Target,Event_Count,Status,MITRE_TTP,Details\n';
    const rows = userProfile.edges.map(e => 
      `"${e.id}","T-${e.hour}h","${e.action}","${e.protocol}","${e.source}","${e.target}","${e.eventCount}","${e.status}","${(e.ttp || []).join(';')}","${e.details.replace(/"/g, '""')}"`
    ).join('\n');
    const blob = new Blob([headers + rows], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `watchme_timeline_${userProfile.username}_48h.csv`;
    link.click();
  };

  if (loading || !userProfile) {
    return (
      <div className="w-screen h-screen bg-slate-950 flex flex-col items-center justify-center text-slate-400 font-mono text-sm space-y-3">
        <div className="w-8 h-8 rounded-full border-2 border-cyan-400 border-t-transparent animate-spin" />
        <div className="flex items-center gap-2">
          <span>MEMGRAPH GRAPHQL ENGINE INITIALIZING</span>
          <span className="text-cyan-400 animate-pulse">●</span>
        </div>
      </div>
    );
  }

  const visibleNodes = userProfile.nodes.filter(n => n.firstSeenHour >= currentHour);
  const visibleEdges = userProfile.edges.filter(e => {
    const src = userProfile.nodes.find(n => n.id === e.source);
    const tgt = userProfile.nodes.find(n => n.id === e.target);
    return src && tgt && src.firstSeenHour >= currentHour && tgt.firstSeenHour >= currentHour && e.hour >= currentHour;
  });

  return (
    <div className="flex flex-col w-screen h-screen overflow-hidden bg-slate-100 dark:bg-slate-950 text-slate-900 dark:text-slate-100 font-sans transition-colors duration-200">
      {/* 1. Section 10 Top Navigation */}
      <TopNav
        activeTab={activeTab}
        onChangeTab={setActiveTab}
        selectedUser={userProfile}
        availableUsers={availableUsers}
        onSelectUser={setSelectedUserId}
        onGenerateReplayClick={() => {
          setActiveTab('replay');
          startAutomatedRecording();
        }}
        isRecording={isRecording}
        activeWindowDays={activeWindowDays}
        onChangeWindowDays={setActiveWindowDays}
        isDarkMode={isDarkMode}
        onToggleDarkMode={() => setIsDarkMode(prev => !prev)}
        onOpenGlobalSearch={() => setGlobalSearchOpen(true)}
      />

      {/* 2. SIEM Alert Contextual Banner */}
      <SIEMAlertBanner
        userProfile={userProfile}
        onExploreGraph={() => setActiveTab('investigation')}
        onQuickReplay={() => {
          setActiveTab('investigation');
          setCurrentHour(48);
          setIsPlaying(true);
        }}
      />

      {/* 3. Main Workspace Viewport (Section 10 Six Screens) */}
      <main className="flex-1 relative flex overflow-hidden">
        {/* SCREEN 1: Watchlist Home */}
        {activeTab === 'watchlist' && (
          <WatchlistHome
            watchlist={watchlist}
            onSelectEntity={(entId) => {
              setSelectedUserId(entId);
              setActiveTab('investigation');
            }}
            onRemoveFromWatchlist={(id) => {
              fetch(`/api/watchlist/${id}`, { method: 'DELETE' });
              setWatchlist(prev => prev.filter(w => w.id !== id));
            }}
            onAddToWatchlist={(entityId, reason) => {
              fetch('/api/watchlist', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ entityId, reason })
              })
                .then(res => res.json())
                .then(d => {
                  if (d.item) setWatchlist(prev => [d.item, ...prev]);
                });
            }}
          />
        )}

        {/* SCREEN 2: Investigation Main Canvas */}
        {activeTab === 'investigation' && (
          <div className="flex-1 flex flex-col h-full relative overflow-hidden">
            <div className="flex-1 relative overflow-hidden">
              <TemporalGraphCanvas
                nodes={userProfile.nodes}
                edges={userProfile.edges}
                currentHour={currentHour}
                onSelectNode={handleSelectNode}
                selectedNodeId={selectedNode?.id || null}
                highlightedCitationId={highlightedCitationId}
                canvasRefCallback={handleCanvasRef}
                isRecording={isRecording}
                recordingWatermarkText={`#CASE-${userProfile.id} // User: ${userProfile.username}`}
                onExpandNode={handleExpandNode}
                onPinNode={handlePinNode}
              />

              {/* Side Detail Drawer (FR-13 & FR-14) */}
              {selectedNode && (
                <div className="absolute top-0 right-0 h-full z-20">
                  <NodeDetailDrawer
                    node={selectedNode}
                    edges={userProfile.edges}
                    onClose={() => setSelectedNode(null)}
                    onFilterToNodeTimeline={() => {}}
                    onExpandNode={handleExpandNode}
                    onPinNode={handlePinNode}
                    onTagVerdict={handleTagVerdict}
                  />
                </div>
              )}
            </div>

            {/* Time Scrubber & Event Density Histogram (FR-10, FR-11, FR-12) */}
            <TimeScrubber
              currentHour={currentHour}
              onChangeHour={setCurrentHour}
              isPlaying={isPlaying}
              onTogglePlay={() => setIsPlaying(p => !p)}
              playbackSpeed={playbackSpeed}
              onChangeSpeed={setPlaybackSpeed}
              milestones={userProfile.milestones}
              visibleNodeCount={visibleNodes.length}
              totalNodeCount={userProfile.nodes.length}
              visibleEdgeCount={visibleEdges.length}
            />
          </div>
        )}

        {/* SCREEN 3: Replay Video Studio (Section 8) */}
        {activeTab === 'replay' && (
          <ReplayVideoStudio
            userProfile={userProfile}
            canvasElement={canvasElementRef.current}
            onRunReplay={() => {
              setCurrentHour(48);
              setIsPlaying(true);
              setActiveTab('investigation');
            }}
            isRecording={isRecording}
            recordingProgress={recordingProgress}
            recordedVideoUrl={recordedVideoUrl}
            onStartRecording={startAutomatedRecording}
            onCancelRecording={cancelRecording}
            onPushToTicket={handlePushToTicket}
          />
        )}

        {/* SCREEN 4: Cases & Evidence Repository */}
        {activeTab === 'cases' && (
          <CaseViewScreen
            cases={cases}
            onOpenCase={() => setActiveTab('investigation')}
            onExportTimelineJson={handleExportTimelineJson}
            onExportTimelineCsv={handleExportTimelineCsv}
          />
        )}

        {/* SCREEN 5: SIEM & Security Tools Integrations Hub */}
        {activeTab === 'integrations' && (
          <SecurityToolsIntegrationHub
            currentEntity={userProfile.username}
            onSyncComplete={(count) => {
              fetch(`/api/graph/${selectedUserId}?windowDays=${activeWindowDays}`)
                .then(res => res.json())
                .then(data => {
                  if (data.profile) setUserProfile(data.profile);
                });
            }}
            onAlertInjected={(newNode) => {
              setUserProfile(prev => {
                if (!prev) return prev;
                return {
                  ...prev,
                  nodes: [newNode, ...prev.nodes]
                };
              });
            }}
          />
        )}

        {/* SCREEN 6: Admin & Rules Screen */}
        {activeTab === 'admin' && (
          <AdminConfigScreen userKey={selectedUserId} />
        )}
      </main>

      {/* Floating Drawer Trigger for AI Case Summary (Section 7) */}
      {activeTab === 'investigation' && (
        <div className="absolute bottom-28 right-6 z-20">
          <button
            onClick={() => {
              const modal = document.getElementById('ai-dossier-modal');
              if (modal) modal.classList.toggle('hidden');
            }}
            className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold rounded-xl shadow-[0_0_20px_rgba(6,182,212,0.5)] text-xs font-mono transition-all"
          >
            <Sparkles className="w-4 h-4" />
            <span>AI Case Dossier (Gemini 3.8)</span>
          </button>
        </div>
      )}

      {/* AI Case Dossier Modal (Section 7) */}
      <div id="ai-dossier-modal" className="hidden fixed inset-8 bg-white/95 dark:bg-slate-950/95 backdrop-blur-xl border border-slate-200 dark:border-slate-800 rounded-2xl shadow-2xl z-40 overflow-hidden flex flex-col text-slate-800 dark:text-slate-100">
        <div className="flex justify-end p-3 border-b border-slate-200 dark:border-slate-800">
          <button
            onClick={() => {
              const modal = document.getElementById('ai-dossier-modal');
              if (modal) modal.classList.add('hidden');
            }}
            className="px-3 py-1 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 rounded text-xs font-mono"
          >
            ✕ Close Dossier
          </button>
        </div>
        <div className="flex-1 overflow-y-auto">
          <AICaseDossier
            userProfile={userProfile}
            onCitationClick={(citId) => {
              setHighlightedCitationId(citId);
              const modal = document.getElementById('ai-dossier-modal');
              if (modal) modal.classList.add('hidden');
              // Find matching edge or node and jump scrubber
              const edge = userProfile.edges.find(e => e.id === citId);
              if (edge) setCurrentHour(edge.hour);
              const node = userProfile.nodes.find(n => n.id === citId);
              if (node) setSelectedNode(node);
            }}
            onSaveCase={handleSaveCase}
          />
        </div>
      </div>

      {/* Global Command Palette / Search Modal (Ctrl+K) */}
      {globalSearchOpen && (
        <div className="fixed inset-0 bg-slate-950/60 backdrop-blur-xs z-50 flex items-start justify-center pt-20 p-4">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl w-full max-w-lg shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
            {/* Search Input */}
            <div className="flex items-center px-4 py-3 border-b border-slate-200 dark:border-slate-800 gap-3">
              <Search className="w-5 h-5 text-slate-400" />
              <input
                type="text"
                autoFocus
                placeholder="Search identities, SIEM alerts, connectors, crown jewels..."
                value={globalSearchTerm}
                onChange={(e) => setGlobalSearchTerm(e.target.value)}
                className="w-full bg-transparent text-sm text-slate-900 dark:text-slate-100 placeholder-slate-400 focus:outline-none font-sans"
              />
              <kbd className="px-1.5 py-0.5 text-[10px] font-mono bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded text-slate-400">
                ESC
              </kbd>
            </div>

            {/* Quick Actions & Search Results */}
            <div className="p-3 max-h-80 overflow-y-auto space-y-1 text-xs font-mono">
              <div className="text-[10px] uppercase font-bold text-slate-400 px-2 py-1 tracking-wider">
                Entities & Identities
              </div>
              {availableUsers
                .filter(u => !globalSearchTerm || u.username.toLowerCase().includes(globalSearchTerm.toLowerCase()) || u.fullName.toLowerCase().includes(globalSearchTerm.toLowerCase()))
                .map(u => (
                  <div
                    key={u.id}
                    onClick={() => {
                      setSelectedUserId(u.username.replace(/[^a-z0-9]/g, ''));
                      setActiveTab('investigation');
                      setGlobalSearchOpen(false);
                      setGlobalSearchTerm('');
                    }}
                    className="flex items-center justify-between p-2 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800/80 cursor-pointer transition-colors"
                  >
                    <div className="flex items-center gap-2.5">
                      <div className="w-6 h-6 rounded-full bg-cyan-100 dark:bg-cyan-950 text-cyan-600 dark:text-cyan-400 font-bold flex items-center justify-center text-[10px]">
                        {u.username[0].toUpperCase()}
                      </div>
                      <div>
                        <div className="font-semibold text-slate-900 dark:text-slate-100">{u.fullName} ({u.username})</div>
                        <div className="text-[10px] text-slate-400">{u.triggerEvent}</div>
                      </div>
                    </div>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-100 dark:bg-red-950/60 text-red-600 dark:text-red-400 font-bold">
                      Risk {u.riskScore}
                    </span>
                  </div>
                ))}

              <div className="text-[10px] uppercase font-bold text-slate-400 px-2 pt-3 pb-1 tracking-wider">
                Quick Navigation
              </div>
              <div
                onClick={() => { setActiveTab('integrations'); setGlobalSearchOpen(false); }}
                className="flex items-center gap-2.5 p-2 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800/80 cursor-pointer text-slate-700 dark:text-slate-300"
              >
                <Network className="w-4 h-4 text-cyan-500" />
                <span>SIEM & Security Tools Integration Hub</span>
              </div>
              <div
                onClick={() => { setActiveTab('replay'); setGlobalSearchOpen(false); }}
                className="flex items-center gap-2.5 p-2 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800/80 cursor-pointer text-slate-700 dark:text-slate-300"
              >
                <Video className="w-4 h-4 text-purple-500" />
                <span>Replay Video Studio (MP4 / WebM Evidence)</span>
              </div>
              <div
                onClick={() => { setActiveTab('cases'); setGlobalSearchOpen(false); }}
                className="flex items-center gap-2.5 p-2 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800/80 cursor-pointer text-slate-700 dark:text-slate-300"
              >
                <FolderArchive className="w-4 h-4 text-blue-500" />
                <span>Cases & Forensic Timeline Exports</span>
              </div>
              <div
                onClick={() => { setActiveTab('admin'); setGlobalSearchOpen(false); }}
                className="flex items-center gap-2.5 p-2 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800/80 cursor-pointer text-slate-700 dark:text-slate-300"
              >
                <Settings className="w-4 h-4 text-slate-400" />
                <span>Admin & Detection Rule Tuning (YARA-L / KQL)</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
