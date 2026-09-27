import React, { useState } from 'react';
import { Video, Download, CheckCircle2, Camera, Hash, Sliders, Send, AlertTriangle, FileCheck } from 'lucide-react';
import { UserProfile } from '../types';

export interface RecordedVideo {
  url: string;
  mimeType: string;
  sizeBytes: number;
  sha256: string; // computed in the browser over the exact file bytes
  fileName: string;
  width: number;
  height: number;
  durationSecs: number;
  registeredCaseRef?: string;
}

export interface ReplaySettings {
  durationSecs: number;
  redact: boolean;
  titleText: string;
}

interface Props {
  userProfile: UserProfile;
  canvasElement: HTMLCanvasElement | null;
  isRecording: boolean;
  recordingProgress: number;
  recordedVideo: RecordedVideo | null;
  settings: ReplaySettings;
  onChangeSettings: (s: ReplaySettings) => void;
  recordingMime: string; // what this browser will record ('' = unsupported)
  activeCaseRef: string | null;
  onStartRecording: () => void;
  onCancelRecording: () => void;
  onRegisterEvidence: (video: RecordedVideo) => void;
  onPushToTicket?: (system: 'jira' | 'slack' | 'servicenow') => void;
}

const formatBytes = (n: number) => (n > 1048576 ? `${(n / 1048576).toFixed(2)} MB` : `${Math.max(1, Math.round(n / 1024))} KB`);

export const ReplayVideoStudio: React.FC<Props> = ({
  userProfile,
  canvasElement,
  isRecording,
  recordingProgress,
  recordedVideo,
  settings,
  onChangeSettings,
  recordingMime,
  activeCaseRef,
  onStartRecording,
  onCancelRecording,
  onRegisterEvidence,
  onPushToTicket,
}) => {
  const [copiedHash, setCopiedHash] = useState(false);
  const formatLabel = !recordingMime ? 'Unsupported' : recordingMime.includes('mp4') ? 'MP4 (H.264)' : 'WebM';
  const overTarget = recordedVideo && recordedVideo.sizeBytes > 8 * 1048576;

  const copyHash = () => {
    if (!recordedVideo) return;
    navigator.clipboard.writeText(recordedVideo.sha256);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  const handleTakeSnapshot = () => {
    if (!canvasElement || !canvasElement.isConnected) return;
    try {
      const link = document.createElement('a');
      link.download = `watchme_${userProfile.username.replace(/[^A-Za-z0-9._-]/g, '_')}_graph.png`;
      link.href = canvasElement.toDataURL('image/png');
      link.click();
    } catch (err) {
      console.error('Failed to capture snapshot', err);
    }
  };

  return (
    <div className="w-full h-full flex flex-col p-6 space-y-6 overflow-y-auto">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs mb-1">
            <Video className="w-4 h-4" />
            <span>REPLAY EVIDENCE</span>
          </div>
          <h2 className="text-xl font-bold text-slate-100">Timeline Replay Studio</h2>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            Records the graph canvas while the timeline plays from T-{userProfile.windowHours ?? 48}h to T-0, with the timeline clock and case title burned in. The file's SHA-256 is computed in your browser and can be registered with the case.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleTakeSnapshot}
            disabled={!canvasElement?.isConnected}
            title={canvasElement?.isConnected ? 'Download the current graph as PNG' : 'Open the Investigation tab first'}
            className="flex items-center gap-2 px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-semibold transition-colors disabled:opacity-40"
          >
            <Camera className="w-4 h-4 text-cyan-400" />
            <span>Snapshot PNG</span>
          </button>

          {!isRecording ? (
            <button
              onClick={onStartRecording}
              disabled={!recordingMime}
              className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded-lg text-xs font-semibold shadow-[0_0_15px_rgba(239,68,68,0.5)] transition-all disabled:opacity-40"
            >
              <Video className="w-4 h-4" />
              <span>Record {settings.durationSecs}s Replay ({formatLabel})</span>
            </button>
          ) : (
            <button onClick={onCancelRecording} className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-red-400 border border-red-500/40 rounded-lg text-xs font-semibold transition-colors">
              <span>Cancel Recording</span>
            </button>
          )}
        </div>
      </div>

      {isRecording && (
        <div className="p-4 bg-slate-900 border border-red-500/40 rounded-xl space-y-3">
          <div className="flex items-center justify-between text-xs font-mono">
            <div className="flex items-center gap-2 text-red-400">
              <span className="w-2.5 h-2.5 rounded-full bg-red-500 animate-ping" />
              <span className="font-semibold">RECORDING CANVAS ({formatLabel}, 30 fps)...</span>
            </div>
            <span className="text-slate-300 font-bold tabular-nums">{Math.round(recordingProgress)}%</span>
          </div>
          <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden border border-slate-800">
            <div className="bg-gradient-to-r from-cyan-500 via-amber-500 to-red-500 h-full transition-all duration-200" style={{ width: `${recordingProgress}%` }} />
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-7 bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2 text-xs font-mono text-slate-300">
                <Video className="w-4 h-4 text-cyan-400" />
                <span className="font-semibold">VIDEO PREVIEW</span>
              </div>
              {recordedVideo?.registeredCaseRef && (
                <span className="text-xs font-mono text-emerald-400 flex items-center gap-1">
                  <CheckCircle2 className="w-3.5 h-3.5" /> Registered with {recordedVideo.registeredCaseRef}
                </span>
              )}
            </div>

            {recordedVideo ? (
              <div className="relative rounded-lg overflow-hidden border border-slate-800 bg-slate-950 aspect-video flex items-center justify-center">
                <video src={recordedVideo.url} controls autoPlay loop className="w-full h-full object-contain" />
              </div>
            ) : (
              <div className="aspect-video bg-slate-950 border border-slate-800/80 rounded-lg flex flex-col items-center justify-center p-6 text-center">
                <Video className="w-6 h-6 text-slate-500 mb-3" />
                <h4 className="text-sm font-semibold text-slate-200 mb-1">No replay recorded yet</h4>
                <p className="text-xs text-slate-400 max-w-sm mb-4">
                  {recordingMime
                    ? 'Recording switches to the graph view, plays the timeline, then returns here with the file.'
                    : 'This browser cannot record canvas video (MediaRecorder unsupported). Use Chrome or Edge.'}
                </p>
                <button
                  onClick={onStartRecording}
                  disabled={!recordingMime || isRecording}
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs rounded-lg transition-colors disabled:opacity-40"
                >
                  Generate Replay
                </button>
              </div>
            )}
          </div>

          {recordedVideo && (
            <div className="mt-4 pt-4 border-t border-slate-800 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="text-xs font-mono text-slate-400">
                  {recordedVideo.mimeType} · {recordedVideo.width}×{recordedVideo.height} · ~{recordedVideo.durationSecs}s · {formatBytes(recordedVideo.sizeBytes)}
                  {overTarget && <span className="text-amber-400"> · over the 8 MB ticket target</span>}
                </div>
                <div className="flex items-center gap-2">
                  {!recordedVideo.registeredCaseRef && (
                    <button
                      onClick={() => onRegisterEvidence(recordedVideo)}
                      className="flex items-center gap-2 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-semibold"
                      title={activeCaseRef ? `Record this file's hash on ${activeCaseRef}` : 'Creates a case for this investigation and records the hash'}
                    >
                      <FileCheck className="w-4 h-4 text-cyan-400" />
                      <span>{activeCaseRef ? `Register with ${activeCaseRef}` : 'Save case & register'}</span>
                    </button>
                  )}
                  <a
                    href={recordedVideo.url}
                    download={recordedVideo.fileName}
                    className="flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold transition-colors shadow-md"
                  >
                    <Download className="w-4 h-4" />
                    <span>Download .{recordedVideo.fileName.split('.').pop()}</span>
                  </a>
                </div>
              </div>

              <div className="p-2.5 bg-slate-950 border border-slate-800 rounded-lg flex items-center justify-between text-xs font-mono">
                <div className="flex items-center gap-2 text-slate-400 truncate">
                  <Hash className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                  <span className="shrink-0">SHA-256:</span>
                  <span className="text-slate-300 truncate">{recordedVideo.sha256}</span>
                </div>
                <button onClick={copyHash} className="px-2 py-0.5 bg-slate-900 hover:bg-slate-800 text-slate-300 rounded text-[11px] shrink-0 transition-colors">
                  {copiedHash ? 'Copied' : 'Copy Hash'}
                </button>
              </div>
            </div>
          )}
        </div>

        <div className="lg:col-span-5 space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3 text-xs font-mono">
            <div className="flex items-center gap-2 text-slate-200 font-semibold border-b border-slate-800 pb-2">
              <Sliders className="w-4 h-4 text-cyan-400" />
              <span>EXPORT CONTROLS</span>
            </div>

            <div className="flex justify-between items-center">
              <span className="text-slate-400">Format (this browser):</span>
              <span className="text-slate-200 font-semibold">{formatLabel}</span>
            </div>
            {recordingMime && !recordingMime.includes('mp4') && (
              <div className="flex gap-2 text-[11px] text-amber-300">
                <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                <span>This browser records WebM. Chrome and Edge can record MP4. GIF export is not available.</span>
              </div>
            )}

            <div className="flex justify-between items-center">
              <span className="text-slate-400">Duration:</span>
              <div className="flex gap-1">
                {[15, 30, 60].map(s => (
                  <button
                    key={s}
                    disabled={isRecording}
                    onClick={() => onChangeSettings({ ...settings, durationSecs: s })}
                    className={`px-2.5 py-1 rounded font-semibold transition-colors ${settings.durationSecs === s ? 'bg-cyan-500 text-slate-950' : 'bg-slate-800 text-slate-400'}`}
                  >
                    {s}s
                  </button>
                ))}
              </div>
            </div>

            <div className="flex justify-between items-center">
              <span className="text-slate-400">Resolution:</span>
              <span className="text-slate-300">Canvas size{canvasElement?.isConnected ? ` (${canvasElement.width}×${canvasElement.height})` : ''}; resize the window to change it</span>
            </div>

            <label className="flex justify-between items-center pt-1 border-t border-slate-800/80 cursor-pointer">
              <div>
                <span className="text-slate-300 block font-semibold">Redaction mode</span>
                <span className="text-[10px] text-slate-500">Replace entity names with tokens (USER_1, HOST_2) in the video</span>
              </div>
              <input
                type="checkbox"
                checked={settings.redact}
                disabled={isRecording}
                onChange={e => onChangeSettings({ ...settings, redact: e.target.checked })}
                className="rounded bg-slate-800 border-slate-700 text-cyan-500 focus:ring-cyan-400"
              />
            </label>

            <div className="pt-1 border-t border-slate-800/80">
              <span className="text-[10px] text-slate-400 block mb-1">Title (burned into the video):</span>
              <input
                type="text"
                value={settings.titleText}
                disabled={isRecording}
                maxLength={60}
                onChange={e => onChangeSettings({ ...settings, titleText: e.target.value })}
                className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-xs text-slate-200 focus:outline-none focus:ring-1 focus:ring-cyan-500"
              />
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <span className="text-xs font-mono font-semibold text-slate-200">TICKET HANDOVER</span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40">SIMULATED</span>
            </div>
            <p className="text-xs text-slate-400">
              Jira, Slack and ServiceNow are not connected yet. Pushing records a simulated handover on the case{activeCaseRef ? ` (${activeCaseRef})` : ' (a case is created if needed)'}; nothing is sent. Download the video and attach it manually for now.
            </p>
            <div className="space-y-2">
              {([
                ['jira', 'Jira (create issue)'],
                ['slack', 'Slack (#incident-response)'],
                ['servicenow', 'ServiceNow SecOps'],
              ] as const).map(([sys, label]) => (
                <button
                  key={sys}
                  onClick={() => onPushToTicket?.(sys)}
                  className="w-full flex items-center justify-between p-2.5 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded-lg text-xs font-mono transition-colors"
                >
                  <span className="text-slate-200">{label}</span>
                  <Send className="w-3.5 h-3.5 text-cyan-400" />
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
