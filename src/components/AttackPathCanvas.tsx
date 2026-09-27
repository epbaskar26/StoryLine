import React, { useEffect, useMemo, useRef, useState } from 'react';
import { ZoomIn, ZoomOut, RotateCcw, LocateFixed, Route, Info } from 'lucide-react';
import type { SecurityEdge, SecurityNode, UserProfile } from '../types';
import { buildAttackPath, displayedSteps, formatGap, type DisplayedStep } from '../attackPath';
import { hourToUtc } from '../api';

interface Props {
  profile: UserProfile;
  currentHour: number;
  windowHours: number;
  onSelectNode: (node: SecurityNode) => void;
  selectedNodeId: string | null;
  highlightedCitationId?: string | null;
  canvasRefCallback?: (canvas: HTMLCanvasElement | null) => void;
  isRecording?: boolean;
  recordingWatermarkText?: string;
  redactNames?: boolean;
  theme?: 'light' | 'dark';
}

const PALETTES = {
  light: {
    recordingBg: '#FFFFFF', card: '#FFFFFF', cardBorder: '#E3E6EA', text: '#121314', sub: '#74767A', faint: '#A9ACB1',
    connector: '#C3C7CE', connectorCritical: '#D75054', connectorAnomalous: '#FBA21B', label: '#74767A',
    tacticBg: '#EEF1FD', tacticText: '#2740CB', revisitBg: '#843CF3', revisitText: '#FFFFFF', note: '#6A2BC9', loginNote: '#018102',
    chipBg: '#F6F8FA', chipBorder: '#DDE0E4', chipText: '#74767A', ring: '#2740CB',
    bar: { critical: '#D75054', anomalous: '#FBA21B', blocked: '#A9ACB1', allowed: '#13A8B1', start: '#2740CB' },
    overlayBg: 'rgba(255, 255, 255, 0.96)', overlayBorder: '#2740CB', overlayRec: '#D75054', overlayClock: '#2740CB', overlayWarn: '#B06A00',
  },
  dark: {
    recordingBg: '#020617', card: '#0f172a', cardBorder: '#1e293b', text: '#f1f5f9', sub: '#94a3b8', faint: '#64748b',
    connector: '#334155', connectorCritical: '#ef4444', connectorAnomalous: '#f59e0b', label: '#94a3b8',
    tacticBg: '#0c2a3f', tacticText: '#7dd3fc', revisitBg: '#9333ea', revisitText: '#FFFFFF', note: '#c084fc', loginNote: '#34d399',
    chipBg: '#1e293b', chipBorder: '#334155', chipText: '#94a3b8', ring: '#38bdf8',
    bar: { critical: '#ef4444', anomalous: '#f59e0b', blocked: '#64748b', allowed: '#14b8a6', start: '#38bdf8' },
    overlayBg: 'rgba(2, 6, 23, 0.9)', overlayBorder: '#ef4444', overlayRec: '#ef4444', overlayClock: '#38bdf8', overlayWarn: '#fbbf24',
  },
};

// Short connector labels so they fit between cards
const STEP_LABEL: Record<string, string> = {
  AUTH_SUCCESS: 'login', AUTH_FAIL: 'failed login', FROM_IP: 'from IP', CONNECTED_TO: 'connected', ACCESSED: 'accessed',
  EXECUTED: 'ran', RAN_ON: 'on host', MEMBER_CHANGE: 'group change', UPLOADED: 'upload', TRIGGERED: 'alert',
};

const ICONS: Record<string, string> = { user: '👤', host: '💻', ip: '🌐', application: '🗄️', file: '📄', process: '⚡', domain: '☁️', alert: '🚨' };

// Layout (world units, before zoom)
const CARD_W = 196;
const CARD_H = 70;
const GAP_X = 72;
const ROW_H = CARD_H + 78; // room for the tactic chip above and the note below
const PAD_X = 32;
const PAD_TOP = 40;
const FONT = 'Inter, -apple-system, "Segoe UI", sans-serif';

interface Placed {
  kind: 'start' | 'step';
  step?: DisplayedStep;
  node: SecurityNode;
  x: number;
  y: number;
}

interface ChipHit { x: number; y: number; w: number; h: number }

function fmtTime(ms: number): string {
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return '';
  const iso = d.toISOString();
  return `${iso.slice(5, 10)} ${iso.slice(11, 16)} UTC`;
}

function truncate(ctx: CanvasRenderingContext2D, text: string, max: number): string {
  if (ctx.measureText(text).width <= max) return text;
  let t = text;
  while (t.length > 1 && ctx.measureText(t + '…').width > max) t = t.slice(0, -1);
  return t + '…';
}

function roundRect(ctx: CanvasRenderingContext2D, x: number, y: number, w: number, h: number, r: number) {
  ctx.beginPath();
  ctx.roundRect(x, y, w, h, r);
}

function arrowHead(ctx: CanvasRenderingContext2D, x: number, y: number, angle: number, color: string) {
  ctx.save();
  ctx.fillStyle = color;
  ctx.translate(x, y);
  ctx.rotate(angle);
  ctx.beginPath();
  ctx.moveTo(0, 0);
  ctx.lineTo(-8, -4.5);
  ctx.lineTo(-8, 4.5);
  ctx.closePath();
  ctx.fill();
  ctx.restore();
}

export const AttackPathCanvas: React.FC<Props> = ({
  profile,
  currentHour,
  windowHours,
  onSelectNode,
  selectedNodeId,
  highlightedCitationId,
  canvasRefCallback,
  isRecording = false,
  recordingWatermarkText,
  redactNames = false,
  theme = 'light',
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [showRoutine, setShowRoutine] = useState(false);
  const [zoom, setZoom] = useState(1);
  const [autoFollow, setAutoFollow] = useState(true);
  const panRef = useRef({ x: 0, y: 0 });
  const dragRef = useRef<{ x: number; y: number; px: number; py: number; moved: boolean } | null>(null);
  const alphaRef = useRef(new Map<string, number>());
  const layoutRef = useRef<{ placed: Placed[]; chips: { hit: ChipHit }[] }>({ placed: [], chips: [] });
  const sizeRef = useRef({ w: 800, h: 600, dpr: 1 });

  const path = useMemo(() => buildAttackPath(profile), [profile]);
  const { shown, hiddenAfter, truncated } = useMemo(() => displayedSteps(path, showRoutine), [path, showRoutine]);
  const totalRoutine = path.steps.filter(s => s.routine && !s.isFirstLogin).length;
  const revisitCount = shown.filter(s => s.visitNo > 1).length;

  const redaction = useMemo(() => {
    const counters: Record<string, number> = {};
    const map = new Map<string, string>();
    profile.nodes.forEach(n => {
      counters[n.type] = (counters[n.type] || 0) + 1;
      map.set(n.id, `${n.type.toUpperCase()}_${counters[n.type]}`);
    });
    return map;
  }, [profile.nodes]);

  // Everything the render loop reads, refreshed on every React render
  const live = useRef({ shown, currentHour, windowHours, selectedNodeId, highlightedCitationId, isRecording, recordingWatermarkText, redactNames, theme, zoom, autoFollow, profile, redaction });
  live.current = { shown, currentHour, windowHours, selectedNodeId, highlightedCitationId, isRecording, recordingWatermarkText, redactNames, theme, zoom, autoFollow, profile, redaction };

  useEffect(() => {
    canvasRefCallback?.(canvasRef.current);
  }, [canvasRefCallback]);

  // Size the canvas to its container (and to the screen's pixel density)
  useEffect(() => {
    const el = containerRef.current;
    const canvas = canvasRef.current;
    if (!el || !canvas) return;
    const resize = () => {
      const dpr = Math.min(2, window.devicePixelRatio || 1);
      const w = el.clientWidth;
      const h = el.clientHeight;
      sizeRef.current = { w, h, dpr };
      canvas.width = Math.max(1, Math.floor(w * dpr));
      canvas.height = Math.max(1, Math.floor(h * dpr));
      canvas.style.width = `${w}px`;
      canvas.style.height = `${h}px`;
    };
    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // Render loop
  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx = canvas?.getContext('2d');
    if (!canvas || !ctx) return;
    let frame = 0;
    let running = true;

    const render = () => {
      if (!running) return;
      const L = live.current;
      const P = PALETTES[L.theme];
      const { w, h, dpr } = sizeRef.current;
      const z = L.zoom;

      // Layout in reading order: start card, then each shown step; rows wrap like text
      const perRow = Math.max(2, Math.floor((w / z - 2 * PAD_X + GAP_X) / (CARD_W + GAP_X)));
      const slot = (i: number) => ({ x: PAD_X + (i % perRow) * (CARD_W + GAP_X), y: PAD_TOP + Math.floor(i / perRow) * ROW_H });
      const root = L.profile.nodes.find(n => n.type === 'user' && n.name.toLowerCase() === L.profile.username.toLowerCase()) || L.profile.nodes[0];
      const placed: Placed[] = [];
      if (root) placed.push({ kind: 'start', node: root, ...slot(0) });
      L.shown.forEach((s, i) => placed.push({ kind: 'step', step: s, node: s.node, ...slot(i + 1) }));

      // Only steps that have happened by the scrubber position are drawn; new ones fade in
      const visible = placed.filter(p => p.kind === 'start' || (p.step && p.step.hour >= L.currentHour));
      for (const p of placed) {
        const key = p.step?.key || 'start';
        const target = visible.includes(p) ? 1 : 0;
        const a = alphaRef.current.get(key) ?? target;
        alphaRef.current.set(key, a + (target - a) * 0.2);
      }

      // Follow the newest visible step (during replay and by default)
      if (L.autoFollow && !dragRef.current) {
        const last = visible[visible.length - 1];
        const needed = last ? (last.y + ROW_H) * z - h + 24 : 0;
        const targetY = -Math.max(0, needed);
        panRef.current.y += (targetY - panRef.current.y) * 0.15;
        panRef.current.x += (0 - panRef.current.x) * 0.15;
      }

      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);
      if (L.isRecording) {
        ctx.fillStyle = P.recordingBg;
        ctx.fillRect(0, 0, w, h);
      }
      ctx.save();
      ctx.translate(panRef.current.x, panRef.current.y);
      ctx.scale(z, z);

      const label = (n: SecurityNode) => (L.redactNames ? L.redaction.get(n.id) || n.type.toUpperCase() : n.name);
      const chips: { hit: ChipHit }[] = [];

      // Connectors
      for (let i = 1; i < placed.length; i++) {
        const prev = placed[i - 1];
        const cur = placed[i];
        const alpha = Math.min(alphaRef.current.get(cur.step!.key) ?? 0, alphaRef.current.get(prev.step?.key || 'start') ?? 1);
        if (alpha < 0.02) continue;
        const st = cur.step!;
        const color = st.status === 'critical' ? P.connectorCritical : st.status === 'anomalous' ? P.connectorAnomalous : P.connector;
        ctx.globalAlpha = alpha;
        ctx.strokeStyle = color;
        ctx.lineWidth = st.status === 'critical' ? 2 : 1.5;
        ctx.setLineDash(st.edge.firstSeenInBaseline === false ? [6, 4] : []);

        let labelX: number;
        let labelY: number;
        if (prev.y === cur.y) {
          const x1 = prev.x + CARD_W;
          const y1 = prev.y + CARD_H / 2;
          const x2 = cur.x - 2;
          ctx.beginPath();
          ctx.moveTo(x1, y1);
          ctx.lineTo(x2, y1);
          ctx.stroke();
          ctx.setLineDash([]);
          arrowHead(ctx, x2, y1, 0, color);
          labelX = (x1 + x2) / 2;
          labelY = y1 - 7;
        } else {
          // Wrap to the next row: out of the right side, down between rows, back left, into the next card's left side
          const xOut = prev.x + CARD_W + 18;
          const midY = cur.y - 36;
          const xIn = cur.x - 18;
          const yIn = cur.y + CARD_H / 2;
          ctx.beginPath();
          ctx.moveTo(prev.x + CARD_W, prev.y + CARD_H / 2);
          ctx.lineTo(xOut, prev.y + CARD_H / 2);
          ctx.lineTo(xOut, midY);
          ctx.lineTo(xIn, midY);
          ctx.lineTo(xIn, yIn);
          ctx.lineTo(cur.x - 2, yIn);
          ctx.stroke();
          ctx.setLineDash([]);
          arrowHead(ctx, cur.x - 2, yIn, 0, color);
          labelX = (xOut + xIn) / 2;
          labelY = midY - 6;
        }

        ctx.font = `600 9.5px ${FONT}`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'alphabetic';
        ctx.fillStyle = P.label;
        ctx.fillText(STEP_LABEL[st.edge.type] || st.edge.type, labelX, labelY);

        if (st.hiddenBefore > 0) {
          ctx.font = `500 9.5px ${FONT}`;
          const text = `+${st.hiddenBefore} routine`;
          const tw = ctx.measureText(text).width + 12;
          const cx = labelX - tw / 2;
          const cy = labelY + 6;
          roundRect(ctx, cx, cy, tw, 16, 8);
          ctx.fillStyle = P.chipBg;
          ctx.fill();
          ctx.strokeStyle = P.chipBorder;
          ctx.lineWidth = 1;
          ctx.stroke();
          ctx.fillStyle = P.chipText;
          ctx.fillText(text, labelX, cy + 11.5);
          chips.push({ hit: { x: cx, y: cy, w: tw, h: 16 } });
        }
      }
      ctx.globalAlpha = 1;

      // Cards
      for (const p of placed) {
        const key = p.step?.key || 'start';
        const alpha = alphaRef.current.get(key) ?? 1;
        if (alpha < 0.02) continue;
        ctx.globalAlpha = alpha;
        const { x, y, node } = p;
        const st = p.step;
        const status = p.kind === 'start' ? 'start' : st!.status;
        const bar = P.bar[status as keyof typeof P.bar];
        const highlighted = L.highlightedCitationId && (L.highlightedCitationId === node.id || L.highlightedCitationId === st?.edge.id);
        const selected = L.selectedNodeId === node.id;

        // Tactic chip above the card
        if (st?.tactic || st?.ttp) {
          ctx.font = `600 9.5px ${FONT}`;
          const text = st.tactic ? `${st.tactic} · ${st.ttp}` : st.ttp!;
          const tw = Math.min(CARD_W, ctx.measureText(text).width + 14);
          roundRect(ctx, x, y - 22, tw, 17, 8.5);
          ctx.fillStyle = P.tacticBg;
          ctx.fill();
          ctx.fillStyle = P.tacticText;
          ctx.textAlign = 'left';
          ctx.fillText(truncate(ctx, text, tw - 12), x + 7, y - 10);
        }

        // Card body
        roundRect(ctx, x, y, CARD_W, CARD_H, 10);
        ctx.fillStyle = P.card;
        ctx.shadowColor = L.theme === 'light' ? 'rgba(16, 24, 40, 0.06)' : 'transparent';
        ctx.shadowBlur = 6;
        ctx.shadowOffsetY = 1;
        ctx.fill();
        ctx.shadowColor = 'transparent';
        ctx.lineWidth = selected || highlighted ? 2 : 1;
        ctx.strokeStyle = selected || highlighted ? P.ring : P.cardBorder;
        ctx.stroke();

        // Status bar
        ctx.save();
        roundRect(ctx, x, y, CARD_W, CARD_H, 10);
        ctx.clip();
        ctx.fillStyle = bar;
        ctx.fillRect(x, y, 4, CARD_H);
        ctx.restore();

        // Text
        ctx.textAlign = 'left';
        ctx.font = `15px ${FONT}`;
        ctx.fillText(ICONS[node.type] || '●', x + 12, y + 25);
        ctx.fillStyle = P.text;
        ctx.font = `600 12px ${FONT}`;
        const name = (node.isCrownJewel ? '👑 ' : '') + label(node);
        ctx.fillText(truncate(ctx, name, CARD_W - 46), x + 34, y + 23);

        ctx.fillStyle = P.sub;
        ctx.font = `500 10.5px ${FONT}`;
        const sub = p.kind === 'start' ? 'Investigated identity · start' : `${node.type} · ${st!.edge.type}${st!.count > 1 ? ` ×${st!.count}` : ''}`;
        ctx.fillText(truncate(ctx, sub, CARD_W - 20), x + 12, y + 44);

        ctx.fillStyle = P.faint;
        ctx.font = `500 10px ${FONT}`;
        const when = p.kind === 'start'
          ? `Window opens T-${String(L.windowHours).padStart(2, '0')}:00`
          : `T-${String(st!.hour).padStart(2, '0')}:00 · ${fmtTime(st!.startMs)}`;
        ctx.fillText(truncate(ctx, when, CARD_W - 20), x + 12, y + 60);

        // Revisit tag and note
        if (st && st.visitNo > 1) {
          ctx.font = `700 9px ${FONT}`;
          const tag = `↺ REVISIT ×${st.visitNo}`;
          const tw = ctx.measureText(tag).width + 12;
          const tx = x + CARD_W - tw - 8;
          const ty = y - 8;
          roundRect(ctx, tx, ty, tw, 16, 8);
          ctx.fillStyle = P.revisitBg;
          ctx.fill();
          ctx.fillStyle = P.revisitText;
          ctx.fillText(tag, tx + 6, ty + 11.5);

          ctx.font = `500 10px ${FONT}`;
          ctx.fillStyle = P.note;
          const first = st.firstVisitHour !== undefined ? ` · first seen T-${String(st.firstVisitHour).padStart(2, '0')}:00` : '';
          const note = `Back after ${formatGap(st.gapMs)}${first}`;
          ctx.fillText(truncate(ctx, note, CARD_W), x + 2, y + CARD_H + 15);
        } else if (st?.isFirstLogin) {
          ctx.font = `500 10px ${FONT}`;
          ctx.fillStyle = P.loginNote;
          ctx.fillText('First login in window', x + 2, y + CARD_H + 15);
        }
      }
      ctx.globalAlpha = 1;
      ctx.restore();

      layoutRef.current = { placed: visible, chips };

      // Burned-in overlay for replay recordings
      if (L.isRecording) {
        ctx.save();
        ctx.textAlign = 'left';
        ctx.fillStyle = P.overlayBg;
        ctx.fillRect(w - 436, 12, 420, 80);
        ctx.strokeStyle = P.overlayBorder;
        ctx.lineWidth = 1.5;
        ctx.strokeRect(w - 436, 12, 420, 80);
        ctx.fillStyle = P.overlayRec;
        ctx.font = `700 12px ${FONT}`;
        ctx.fillText('● REC // WATCHME ATTACK PATH', w - 424, 32);
        ctx.fillStyle = P.text;
        ctx.font = `500 11px ${FONT}`;
        ctx.fillText((L.recordingWatermarkText || 'WatchMe replay').slice(0, 60), w - 424, 50);
        ctx.fillStyle = P.overlayClock;
        ctx.font = `500 10px ${FONT}`;
        const abs = hourToUtc(L.profile.t0, L.currentHour);
        ctx.fillText(`T-${String(L.currentHour).padStart(2, '0')}:00${abs ? ` · ${abs}` : ''} · window ${L.windowHours}h`, w - 424, 68);
        if (L.redactNames) {
          ctx.fillStyle = P.overlayWarn;
          ctx.fillText('NAMES REDACTED', w - 424, 84);
        }
        ctx.restore();
      }

      frame = requestAnimationFrame(render);
    };
    frame = requestAnimationFrame(render);
    return () => { running = false; cancelAnimationFrame(frame); };
  }, []);

  const toWorld = (e: React.MouseEvent) => {
    const rect = canvasRef.current!.getBoundingClientRect();
    return { x: (e.clientX - rect.left - panRef.current.x) / zoom, y: (e.clientY - rect.top - panRef.current.y) / zoom };
  };

  const handleMouseDown = (e: React.MouseEvent) => {
    dragRef.current = { x: e.clientX, y: e.clientY, px: panRef.current.x, py: panRef.current.y, moved: false };
  };
  const handleMouseMove = (e: React.MouseEvent) => {
    const d = dragRef.current;
    if (!d) return;
    const dx = e.clientX - d.x;
    const dy = e.clientY - d.y;
    if (Math.abs(dx) + Math.abs(dy) > 4) {
      d.moved = true;
      setAutoFollow(false);
      panRef.current = { x: d.px + dx, y: d.py + dy };
    }
  };
  const handleMouseUp = (e: React.MouseEvent) => {
    const d = dragRef.current;
    dragRef.current = null;
    if (d?.moved) return;
    const p = toWorld(e);
    for (const c of layoutRef.current.chips) {
      if (p.x >= c.hit.x && p.x <= c.hit.x + c.hit.w && p.y >= c.hit.y && p.y <= c.hit.y + c.hit.h) {
        setShowRoutine(true);
        return;
      }
    }
    for (const pl of layoutRef.current.placed) {
      if (p.x >= pl.x && p.x <= pl.x + CARD_W && p.y >= pl.y && p.y <= pl.y + CARD_H) {
        onSelectNode(pl.node);
        return;
      }
    }
  };
  const handleWheel = (e: React.WheelEvent) => {
    if (e.ctrlKey) {
      setZoom(z => Math.min(1.8, Math.max(0.5, z * (e.deltaY < 0 ? 1.1 : 0.9))));
    } else {
      setAutoFollow(false);
      panRef.current = { x: panRef.current.x - e.deltaX, y: Math.min(0, panRef.current.y - e.deltaY) };
    }
  };

  const btn = 'p-1.5 text-slate-400 hover:text-slate-100 rounded';
  return (
    <div className="w-full h-full flex flex-col select-none">
      {/* Toolbar: legend and controls (kept out of the drawing area so nothing is covered) */}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 px-3 py-1.5 bg-slate-900 border-b border-slate-800 text-[11px] text-slate-400">
        <span className="flex items-center gap-1.5 font-semibold text-slate-200">
          <Route className="w-3.5 h-3.5 text-cyan-400" /> {shown.length} steps
        </span>
        <label className="flex items-center gap-1.5 cursor-pointer text-slate-300">
          <input type="checkbox" checked={showRoutine} onChange={e => setShowRoutine(e.target.checked)} />
          Show routine steps ({totalRoutine})
        </label>
        <span className="flex items-center gap-1"><span className="w-1 h-3 rounded bg-red-500" />Critical</span>
        <span className="flex items-center gap-1"><span className="w-1 h-3 rounded bg-amber-500" />Anomalous</span>
        <span className="flex items-center gap-1"><span className="w-1 h-3 rounded bg-slate-600" />Failed</span>
        <span className="flex items-center gap-1"><span className="w-1 h-3 rounded" style={{ background: theme === 'light' ? '#13A8B1' : '#14b8a6' }} />Routine</span>
        <span className="flex items-center gap-1">
          <span className="px-1.5 py-0.5 rounded-full text-white font-bold text-[9px]" style={{ background: theme === 'light' ? '#843CF3' : '#9333ea' }}>↺ REVISIT ×n</span>
          reached again ({revisitCount})
        </span>
        <span>Dashed = first seen</span>
        {(truncated > 0 || hiddenAfter > 0) && (
          <span className="flex items-center gap-1 text-slate-500">
            <Info className="w-3.5 h-3.5" />
            {truncated > 0 ? `First ${shown.length} shown (${truncated} more). ` : ''}
            {hiddenAfter > 0 ? `${hiddenAfter} routine after last step.` : ''}
          </span>
        )}
        <span className="ml-auto flex items-center gap-1">
          <button onClick={() => setZoom(z => Math.min(1.8, z + 0.1))} title="Zoom in" className={btn}><ZoomIn className="w-4 h-4" /></button>
          <button onClick={() => setZoom(z => Math.max(0.5, z - 0.1))} title="Zoom out" className={btn}><ZoomOut className="w-4 h-4" /></button>
          <button onClick={() => { setZoom(1); panRef.current = { x: 0, y: 0 }; }} title="Reset view" className={btn}><RotateCcw className="w-4 h-4" /></button>
          <button
            onClick={() => setAutoFollow(true)}
            title="Follow the latest step"
            className={`flex items-center gap-1 px-2 py-1 rounded font-semibold ${autoFollow ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-100'}`}
          >
            <LocateFixed className="w-3.5 h-3.5" /> Follow
          </button>
        </span>
      </div>

      <div ref={containerRef} className="relative flex-1 min-h-0 overflow-hidden soc-grid-bg">
        <canvas
          ref={canvasRef}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onMouseLeave={() => { dragRef.current = null; }}
          onWheel={handleWheel}
          className="block cursor-grab active:cursor-grabbing"
        />
      </div>
    </div>
  );
};

export type { SecurityEdge };
