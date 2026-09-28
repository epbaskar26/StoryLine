import React, { useEffect, useMemo, useRef, useState } from 'react';
import { ZoomIn, ZoomOut, RotateCcw, LocateFixed, Route, Info } from 'lucide-react';
import type { SecurityEdge, SecurityNode, UserProfile } from '../types';
import { buildAttackPath, displayedSteps, formatGap, type DisplayedStep } from '../attackPath';
import { fmtLocal, hourToLocal, tzLabel } from '../timefmt';
import { drawIconTile, iconFor } from '../nodeIcons';
import { analyzeCommand, type CommandInsight } from '../commandInsight';

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
  verdicts?: Record<string, 'BENIGN' | 'MALICIOUS'>; // latest analyst verdict per node
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
  SPAWNED: 'started', WROTE: 'wrote', MATCHED: 'matched',
  INSTALLED: 'installed', UNINSTALLED: 'removed', SERVICE_INSTALL: 'service', SCHEDULED_TASK: 'task',
  REGISTRY_SET: 'registry', ACCESSED_PROCESS: 'opened', DETECTED: 'detected', CONNECTED_DEVICE: 'device', OBSERVED: 'event',
};

const SEV_COLORS = {
  light: { high: '#D75054', medium: '#B06A00', low: '#5B6270', info: '#5B6270', bgHigh: '#FDECEC', bgMedium: '#FFF4E0', bgLow: '#F2F4F7' },
  dark: { high: '#f87171', medium: '#fbbf24', low: '#94a3b8', info: '#94a3b8', bgHigh: '#3b1215', bgMedium: '#3a2a0a', bgLow: '#1e293b' },
};

// Most telling command for a process step: the riskiest execution, or the first one
function commandInsightFor(node: SecurityNode): CommandInsight | null {
  const ex = node.executions;
  if (!ex?.length) return null;
  const rank = { high: 3, medium: 2, low: 1, info: 0 } as const;
  let best: CommandInsight | null = null;
  for (const x of ex.slice(0, 20)) {
    const ins = analyzeCommand(x.commandLine, { scriptBlock: x.source?.includes('4104') });
    if (!best || rank[ins.severity] > rank[best.severity]) best = ins;
  }
  return best;
}

// Layout (world units, before zoom)
const CARD_W = 196;
const CARD_H = 70;
const GAP_X = 72;
const ROW_H = CARD_H + 100; // room for the tactic chip above, and the command callout and note below
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
  verdicts = {},
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
  const pulseRef = useRef(0); // time the Follow button was pressed: the newest step pulses
  const [hover, setHover] = useState<{ p: Placed; sx: number; sy: number } | null>(null);
  const insights = useMemo(() => new Map(profile.nodes.filter(n => n.executions?.length).map(n => [n.id, commandInsightFor(n)])), [profile.nodes]);
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
  const live = useRef({ shown, currentHour, windowHours, selectedNodeId, highlightedCitationId, isRecording, recordingWatermarkText, redactNames, theme, zoom, autoFollow, profile, redaction, insights, verdicts });
  live.current = { shown, currentHour, windowHours, selectedNodeId, highlightedCitationId, isRecording, recordingWatermarkText, redactNames, theme, zoom, autoFollow, profile, redaction, insights, verdicts };

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

      // Follow the newest visible step (during replay and by default): keep it inside the view on both axes
      const newest = visible[visible.length - 1];
      if (L.autoFollow && !dragRef.current && newest) {
        const needY = (newest.y + CARD_H + 70) * z - h + 16;
        const targetY = -Math.max(0, needY);
        const needX = (newest.x + CARD_W + PAD_X) * z - w;
        const targetX = -Math.max(0, needX);
        panRef.current.y += (targetY - panRef.current.y) * 0.15;
        panRef.current.x += (targetX - panRef.current.x) * 0.15;
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

        // Icon tile (what the entity is: mail client, shell, server, archive...)
        drawIconTile(ctx, node, x + 10, y + 8, 22, { tileAlpha: L.theme === 'light' ? 0.12 : 0.22 });
        ctx.textAlign = 'left';
        ctx.fillStyle = P.text;
        ctx.font = `600 12px ${FONT}`;
        const name = (node.isCrownJewel ? '👑 ' : '') + label(node);
        ctx.fillText(truncate(ctx, name, CARD_W - 46), x + 34, y + 23);

        ctx.fillStyle = P.sub;
        ctx.font = `500 10.5px ${FONT}`;
        const sub = p.kind === 'start'
          ? (node.type === 'query' ? 'Log search · start' : 'Investigated identity · start')
          : `${iconFor(node).kind} · ${st!.edge.type}${st!.count > 1 ? ` ×${st!.count}` : ''}`;
        ctx.fillText(truncate(ctx, sub, CARD_W - 20), x + 12, y + 44);

        ctx.fillStyle = P.faint;
        ctx.font = `500 10px ${FONT}`;
        const when = p.kind === 'start'
          ? `Window opens ${hourToLocal(L.profile.t0, L.windowHours, { withZone: true })}`
          : `${fmtLocal(st!.startMs, { withSeconds: true })} ${tzLabel()}`;
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

        }

        // Command callout under process steps: one-line summary of what the command does
        const ins = st ? L.insights.get(node.id) : null;
        let noteY = y + CARD_H + 15;
        if (ins) {
          const C = SEV_COLORS[L.theme];
          const sevKey = ins.severity as 'high' | 'medium' | 'low' | 'info';
          const fg = C[sevKey];
          const bg = sevKey === 'high' ? C.bgHigh : sevKey === 'medium' ? C.bgMedium : C.bgLow;
          ctx.font = `600 10px ${FONT}`;
          const text = truncate(ctx, `›_ ${ins.summary}`, CARD_W + GAP_X - 24);
          const tw = ctx.measureText(text).width + 14;
          const cy = y + CARD_H + 9;
          ctx.beginPath();
          ctx.moveTo(x + 18, cy);
          ctx.lineTo(x + 24, cy - 6);
          ctx.lineTo(x + 30, cy);
          ctx.closePath();
          ctx.fillStyle = bg;
          ctx.fill();
          roundRect(ctx, x, cy, tw, 19, 6);
          ctx.fill();
          ctx.strokeStyle = fg;
          ctx.lineWidth = 1;
          ctx.stroke();
          ctx.fillStyle = fg;
          ctx.fillText(text, x + 7, cy + 13);
          noteY = cy + 33;
        }

        if (st && st.visitNo > 1) {
          ctx.font = `500 10px ${FONT}`;
          ctx.fillStyle = P.note;
          const first = st.firstVisitMs !== undefined ? ` · first seen ${fmtLocal(st.firstVisitMs)}` : '';
          const note = `Back after ${formatGap(st.gapMs)}${first}`;
          ctx.fillText(truncate(ctx, note, CARD_W), x + 2, noteY);
        } else if (st?.isFirstLogin) {
          ctx.font = `500 10px ${FONT}`;
          ctx.fillStyle = P.loginNote;
          ctx.fillText('First login in window', x + 2, noteY);
        }

        // Analyst verdict and "new in live mode" tags on the card's top-left edge
        const verdict = L.verdicts[node.id];
        let tagX = x + 8;
        const tag = (label: string, color: string) => {
          ctx.font = `700 8.5px ${FONT}`;
          const tw = ctx.measureText(label).width + 10;
          roundRect(ctx, tagX, y - 7, tw, 14, 7);
          ctx.fillStyle = color;
          ctx.fill();
          ctx.fillStyle = '#FFFFFF';
          ctx.fillText(label, tagX + 5, y + 3);
          tagX += tw + 4;
        };
        if (verdict && !(st?.tactic || st?.ttp)) tag(verdict === 'MALICIOUS' ? '✕ MALICIOUS' : '✓ BENIGN', verdict === 'MALICIOUS' ? P.connectorCritical : '#018102');
        if (node.isNew && p.kind === 'step') tag('NEW', '#2740CB');

        // Follow: pulse ring on the newest step so the analyst sees where the replay is
        const sincePulse = performance.now() - pulseRef.current;
        if (p === newest && p.kind === 'step' && sincePulse < 1600) {
          const k = sincePulse / 1600;
          ctx.save();
          ctx.globalAlpha = Math.max(0, 1 - k);
          ctx.strokeStyle = P.ring;
          ctx.lineWidth = 3;
          roundRect(ctx, x - 4 - k * 10, y - 4 - k * 10, CARD_W + 8 + k * 20, CARD_H + 8 + k * 20, 14);
          ctx.stroke();
          ctx.restore();
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
        ctx.fillText(`${hourToLocal(L.profile.t0, L.currentHour, { withZone: true })} · window ${L.windowHours}h`, w - 424, 68);
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
  const hitTest = (e: React.MouseEvent): Placed | null => {
    const p = toWorld(e);
    for (const pl of layoutRef.current.placed) {
      if (p.x >= pl.x && p.x <= pl.x + CARD_W && p.y >= pl.y && p.y <= pl.y + CARD_H) return pl;
    }
    return null;
  };
  const handleMouseMove = (e: React.MouseEvent) => {
    const d = dragRef.current;
    if (!d) {
      const hit = hitTest(e);
      if (hit?.kind === 'step') {
        const rect = canvasRef.current!.getBoundingClientRect();
        setHover(h => (h?.p.step?.key === hit.step?.key ? h : { p: hit, sx: e.clientX - rect.left, sy: e.clientY - rect.top }));
      } else if (hover) setHover(null);
      return;
    }
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
            data-testid="follow-button"
            onClick={() => { setAutoFollow(true); pulseRef.current = performance.now(); }}
            title={autoFollow ? 'Following the newest step (dragging or scrolling stops following). Click to jump to it.' : 'Jump to the newest step and keep it in view during replay'}
            className={`flex items-center gap-1 px-2 py-1 rounded font-semibold ${autoFollow ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-100 border border-slate-700'}`}
          >
            <LocateFixed className="w-3.5 h-3.5" /> {autoFollow ? 'Following' : 'Follow'}
          </button>
        </span>
      </div>

      <div ref={containerRef} className="relative flex-1 min-h-0 overflow-hidden soc-grid-bg">
        <canvas
          ref={canvasRef}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onMouseLeave={() => { dragRef.current = null; setHover(null); }}
          onWheel={handleWheel}
          className="block cursor-grab active:cursor-grabbing"
        />
        {hover && hover.p.step && !isRecording && (() => {
          const st = hover.p.step!;
          const node = st.node;
          const ex = node.executions || [];
          const spec = iconFor(node);
          const left = Math.min(hover.sx + 16, (containerRef.current?.clientWidth || 800) - 360);
          const top = Math.min(hover.sy + 12, (containerRef.current?.clientHeight || 600) - 60);
          return (
            <div data-testid="path-popover" className="absolute z-20 w-[22rem] pointer-events-none bg-slate-900 border border-slate-700 rounded-xl shadow-2xl p-3 text-xs space-y-1.5" style={{ left, top }}>
              <div className="flex items-center gap-2">
                <spec.Icon className="w-4 h-4" style={{ color: spec.tint }} />
                <span className="font-semibold text-slate-100 break-all">{node.name}</span>
              </div>
              <div className="text-slate-400">{spec.kind} · {STEP_LABEL[st.edge.type] || st.edge.type} · {fmtLocal(st.startMs, { withSeconds: true, withZone: true })}{st.count > 1 ? ` · ${st.count} events` : ''}</div>
              {ex.length > 0 ? (
                <div className="space-y-1">
                  {ex.slice(0, 3).map((x, i) => {
                    const ins = analyzeCommand(x.commandLine, { scriptBlock: x.source?.includes('4104') });
                    return (
                      <div key={i} className="p-1.5 rounded bg-slate-950 border border-slate-800">
                        <div className={ins.severity === 'high' ? 'text-red-400 font-semibold' : ins.severity === 'medium' ? 'text-amber-400 font-semibold' : 'text-slate-200'}>{ins.summary}</div>
                        <div className="font-mono text-[10px] text-slate-400 break-all line-clamp-2">{x.commandLine}</div>
                      </div>
                    );
                  })}
                  {ex.length > 3 && <div className="text-slate-500">+{ex.length - 3} more command line(s): click for all</div>}
                </div>
              ) : (
                <div className="text-slate-300">{st.edge.details}</div>
              )}
              <div className="text-[10px] text-slate-500">Click the card for full details, notes and verdict</div>
            </div>
          );
        })()}
      </div>
    </div>
  );
};

export type { SecurityEdge };
