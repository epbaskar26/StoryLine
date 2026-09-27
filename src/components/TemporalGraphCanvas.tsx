import React, { useEffect, useRef, useState, useMemo } from 'react';
import { hourToLocal } from '../timefmt';
import { iconFor, iconImage } from '../nodeIcons';
import { SecurityNode, SecurityEdge, NodeType, RiskBand } from '../types';
import { 
  ZoomIn, 
  ZoomOut, 
  RotateCcw, 
  Maximize2,
  Pin,
  EyeOff,
  Filter,
  Layers,
  Sparkles,
  AlertTriangle,
  Info,
  SlidersHorizontal,
  ChevronDown
} from 'lucide-react';

// Canvas colors per theme. Light values are from the reference design
// (red #D75054, orange #FBA21B, teal #13A8B1, purple #843CF3, blue #2740CB).
const CANVAS_PALETTES = {
  light: {
    recordingBg: '#FFFFFF',
    particle: '#3140CB', particleThreat: '#D75054',
    compromised: { fill: '#D75054', stroke: '#B8383C', glow: 'rgba(215, 80, 84, 0.30)' },
    crown: { fill: '#843CF3', stroke: '#6A2BC9', glow: 'rgba(132, 60, 243, 0.25)' },
    high: { fill: '#D75054', stroke: '#B8383C', glow: 'rgba(215, 80, 84, 0.25)' },
    medium: { fill: '#FBA21B', stroke: '#D98A0A', glow: 'rgba(251, 162, 27, 0.25)' },
    low: { fill: '#13A8B1', stroke: '#0E8A92', glow: 'rgba(19, 168, 177, 0.20)' },
    halo: ['rgba(215, 80, 84, 0.12)', 'rgba(215, 80, 84, 0.04)', 'rgba(215, 80, 84, 0)'],
    haloStroke: 'rgba(215, 80, 84, 0.30)',
    edgeCitation: '#2740CB', edgeCritical: '#D75054', edgeCriticalGlow: 'rgba(215, 80, 84, 0.25)',
    edgeAnomalous: '#FBA21B', edgeAnomalousGlow: 'rgba(251, 162, 27, 0.25)', edgeBlocked: '#A9ACB1', edgeNormal: '#C9CDD3',
    labelCitation: '#2740CB', labelCritical: '#C2454A', labelAnomalous: '#B06A00', labelNormal: '#74767A', edgeMeta: '#A9ACB1',
    ringSelected: '#2740CB', ringHover: '#A9ACB1',
    icon: '#FFFFFF', crownBadge: '#843CF3',
    nodeLabel: '#1F201F', nodeLabelHighRisk: '#A5363A', subLabel: '#888A8C',
    badge: '#D75054', badgeStroke: '#FFFFFF',
    overlayBg: 'rgba(255, 255, 255, 0.96)', overlayBorder: '#2740CB', overlayRec: '#D75054', overlayText: '#121314', overlayClock: '#2740CB', overlayWarn: '#B06A00',
  },
  dark: {
    recordingBg: '#020617',
    particle: '#38bdf8', particleThreat: '#ef4444',
    compromised: { fill: '#ef4444', stroke: '#f87171', glow: 'rgba(239, 68, 68, 0.6)' },
    crown: { fill: '#9333ea', stroke: '#c084fc', glow: 'rgba(192, 132, 252, 0.6)' },
    high: { fill: '#b91c1c', stroke: '#f87171', glow: 'rgba(239, 68, 68, 0.4)' },
    medium: { fill: '#d97706', stroke: '#fbbf24', glow: 'rgba(251, 191, 36, 0.4)' },
    low: { fill: '#0f766e', stroke: '#2dd4bf', glow: 'rgba(45, 212, 191, 0.3)' },
    halo: ['rgba(239, 68, 68, 0.25)', 'rgba(239, 68, 68, 0.08)', 'rgba(239, 68, 68, 0)'],
    haloStroke: 'rgba(239, 68, 68, 0.4)',
    edgeCitation: '#38bdf8', edgeCritical: '#ef4444', edgeCriticalGlow: 'rgba(239, 68, 68, 0.8)',
    edgeAnomalous: '#f59e0b', edgeAnomalousGlow: 'rgba(245, 158, 11, 0.6)', edgeBlocked: '#64748b', edgeNormal: '#1e293b',
    labelCitation: '#38bdf8', labelCritical: '#fca5a5', labelAnomalous: '#fde047', labelNormal: '#94a3b8', edgeMeta: '#64748b',
    ringSelected: '#38bdf8', ringHover: '#e2e8f0',
    icon: '#ffffff', crownBadge: '#fde047',
    nodeLabel: '#f8fafc', nodeLabelHighRisk: '#fca5a5', subLabel: '#94a3b8',
    badge: '#ef4444', badgeStroke: '#020617',
    overlayBg: 'rgba(2, 6, 23, 0.9)', overlayBorder: '#ef4444', overlayRec: '#ef4444', overlayText: '#f8fafc', overlayClock: '#38bdf8', overlayWarn: '#fbbf24',
  },
};

interface Props {
  nodes: SecurityNode[];
  edges: SecurityEdge[];
  currentHour: number; // windowHours down to 0 (hours before T-0)
  windowHours?: number;
  t0?: string;
  redactNames?: boolean; // replace entity names with type tokens (for sharing replays more widely)
  theme?: 'light' | 'dark';
  truncated?: boolean;
  totalNodeCount?: number;
  totalEdgeCount?: number;
  onSelectNode: (node: SecurityNode) => void;
  selectedNodeId: string | null;
  highlightedCitationId?: string | null;
  canvasRefCallback?: (canvas: HTMLCanvasElement | null) => void;
  isRecording?: boolean;
  recordingWatermarkText?: string;
  onExpandNode?: (nodeId: string) => void;
  onPinNode?: (nodeId: string) => void;
  onHideNode?: (nodeId: string) => void;
}

interface SimNode extends SecurityNode {
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
  targetRadius: number;
  alpha: number;
  pinned?: boolean;
  hidden?: boolean;
}

interface Particle {
  edgeId: string;
  progress: number;
  speed: number;
  color: string;
}

export const TemporalGraphCanvas: React.FC<Props> = ({
  nodes,
  edges,
  currentHour,
  windowHours = 48,
  t0,
  redactNames = false,
  theme = 'light',
  truncated = false,
  totalNodeCount,
  totalEdgeCount,
  onSelectNode,
  selectedNodeId,
  highlightedCitationId,
  canvasRefCallback,
  isRecording = false,
  recordingWatermarkText,
  onExpandNode,
  onPinNode,
  onHideNode
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const P = CANVAS_PALETTES[theme];
  const canvasRef = useRef<HTMLCanvasElement>(null);

  const [hoveredNode, setHoveredNode] = useState<SecurityNode | null>(null);
  const [zoom, setZoom] = useState<number>(1);
  const [pan, setPan] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [isDraggingCanvas, setIsDraggingCanvas] = useState(false);
  const [dragStart, setDragStart] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [draggedNode, setDraggedNode] = useState<SimNode | null>(null);

  // Left Filters (FR-04, FR-05)
  const [filterFirstSeenOnly, setFilterFirstSeenOnly] = useState(false);
  const [filterCrownJewelOnly, setFilterCrownJewelOnly] = useState(false);
  const [filterRiskBand, setFilterRiskBand] = useState<'ALL' | 'HIGH' | 'MEDIUM'>('ALL');
  const [selectedTypes, setSelectedTypes] = useState<Record<string, boolean>>({
    user: true,
    host: true,
    ip: true,
    application: true,
    file: true,
    process: true,
    domain: true,
    alert: true
  });

  // Redaction tokens (USER_1, HOST_2 ...) in stable order
  const redactionLabels = useMemo(() => {
    const counters: Record<string, number> = {};
    const map = new Map<string, string>();
    nodes.forEach(n => {
      counters[n.type] = (counters[n.type] || 0) + 1;
      map.set(n.id, `${n.type.toUpperCase()}_${counters[n.type]}`);
    });
    return map;
  }, [nodes]);

  // Persistent sim nodes map
  const simNodesRef = useRef<Map<string, SimNode>>(new Map());
  const particlesRef = useRef<Particle[]>([]);
  const animFrameRef = useRef<number | null>(null);

  useEffect(() => {
    if (canvasRefCallback) {
      canvasRefCallback(canvasRef.current);
    }
  }, [canvasRefCallback]);

  // Synchronize simulation nodes
  useEffect(() => {
    const width = containerRef.current?.clientWidth || 800;
    const height = containerRef.current?.clientHeight || 600;
    const centerX = width / 2;
    const centerY = height / 2;

    const existingMap = simNodesRef.current;
    const newMap = new Map<string, SimNode>();

    nodes.forEach((n, idx) => {
      const existing = existingMap.get(n.id);
      const isVisibleByTime = n.firstSeenHour >= currentHour;

      let defaultX = centerX;
      let defaultY = centerY;

      if (n.type === 'user') {
        defaultX = centerX;
        defaultY = centerY;
      } else {
        const angle = (idx / (nodes.length - 1 || 1)) * 2 * Math.PI;
        const dist = 160 + (idx % 3) * 65;
        defaultX = centerX + Math.cos(angle) * dist;
        defaultY = centerY + Math.sin(angle) * dist;
      }

      const nodeRadius = n.type === 'user' ? 32 : n.isCrownJewel ? 30 : n.type === 'application' ? 26 : 22;

      newMap.set(n.id, {
        ...n,
        x: existing?.x ?? defaultX,
        y: existing?.y ?? defaultY,
        vx: existing?.vx ?? (Math.random() - 0.5) * 2,
        vy: existing?.vy ?? (Math.random() - 0.5) * 2,
        radius: isVisibleByTime ? nodeRadius : 0,
        targetRadius: isVisibleByTime ? nodeRadius : 0,
        alpha: isVisibleByTime ? 1 : 0,
        pinned: n.pinned || existing?.pinned,
        hidden: existing?.hidden
      });
    });

    simNodesRef.current = newMap;
  }, [nodes]);

  // Update target radius based on current time & filters
  useEffect(() => {
    simNodesRef.current.forEach(simNode => {
      const isVisibleByTime = simNode.firstSeenHour >= currentHour;
      const typeAllowed = selectedTypes[simNode.type] !== false;
      const riskAllowed = filterRiskBand === 'ALL' || simNode.riskBand === filterRiskBand;
      const crownAllowed = !filterCrownJewelOnly || simNode.isCrownJewel;
      const firstSeenAllowed = !filterFirstSeenOnly || !simNode.firstSeenInBaseline;

      const isVisible = isVisibleByTime && typeAllowed && riskAllowed && crownAllowed && firstSeenAllowed && !simNode.hidden;
      const baseRadius = simNode.type === 'user' ? 32 : simNode.isCrownJewel ? 30 : 22;
      simNode.targetRadius = isVisible ? baseRadius : 0;
    });
  }, [currentHour, selectedTypes, filterRiskBand, filterCrownJewelOnly, filterFirstSeenOnly]);

  // Particle emission loop
  useEffect(() => {
    const interval = setInterval(() => {
      const visibleEdges = edges.filter(e => {
        const sourceNode = simNodesRef.current.get(e.source);
        const targetNode = simNodesRef.current.get(e.target);
        return sourceNode && targetNode && sourceNode.targetRadius > 0 && targetNode.targetRadius > 0 && e.hour >= currentHour;
      });

      if (visibleEdges.length > 0 && particlesRef.current.length < 30) {
        const randomEdge = visibleEdges[Math.floor(Math.random() * visibleEdges.length)];
        const isThreat = randomEdge.status === 'critical' || randomEdge.status === 'anomalous';
        particlesRef.current.push({
          edgeId: randomEdge.id,
          progress: 0,
          speed: 0.015 + Math.random() * 0.02,
          color: isThreat ? P.particleThreat : P.particle
        });
      }
    }, 160);

    return () => clearInterval(interval);
  }, [edges, currentHour]);

  // Shape by Type (Section 10 Extended Spec):
  // User = circle, Host = square, IP = diamond, Application = hexagon, File = document, Process = rounded rect
  const drawNodeShape = (ctx: CanvasRenderingContext2D, type: NodeType, x: number, y: number, r: number) => {
    ctx.beginPath();
    switch (type) {
      case 'user': // Circle
        ctx.arc(x, y, r, 0, 2 * Math.PI);
        break;
      case 'host': // Square
        ctx.rect(x - r, y - r, r * 2, r * 2);
        break;
      case 'ip': // Diamond
        ctx.moveTo(x, y - r * 1.2);
        ctx.lineTo(x + r * 1.2, y);
        ctx.lineTo(x, y + r * 1.2);
        ctx.lineTo(x - r * 1.2, y);
        ctx.closePath();
        break;
      case 'application': // Hexagon
        for (let i = 0; i < 6; i++) {
          const angle = (i * Math.PI) / 3;
          const px = x + r * 1.1 * Math.cos(angle);
          const py = y + r * 1.1 * Math.sin(angle);
          if (i === 0) ctx.moveTo(px, py);
          else ctx.lineTo(px, py);
        }
        ctx.closePath();
        break;
      case 'file': // Document
        ctx.rect(x - r * 0.8, y - r * 1.1, r * 1.6, r * 2.2);
        break;
      case 'process': // Pill / Rounded Rect
        ctx.roundRect(x - r * 1.1, y - r * 0.8, r * 2.2, r * 1.6, 6);
        break;
      case 'alert': // Alert Octagon
        for (let i = 0; i < 8; i++) {
          const angle = (i * Math.PI) / 4 + Math.PI / 8;
          const px = x + r * Math.cos(angle);
          const py = y + r * Math.sin(angle);
          if (i === 0) ctx.moveTo(px, py);
          else ctx.lineTo(px, py);
        }
        ctx.closePath();
        break;
      default:
        ctx.arc(x, y, r, 0, 2 * Math.PI);
        break;
    }
  };

  // Node Color by Risk Band (Section 6 & 10 Extended Spec):
  // 0-39 Low (teal/emerald/slate), 40-69 Medium (amber), 70-100 High (crimson red)
  const getNodeColorByRiskBand = (riskBand: RiskBand, compromised: boolean, isCrownJewel?: boolean) => {
    if (compromised) return P.compromised;
    if (isCrownJewel) return P.crown;
    switch (riskBand) {
      case 'HIGH':
        return P.high;
      case 'MEDIUM':
        return P.medium;
      case 'LOW':
      default:
        return P.low;
    }
  };


  // Main Force Physics & Render Loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let isRunning = true;

    const render = () => {
      if (!isRunning) return;

      const width = canvas.width;
      const height = canvas.height;
      const centerX = width / 2;
      const centerY = height / 2;

      const simNodes = Array.from(simNodesRef.current.values());

      // Physics integration (fcose/cola style spring-electrical)
      for (let i = 0; i < simNodes.length; i++) {
        const nodeA = simNodes[i];
        if (nodeA.targetRadius === 0) continue;

        nodeA.radius += (nodeA.targetRadius - nodeA.radius) * 0.15;
        nodeA.alpha += ((nodeA.targetRadius > 0 ? 1 : 0) - nodeA.alpha) * 0.15;

        if (nodeA.pinned) continue;

        // Center pull
        const kCenter = nodeA.type === 'user' ? 0.009 : 0.0016;
        nodeA.vx += (centerX - nodeA.x) * kCenter;
        nodeA.vy += (centerY - nodeA.y) * kCenter;

        // Node repulsion
        for (let j = i + 1; j < simNodes.length; j++) {
          const nodeB = simNodes[j];
          if (nodeB.targetRadius === 0) continue;

          const dx = nodeB.x - nodeA.x;
          const dy = nodeB.y - nodeA.y;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;

          if (dist < 340) {
            const force = (340 - dist) / dist * 0.36;
            nodeA.vx -= dx * force * 0.05;
            nodeA.vy -= dy * force * 0.05;
            nodeB.vx += dx * force * 0.05;
            nodeB.vy += dy * force * 0.05;
          }
        }
      }

      // Edge spring tension
      edges.forEach(e => {
        const source = simNodesRef.current.get(e.source);
        const target = simNodesRef.current.get(e.target);
        if (!source || !target || source.radius < 5 || target.radius < 5) return;
        if (e.hour < currentHour) return;

        const dx = target.x - source.x;
        const dy = target.y - source.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const desiredDist = 180;
        // Linear (Hooke) spring along the unit vector, capped. The previous force grew with distance squared,
        // which made the simulation diverge to NaN within about a second for hub nodes with many edges.
        const springForce = Math.max(-6, Math.min(6, (dist - desiredDist) * 0.02));
        const ux = dx / dist;
        const uy = dy / dist;

        if (!source.pinned) {
          source.vx += ux * springForce;
          source.vy += uy * springForce;
        }
        if (!target.pinned) {
          target.vx -= ux * springForce;
          target.vy -= uy * springForce;
        }
      });

      // Update positions
      simNodes.forEach(n => {
        if (draggedNode && draggedNode.id === n.id) {
          n.vx = 0;
          n.vy = 0;
          return;
        }
        if (n.pinned) {
          n.vx = 0;
          n.vy = 0;
          return;
        }
        n.vx *= 0.82;
        n.vy *= 0.82;
        // Cap velocity and recover from any non-finite state so one bad frame cannot freeze the canvas
        const maxV = 25;
        n.vx = Math.max(-maxV, Math.min(maxV, n.vx));
        n.vy = Math.max(-maxV, Math.min(maxV, n.vy));
        if (!Number.isFinite(n.vx) || !Number.isFinite(n.vy)) { n.vx = 0; n.vy = 0; }
        n.x += n.vx;
        n.y += n.vy;
        if (!Number.isFinite(n.x) || !Number.isFinite(n.y)) {
          n.x = centerX + (Math.random() - 0.5) * 200;
          n.y = centerY + (Math.random() - 0.5) * 200;
        }

        const margin = 40;
        if (n.x < margin) n.vx += 1.5;
        if (n.x > width - margin) n.vx -= 1.5;
        if (n.y < margin) n.vy += 1.5;
        if (n.y > height - margin) n.vy -= 1.5;
      });

      // Render Canvas
      ctx.clearRect(0, 0, width, height);
      if (isRecording) {
        // The on-screen background is CSS, which captureStream does not see; paint one into the video
        ctx.fillStyle = P.recordingBg;
        ctx.fillRect(0, 0, width, height);
      }
      ctx.save();
      ctx.translate(pan.x, pan.y);
      ctx.scale(zoom, zoom);

      // 1. Draw Blast Radius Halo around compromised nodes
      const compromisedNodes = simNodes.filter(n => n.compromised && n.radius > 5);
      compromisedNodes.forEach(cNode => {
        const haloRadius = cNode.radius * 2.8;
        const grad = ctx.createRadialGradient(cNode.x, cNode.y, cNode.radius * 0.5, cNode.x, cNode.y, haloRadius);
        grad.addColorStop(0, P.halo[0]);
        grad.addColorStop(0.7, P.halo[1]);
        grad.addColorStop(1, P.halo[2]);

        ctx.beginPath();
        ctx.arc(cNode.x, cNode.y, haloRadius, 0, 2 * Math.PI);
        ctx.fillStyle = grad;
        ctx.fill();

        ctx.beginPath();
        ctx.arc(cNode.x, cNode.y, haloRadius, 0, 2 * Math.PI);
        ctx.setLineDash([4, 6]);
        ctx.strokeStyle = P.haloStroke;
        ctx.lineWidth = 1;
        ctx.stroke();
        ctx.setLineDash([]);
      });

      // 2. Draw Edges (FR-05: Edge thickness by event count, first-seen edges dashed)
      edges.forEach(e => {
        const source = simNodesRef.current.get(e.source);
        const target = simNodesRef.current.get(e.target);
        if (!source || !target || source.radius < 5 || target.radius < 5) return;
        if (e.hour < currentHour) return;

        const isCitationMatch = highlightedCitationId && (highlightedCitationId === e.id || highlightedCitationId === e.source || highlightedCitationId === e.target);
        const isCritical = e.status === 'critical';
        const isAnomalous = e.status === 'anomalous';

        // FR-05: Line thickness by event count (scaled 1.5px to 6px)
        const baseThickness = Math.min(6, Math.max(1.5, Math.log10(e.eventCount + 1) * 2));
        const lineThickness = isCitationMatch ? baseThickness + 3 : baseThickness;

        ctx.beginPath();
        ctx.moveTo(source.x, source.y);
        ctx.lineTo(target.x, target.y);

        // FR-05: First-seen edges dashed!
        if (e.firstSeenInBaseline === false) {
          ctx.setLineDash([6, 4]);
        } else {
          ctx.setLineDash([]);
        }

        if (isCitationMatch) {
          ctx.strokeStyle = P.edgeCitation;
          ctx.lineWidth = lineThickness;
          ctx.shadowColor = P.edgeCitation;
          ctx.shadowBlur = 14;
        } else if (isCritical) {
          ctx.strokeStyle = P.edgeCritical;
          ctx.lineWidth = lineThickness;
          ctx.shadowColor = P.edgeCriticalGlow;
          ctx.shadowBlur = 8;
        } else if (isAnomalous) {
          ctx.strokeStyle = P.edgeAnomalous;
          ctx.lineWidth = lineThickness;
          ctx.shadowColor = P.edgeAnomalousGlow;
          ctx.shadowBlur = 6;
        } else if (e.status === 'blocked') {
          ctx.strokeStyle = P.edgeBlocked;
          ctx.lineWidth = lineThickness;
          ctx.shadowBlur = 0;
        } else {
          ctx.strokeStyle = P.edgeNormal;
          ctx.lineWidth = lineThickness;
          ctx.shadowBlur = 0;
        }

        ctx.stroke();
        ctx.setLineDash([]);
        ctx.shadowBlur = 0;

        // Draw Edge Label at midpoint
        const midX = (source.x + target.x) / 2;
        const midY = (source.y + target.y) / 2;
        ctx.font = '10px Inter, sans-serif';
        ctx.textAlign = 'center';
        ctx.fillStyle = isCitationMatch ? P.labelCitation : isCritical ? P.labelCritical : isAnomalous ? P.labelAnomalous : P.labelNormal;
        ctx.fillText(e.action, midX, midY - 6);

        // Event count badge & protocol
        ctx.font = '9px Inter, sans-serif';
        ctx.fillStyle = P.edgeMeta;
        ctx.fillText(`[${e.protocol} · ${e.eventCount} evt]`, midX, midY + 8);
      });

      // 3. Draw Traveling Packets along edges
      for (let pIdx = particlesRef.current.length - 1; pIdx >= 0; pIdx--) {
        const p = particlesRef.current[pIdx];
        const edge = edges.find(e => e.id === p.edgeId);
        if (!edge) {
          particlesRef.current.splice(pIdx, 1);
          continue;
        }
        const source = simNodesRef.current.get(edge.source);
        const target = simNodesRef.current.get(edge.target);
        if (!source || !target || source.radius < 5 || target.radius < 5) {
          particlesRef.current.splice(pIdx, 1);
          continue;
        }

        p.progress += p.speed;
        if (p.progress >= 1) {
          particlesRef.current.splice(pIdx, 1);
          continue;
        }

        const px = source.x + (target.x - source.x) * p.progress;
        const py = source.y + (target.y - source.y) * p.progress;

        ctx.beginPath();
        ctx.arc(px, py, 3.5, 0, 2 * Math.PI);
        ctx.fillStyle = p.color;
        ctx.shadowColor = p.color;
        ctx.shadowBlur = 6;
        ctx.fill();
        ctx.shadowBlur = 0;
      }

      // 4. Draw Nodes with distinct shapes per Section 10
      simNodes.forEach(n => {
        if (n.radius < 3) return;

        const isSelected = selectedNodeId === n.id;
        const isHovered = hoveredNode?.id === n.id;
        const isCitationMatch = highlightedCitationId && (highlightedCitationId === n.id || highlightedCitationId === n.name);
        const colors = getNodeColorByRiskBand(n.riskBand, n.compromised, n.isCrownJewel);

        // Selection / Citation highlight ring
        if (isSelected || isHovered || isCitationMatch) {
          ctx.beginPath();
          drawNodeShape(ctx, n.type, n.x, n.y, n.radius + 7);
          ctx.strokeStyle = isCitationMatch || isSelected ? P.ringSelected : P.ringHover;
          ctx.lineWidth = 2;
          ctx.setLineDash([3, 3]);
          ctx.stroke();
          ctx.setLineDash([]);
        }

        // Draw geometric shape
        drawNodeShape(ctx, n.type, n.x, n.y, n.radius);
        ctx.fillStyle = colors.fill;
        ctx.strokeStyle = colors.stroke;
        ctx.lineWidth = n.compromised ? 3 : 2;
        ctx.shadowColor = colors.glow;
        ctx.shadowBlur = theme === 'light' ? (n.compromised ? 10 : 4) : n.compromised ? 16 : 8;
        ctx.fill();
        ctx.stroke();
        ctx.shadowBlur = 0;

        // Inner icon: what the entity is (mail client, shell, server, archive...)
        {
          const img = iconImage(iconFor(n), P.icon);
          const sz = Math.max(12, n.radius * 1.05);
          if (img.complete && img.naturalWidth) ctx.drawImage(img, n.x - sz / 2, n.y - sz / 2, sz, sz);
        }

        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        // Crown Jewel Tag Badge
        if (n.isCrownJewel) {
          ctx.font = 'bold 9px Inter, sans-serif';
          ctx.fillStyle = P.crownBadge;
          ctx.fillText('👑 CROWN JEWEL', n.x, n.y - n.radius - 12);
        }

        // Node Label
        ctx.font = '600 11px Inter, sans-serif';
        ctx.fillStyle = n.compromised ? P.nodeLabelHighRisk : P.nodeLabel;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';
        ctx.fillText(redactNames ? redactionLabels.get(n.id) || n.type.toUpperCase() : n.name, n.x, n.y + n.radius + 6);

        // Classification / Subtitle (hidden when redacting, since it can describe the entity)
        if (n.classification && !redactNames) {
          ctx.font = '500 9px Inter, sans-serif';
          ctx.fillStyle = P.subLabel;
          ctx.fillText(n.classification, n.x, n.y + n.radius + 20);
        }

        // Pin icon if pinned
        if (n.pinned) {
          ctx.font = '10px sans-serif';
          ctx.fillText('📌', n.x + n.radius, n.y - n.radius);
        }
        if (n.isNew) {
          ctx.font = 'bold 9px Inter, sans-serif';
          ctx.fillStyle = P.ringSelected;
          ctx.fillText('NEW', n.x - n.radius, n.y - n.radius);
        }

        // Compromised indicator badge
        if (n.compromised) {
          ctx.beginPath();
          ctx.arc(n.x + n.radius * 0.7, n.y - n.radius * 0.7, 7, 0, 2 * Math.PI);
          ctx.fillStyle = P.badge;
          ctx.strokeStyle = P.badgeStroke;
          ctx.lineWidth = 1.5;
          ctx.fill();
          ctx.stroke();

          ctx.fillStyle = P.icon;
          ctx.font = 'bold 8px monospace';
          ctx.fillText('!', n.x + n.radius * 0.7, n.y - n.radius * 0.7 - 5);
        }
      });

      ctx.restore();

      // Burned-in overlays for replay evidence (section 8): title, case, and the timeline clock
      if (isRecording) {
        ctx.save();
        ctx.textAlign = 'left';
        ctx.textBaseline = 'alphabetic';
        ctx.fillStyle = P.overlayBg;
        ctx.fillRect(16, 16, 420, 80);
        ctx.strokeStyle = P.overlayBorder;
        ctx.lineWidth = 1.5;
        ctx.strokeRect(16, 16, 420, 80);

        ctx.fillStyle = P.overlayRec;
        ctx.font = 'bold 12px Inter, sans-serif';
        ctx.fillText('● REC // WATCHME REPLAY', 28, 36);

        ctx.fillStyle = P.overlayText;
        ctx.font = '11px Inter, sans-serif';
        ctx.fillText((recordingWatermarkText || 'WatchMe replay').slice(0, 60), 28, 54);

        ctx.fillStyle = P.overlayClock;
        ctx.font = '10px Inter, sans-serif';
        ctx.fillText(`${hourToLocal(t0, currentHour, { withZone: true })} · window ${windowHours}h`, 28, 72);
        if (redactNames) {
          ctx.fillStyle = P.overlayWarn;
          ctx.fillText('NAMES REDACTED', 28, 88);
        }
        ctx.restore();
      }

      animFrameRef.current = requestAnimationFrame(render);
    };

    animFrameRef.current = requestAnimationFrame(render);

    return () => {
      isRunning = false;
      if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
    };
  }, [edges, currentHour, selectedNodeId, hoveredNode, zoom, pan, draggedNode, isRecording, recordingWatermarkText, highlightedCitationId, redactNames, redactionLabels, t0, windowHours, theme]);

  // Handle Resize
  useEffect(() => {
    const handleResize = () => {
      if (!canvasRef.current || !containerRef.current) return;
      canvasRef.current.width = containerRef.current.clientWidth;
      canvasRef.current.height = containerRef.current.clientHeight;
    };
    handleResize();
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  // Keyboard Shortcuts (Section 10 Extended Spec):
  // F fit view, E export
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;
      if (e.key === 'f' || e.key === 'F') {
        setZoom(1);
        setPan({ x: 0, y: 0 });
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const getCanvasCoords = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const rect = canvasRef.current?.getBoundingClientRect();
    if (!rect) return { x: 0, y: 0 };
    const clientX = e.clientX - rect.left;
    const clientY = e.clientY - rect.top;
    return {
      x: (clientX - pan.x) / zoom,
      y: (clientY - pan.y) / zoom
    };
  };

  const handleMouseDown = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const coords = getCanvasCoords(e);
    let clickedNode: SimNode | null = null;
    const simNodes = Array.from(simNodesRef.current.values());

    for (let i = simNodes.length - 1; i >= 0; i--) {
      const n = simNodes[i];
      if (n.radius < 5) continue;
      const dx = coords.x - n.x;
      const dy = coords.y - n.y;
      if (dx * dx + dy * dy <= (n.radius + 8) * (n.radius + 8)) {
        clickedNode = n;
        break;
      }
    }

    if (clickedNode) {
      setDraggedNode(clickedNode);
      onSelectNode(clickedNode);
    } else {
      setIsDraggingCanvas(true);
      setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
    }
  };

  const handleDoubleClick = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const coords = getCanvasCoords(e);
    const simNodes = Array.from(simNodesRef.current.values());
    for (let i = simNodes.length - 1; i >= 0; i--) {
      const n = simNodes[i];
      if (n.radius < 5) continue;
      const dx = coords.x - n.x;
      const dy = coords.y - n.y;
      if (dx * dx + dy * dy <= (n.radius + 8) * (n.radius + 8)) {
        // FR-06: 1-Hop expand on double-click
        if (onExpandNode) onExpandNode(n.id);
        break;
      }
    }
  };

  const handleMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const coords = getCanvasCoords(e);

    if (draggedNode) {
      draggedNode.x = coords.x;
      draggedNode.y = coords.y;
      return;
    }

    if (isDraggingCanvas) {
      setPan({
        x: e.clientX - dragStart.x,
        y: e.clientY - dragStart.y
      });
      return;
    }

    let hovered: SimNode | null = null;
    const simNodes = Array.from(simNodesRef.current.values());
    for (let i = simNodes.length - 1; i >= 0; i--) {
      const n = simNodes[i];
      if (n.radius < 5) continue;
      const dx = coords.x - n.x;
      const dy = coords.y - n.y;
      if (dx * dx + dy * dy <= (n.radius + 6) * (n.radius + 6)) {
        hovered = n;
        break;
      }
    }
    setHoveredNode(hovered);
  };

  const handleMouseUp = () => {
    setDraggedNode(null);
    setIsDraggingCanvas(false);
  };

  const handleWheel = (e: React.WheelEvent<HTMLCanvasElement>) => {
    e.preventDefault();
    const zoomFactor = e.deltaY < 0 ? 1.1 : 0.9;
    setZoom(prev => Math.min(Math.max(0.4, prev * zoomFactor), 2.5));
  };

  return (
    <div ref={containerRef} className="relative w-full h-full min-h-[520px] bg-slate-950 overflow-hidden soc-grid-bg select-none">
      {/* HTML5 Canvas */}
      <canvas
        ref={canvasRef}
        onMouseDown={handleMouseDown}
        onDoubleClick={handleDoubleClick}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
        onWheel={handleWheel}
        className="w-full h-full cursor-grab active:cursor-grabbing block"
      />

      {/* Floating Canvas Controls (Top Right) */}
      <div className="absolute top-4 right-4 flex items-center gap-1.5 p-1 bg-slate-900/90 backdrop-blur-md border border-slate-800 rounded-lg shadow-xl z-20">
        <button
          onClick={() => setZoom(z => Math.min(z + 0.15, 2.5))}
          title="Zoom In"
          className="p-1.5 text-slate-400 hover:text-slate-100 hover:bg-slate-800 rounded transition-colors"
        >
          <ZoomIn className="w-4 h-4" />
        </button>
        <button
          onClick={() => setZoom(z => Math.max(z - 0.15, 0.4))}
          title="Zoom Out"
          className="p-1.5 text-slate-400 hover:text-slate-100 hover:bg-slate-800 rounded transition-colors"
        >
          <ZoomOut className="w-4 h-4" />
        </button>
        <div className="w-[1px] h-4 bg-slate-800 my-auto" />
        <button
          onClick={() => {
            setZoom(1);
            setPan({ x: 0, y: 0 });
          }}
          title="Fit View (Hotkey: F)"
          className="p-1.5 text-slate-400 hover:text-slate-100 hover:bg-slate-800 rounded transition-colors"
        >
          <RotateCcw className="w-4 h-4" />
        </button>
      </div>

      {/* Investigation Filters Panel (FR-04, FR-05) - Collapsible on Left */}
      <div className="absolute top-4 left-4 p-3 bg-slate-900/95 backdrop-blur-md border border-slate-800 rounded-xl shadow-2xl z-20 w-64 text-xs font-mono space-y-3">
        <div className="flex items-center justify-between pb-2 border-b border-slate-800 text-slate-300 font-bold">
          <div className="flex items-center gap-1.5">
            <SlidersHorizontal className="w-3.5 h-3.5 text-cyan-400" />
            <span>SUBGRAPH FILTERS</span>
          </div>
          <span className="text-[10px] text-slate-500">{nodes.length} NODES</span>
        </div>

        {/* First-Seen Edges & Crown Jewel Toggles */}
        <div className="space-y-1.5">
          <label className="flex items-center justify-between cursor-pointer text-slate-300 hover:text-slate-100">
            <span>First-Seen Only (Dashed)</span>
            <input
              type="checkbox"
              checked={filterFirstSeenOnly}
              onChange={(e) => setFilterFirstSeenOnly(e.target.checked)}
              className="rounded bg-slate-800 border-slate-700 text-cyan-500 focus:ring-cyan-400"
            />
          </label>
          <label className="flex items-center justify-between cursor-pointer text-slate-300 hover:text-slate-100">
            <span>Crown Jewels Only (👑)</span>
            <input
              type="checkbox"
              checked={filterCrownJewelOnly}
              onChange={(e) => setFilterCrownJewelOnly(e.target.checked)}
              className="rounded bg-slate-800 border-slate-700 text-cyan-500 focus:ring-cyan-400"
            />
          </label>
        </div>

        {/* Risk Band Filter */}
        <div className="pt-2 border-t border-slate-800/80">
          <span className="text-[10px] text-slate-400 block mb-1">RISK BAND (0-100):</span>
          <div className="grid grid-cols-3 gap-1">
            {(['ALL', 'HIGH', 'MEDIUM'] as const).map(b => (
              <button
                key={b}
                onClick={() => setFilterRiskBand(b)}
                className={`py-1 text-[10px] rounded font-semibold transition-colors ${
                  filterRiskBand === b
                    ? 'bg-cyan-500 text-slate-950'
                    : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                {b}
              </button>
            ))}
          </div>
        </div>

        {/* Node Shapes Legend & Toggles */}
        <div className="pt-2 border-t border-slate-800/80 space-y-1">
          <span className="text-[10px] text-slate-400 block mb-1">NODE SHAPES (SECTION 10):</span>
          <div className="grid grid-cols-2 gap-1 text-[10px]">
            <span className="flex items-center gap-1.5 text-slate-300">
              <span className="w-2.5 h-2.5 rounded-full bg-cyan-400" /> Circle: User
            </span>
            <span className="flex items-center gap-1.5 text-slate-300">
              <span className="w-2.5 h-2.5 bg-slate-400" /> Square: Host
            </span>
            <span className="flex items-center gap-1.5 text-slate-300">
              <span className="w-2.5 h-2.5 rotate-45 bg-amber-400" /> Diamond: IP
            </span>
            <span className="flex items-center gap-1.5 text-slate-300">
              <span className="w-2.5 h-2.5 bg-purple-400" /> Hex: App/DB
            </span>
          </div>
        </div>
      </div>

      {/* Graph size / truncation notice */}
      <div className={`absolute bottom-4 right-4 flex items-center gap-2 px-3 py-1.5 bg-slate-900/90 border rounded-lg text-xs font-mono z-10 ${truncated ? 'border-amber-500/50 text-amber-300' : 'border-slate-800 text-slate-400'}`}>
        <Info className="w-3.5 h-3.5 text-cyan-400" />
        <span>
          {truncated
            ? `Truncated: showing ${nodes.length} of ${totalNodeCount ?? '?'} nodes, ${edges.length} of ${totalEdgeCount ?? '?'} edges (highest risk kept)`
            : `${nodes.length} nodes · ${edges.length} edges · force-directed layout`}
        </span>
      </div>
    </div>
  );
};
