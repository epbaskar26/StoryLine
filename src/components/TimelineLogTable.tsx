import React, { useState } from 'react';
import { 
  Search, 
  Filter, 
  Clock, 
  ShieldAlert, 
  CheckCircle, 
  AlertTriangle, 
  Ban, 
  ArrowRight,
  ExternalLink,
  ChevronRight
} from 'lucide-react';
import { SecurityEdge, SecurityNode } from '../types';

interface Props {
  edges: SecurityEdge[];
  nodes: SecurityNode[];
  currentHour: number;
  onJumpToHour: (hour: number) => void;
  onSelectNode: (node: SecurityNode) => void;
}

export const TimelineLogTable: React.FC<Props> = ({
  edges,
  nodes,
  currentHour,
  onJumpToHour,
  onSelectNode,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');

  // Filter edges based on search and status
  const filteredEdges = edges.filter(e => {
    const matchesSearch = 
      e.action.toLowerCase().includes(searchTerm.toLowerCase()) ||
      e.source.toLowerCase().includes(searchTerm.toLowerCase()) ||
      e.target.toLowerCase().includes(searchTerm.toLowerCase()) ||
      e.protocol.toLowerCase().includes(searchTerm.toLowerCase()) ||
      e.details.toLowerCase().includes(searchTerm.toLowerCase());
    
    const matchesStatus = statusFilter === 'all' || e.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'critical':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-red-500/20 text-red-400 border border-red-500/40">
            <ShieldAlert className="w-3 h-3" /> CRITICAL
          </span>
        );
      case 'anomalous':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/20 text-amber-400 border border-amber-500/40">
            <AlertTriangle className="w-3 h-3" /> ANOMALOUS
          </span>
        );
      case 'blocked':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-slate-800 text-slate-400 border border-slate-700">
            <Ban className="w-3 h-3" /> BLOCKED
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <CheckCircle className="w-3 h-3" /> ALLOWED
          </span>
        );
    }
  };

  const handleEntityClick = (nodeId: string) => {
    const found = nodes.find(n => n.id === nodeId);
    if (found) {
      onSelectNode(found);
    }
  };

  return (
    <div className="w-full h-full flex flex-col p-6 space-y-4 overflow-hidden">
      {/* Header and Filter Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
        <div>
          <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
            <span>48-Hour Chronological Security Telemetry Grid</span>
            <span className="text-xs font-mono px-2 py-0.5 bg-slate-800 text-slate-400 rounded">
              {filteredEdges.length} Events
            </span>
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Normalized SIEM, EDR, and IAM graph events buffered from Apache Kafka & Memgraph.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Search Input */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search logs, IPs, protocols..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-slate-900 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 w-56"
            />
          </div>

          {/* Status Filter Tabs */}
          <div className="flex items-center gap-1 bg-slate-900 p-1 border border-slate-800 rounded-lg">
            {['all', 'critical', 'anomalous', 'blocked', 'allowed'].map(st => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={`px-2.5 py-1 text-xs font-medium rounded-md capitalize transition-colors ${
                  statusFilter === st
                    ? 'bg-slate-800 text-cyan-300 font-semibold shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {st}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* High-Density Data Grid */}
      <div className="flex-1 overflow-auto bg-slate-900 border border-slate-800 rounded-xl">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-950/80 sticky top-0 border-b border-slate-800 text-slate-400 font-mono text-[11px] z-10">
            <tr>
              <th className="py-2.5 px-4 font-semibold">OFFSET (T-MINUS)</th>
              <th className="py-2.5 px-4 font-semibold">SEVERITY</th>
              <th className="py-2.5 px-4 font-semibold">ACTION / THREAT ACTIVITY</th>
              <th className="py-2.5 px-4 font-semibold">SOURCE ENTITY</th>
              <th className="py-2.5 px-4 font-semibold">DESTINATION ENTITY</th>
              <th className="py-2.5 px-4 font-semibold">PROTOCOL</th>
              <th className="py-2.5 px-4 font-semibold">TELEMETRY DETAILS</th>
              <th className="py-2.5 px-4 font-semibold text-right">PIVOT</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono">
            {filteredEdges.map(edge => {
              const isCurrentOrPast = edge.hour >= currentHour;

              return (
                <tr 
                  key={edge.id}
                  className={`hover:bg-slate-800/40 transition-colors ${
                    !isCurrentOrPast ? 'opacity-40 bg-slate-950/30' : ''
                  }`}
                >
                  {/* Timestamp Offset */}
                  <td className="py-2.5 px-4 whitespace-nowrap text-slate-300 tabular-nums">
                    <button 
                      onClick={() => onJumpToHour(edge.hour)}
                      title="Jump scrubber to this moment"
                      className="hover:text-cyan-300 underline underline-offset-2 decoration-slate-600 hover:decoration-cyan-400"
                    >
                      T-{edge.hour.toString().padStart(2, '0')}:00h
                    </button>
                  </td>

                  {/* Status */}
                  <td className="py-2.5 px-4 whitespace-nowrap">
                    {getStatusBadge(edge.status)}
                  </td>

                  {/* Action */}
                  <td className="py-2.5 px-4 font-semibold text-slate-200 whitespace-nowrap font-sans">
                    {edge.action}
                  </td>

                  {/* Source */}
                  <td className="py-2.5 px-4 whitespace-nowrap">
                    <button
                      onClick={() => handleEntityClick(edge.source)}
                      className="text-cyan-400 hover:underline"
                    >
                      {edge.source}
                    </button>
                  </td>

                  {/* Target */}
                  <td className="py-2.5 px-4 whitespace-nowrap">
                    <button
                      onClick={() => handleEntityClick(edge.target)}
                      className="text-cyan-400 hover:underline"
                    >
                      {edge.target}
                    </button>
                  </td>

                  {/* Protocol */}
                  <td className="py-2.5 px-4 whitespace-nowrap text-slate-400">
                    <span className="px-1.5 py-0.5 bg-slate-950 border border-slate-800 rounded text-[10px]">
                      {edge.protocol}
                    </span>
                  </td>

                  {/* Telemetry details */}
                  <td className="py-2.5 px-4 text-slate-400 font-sans text-xs max-w-xs truncate">
                    {edge.details}
                  </td>

                  {/* Jump Action */}
                  <td className="py-2.5 px-4 whitespace-nowrap text-right">
                    <button
                      onClick={() => onJumpToHour(edge.hour)}
                      className="px-2 py-1 bg-slate-800 hover:bg-cyan-500 hover:text-slate-950 text-slate-300 rounded text-[10px] font-semibold transition-colors"
                    >
                      Inspect T-{edge.hour}h
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
