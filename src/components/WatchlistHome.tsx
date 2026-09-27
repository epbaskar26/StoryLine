import React, { useState } from 'react';
import { 
  Users, 
  Search, 
  Plus, 
  Trash2, 
  ArrowRight, 
  ShieldAlert, 
  Clock, 
  ExternalLink,
  Calendar,
  UserCheck
} from 'lucide-react';
import { WatchlistItem, RiskBand } from '../types';

interface Props {
  watchlist: WatchlistItem[];
  onSelectEntity: (entityId: string) => void;
  onRemoveFromWatchlist: (id: string) => void;
  onAddToWatchlist: (entityId: string, reason: string) => void;
}

export const WatchlistHome: React.FC<Props> = ({
  watchlist,
  onSelectEntity,
  onRemoveFromWatchlist,
  onAddToWatchlist
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [aliasSearchResults, setAliasSearchResults] = useState<any[]>([]);
  const [isSearching, setIsSearching] = useState(false);
  const [showAddModal, setShowAddModal] = useState(false);
  const [newReason, setNewReason] = useState('Anomalous credential access spike');

  // Search entities & resolve aliases (FR-01)
  const handleSearchChange = (term: string) => {
    setSearchTerm(term);
    if (!term.trim()) {
      setAliasSearchResults([]);
      return;
    }

    setIsSearching(true);
    fetch(`/api/entities/resolve?term=${encodeURIComponent(term)}`)
      .then(res => res.json())
      .then(data => {
        if (data.matches) {
          setAliasSearchResults(data.matches);
        }
      })
      .catch(err => console.error(err))
      .finally(() => setIsSearching(false));
  };

  return (
    <div className="w-full h-full flex flex-col p-6 space-y-6 overflow-y-auto">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs mb-1">
            <Users className="w-4 h-4" />
            <span>FR-01 & FR-03: WATCHLIST & CANONICAL ALIAS RESOLUTION</span>
          </div>
          <h2 className="text-xl font-bold text-slate-100">
            Monitored Risky Identities & Watchlist Home
          </h2>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            Triage alerts in minutes. Search any identity by username, UPN, corporate email, or Windows Kerberos SID—WatchMe resolves them into a single canonical identity.
          </p>
        </div>

        {/* Global Alias Search Bar (FR-01) */}
        <div className="relative w-full md:w-80">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search username, UPN, SID, email..."
            value={searchTerm}
            onChange={(e) => handleSearchChange(e.target.value)}
            className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-9 pr-4 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono"
          />

          {/* Autocomplete Dropdown for Canonical Resolution */}
          {aliasSearchResults.length > 0 && (
            <div className="absolute top-full left-0 right-0 mt-1 bg-slate-900 border border-slate-700 rounded-lg shadow-2xl z-30 overflow-hidden divide-y divide-slate-800">
              {aliasSearchResults.map((match) => (
                <div
                  key={match.canonicalId}
                  onClick={() => {
                    onSelectEntity(match.id);
                    setSearchTerm('');
                    setAliasSearchResults([]);
                  }}
                  className="p-3 hover:bg-slate-800/80 cursor-pointer transition-colors"
                >
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="text-cyan-300 font-bold">{match.fullName}</span>
                    <span className="text-red-400 font-bold">Risk: {match.riskScore}</span>
                  </div>
                  <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                    Canonical ID: {match.canonicalId}
                  </div>
                  <div className="text-[10px] text-slate-500 font-mono mt-0.5">
                    Matched alias: <span className="text-slate-300">{match.matchedAlias}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Watchlist Cards Grid (FR-03: Up to 20 concurrent entities per analyst) */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-slate-200 font-mono flex items-center gap-2">
            <span>ACTIVE WATCHLIST ENTITIES</span>
            <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-400">
              {watchlist.length}/20 CONCURRENT
            </span>
          </h3>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {watchlist.map(item => (
            <div
              key={item.id}
              className="bg-slate-900 border border-slate-800 hover:border-slate-700 rounded-xl p-5 flex flex-col justify-between transition-all group"
            >
              <div>
                <div className="flex items-start justify-between mb-3">
                  <div>
                    <h4 className="text-sm font-bold text-slate-100 font-mono group-hover:text-cyan-300 transition-colors">
                      {item.canonicalName}
                    </h4>
                    <span className="text-[11px] font-mono text-slate-400">
                      Owner: {item.owner}
                    </span>
                  </div>

                  <span className="px-2 py-0.5 bg-red-500/20 text-red-400 border border-red-500/40 rounded text-xs font-mono font-bold">
                    Risk: {item.riskScore}
                  </span>
                </div>

                <p className="text-xs text-slate-400 font-sans mb-4 line-clamp-2">
                  {item.reason}
                </p>

                {/* 48h Risk Sparkline */}
                <div className="mb-4 p-2 bg-slate-950 rounded border border-slate-800/80">
                  <span className="text-[9px] font-mono text-slate-500 block mb-1">
                    48H RISK SPARKLINE:
                  </span>
                  <div className="flex items-end gap-1 h-6">
                    {item.sparkline.map((val, sIdx) => (
                      <div
                        key={sIdx}
                        className="flex-1 bg-gradient-to-t from-cyan-600 to-red-500 rounded-t-[1px]"
                        style={{ height: `${val}%` }}
                        title={`Score: ${val}`}
                      />
                    ))}
                  </div>
                </div>
              </div>

              <div className="pt-3 border-t border-slate-800 flex items-center justify-between text-xs font-mono">
                <span className="text-slate-500 text-[10px]">
                  Expires: {new Date(item.expiry).toLocaleDateString()}
                </span>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => onRemoveFromWatchlist(item.id)}
                    className="p-1 text-slate-500 hover:text-red-400 transition-colors"
                    title="Remove from Watchlist"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>

                  <button
                    onClick={() => onSelectEntity(item.entityId)}
                    className="flex items-center gap-1 px-3 py-1 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold rounded text-xs transition-colors"
                  >
                    <span>Investigate</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
