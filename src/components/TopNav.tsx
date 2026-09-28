import React from 'react';
import { 
  Users, 
  Activity, 
  Video, 
  FolderArchive,
  Network,
  Settings,
  Sun,
  Moon,
  Shield,
  Layers,
  Search,
  Sparkles,
  Command,
  ChevronDown,
  LogOut
} from 'lucide-react';
import { ViewTab, UserProfile, EntitySummary } from '../types';

interface Props {
  activeTab: ViewTab;
  onChangeTab: (tab: ViewTab) => void;
  selectedUser: UserProfile;
  selectedKey: string;
  availableUsers: EntitySummary[];
  onSelectUser: (userId: string) => void;
  onGenerateReplayClick: () => void;
  isRecording?: boolean;
  isDarkMode: boolean;
  onToggleDarkMode: () => void;
  onOpenGlobalSearch?: () => void;
  onSignOut?: () => void;
}

export const TopNav: React.FC<Props> = ({
  activeTab,
  onChangeTab,
  selectedUser,
  selectedKey,
  availableUsers,
  onSelectUser,
  onGenerateReplayClick,
  isRecording = false,
  isDarkMode,
  onToggleDarkMode,
  onOpenGlobalSearch,
  onSignOut
}) => {
  return (
    <header className="w-full bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 px-6 py-2.5 flex items-center justify-between select-none z-30 transition-colors">
      {/* Zone 1: Brand & Search bar matching Vocalyn "Ask Vocalyn / Ctrl+K" */}
      <div className="flex items-center gap-6">
        {/* Brand Logo */}
        <div className="flex items-center gap-2.5 cursor-pointer" onClick={() => onChangeTab('watchlist')}>
          <img src="/storyline-mark.png" alt="StoryLine" className="h-8 w-auto rounded-md bg-white p-1 shadow-sm" />
          <span className="text-base font-extrabold tracking-tight text-slate-900 dark:text-slate-100 font-sans">
            StoryLine
          </span>
        </div>

        {/* Global Search Pill matching Vocalyn Ctrl+K prompt */}
        <div 
          onClick={onOpenGlobalSearch}
          className="hidden md:flex items-center gap-2 px-3 py-1.5 bg-slate-100/80 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg text-xs text-slate-500 hover:border-slate-300 dark:hover:border-slate-700 cursor-pointer transition-colors"
        >
          <Search className="w-3.5 h-3.5 text-slate-400" />
          <span className="font-sans whitespace-nowrap">Search users or logs...</span>
          <kbd className="ml-3 px-1.5 py-0.5 text-[10px] font-mono bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded text-slate-400">
            Ctrl+K
          </kbd>
        </div>
      </div>

      {/* Zone 2: Navigation Links (Clean Minimal Vocalyn Style) */}
      <nav className="flex items-center gap-1">
        <button
          onClick={() => onChangeTab('watchlist')}
          className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg whitespace-nowrap transition-colors ${
            activeTab === 'watchlist'
              ? 'bg-slate-100 dark:bg-slate-800 text-slate-900 dark:text-cyan-300 font-bold'
              : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
          }`}
        >
          <Users className="w-3.5 h-3.5" />
          <span>Watchlist</span>
        </button>

        <button
          onClick={() => onChangeTab('investigation')}
          className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg whitespace-nowrap transition-colors ${
            activeTab === 'investigation'
              ? 'bg-slate-100 dark:bg-slate-800 text-slate-900 dark:text-cyan-300 font-bold'
              : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
          }`}
        >
          <Activity className="w-3.5 h-3.5" />
          <span>Investigation</span>
        </button>

        <button
          onClick={() => onChangeTab('replay')}
          className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg whitespace-nowrap transition-colors ${
            activeTab === 'replay'
              ? 'bg-slate-100 dark:bg-slate-800 text-slate-900 dark:text-cyan-300 font-bold'
              : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
          }`}
        >
          <Video className="w-3.5 h-3.5" />
          <span>Replay Studio</span>
        </button>

        <button
          onClick={() => onChangeTab('cases')}
          className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg whitespace-nowrap transition-colors ${
            activeTab === 'cases'
              ? 'bg-slate-100 dark:bg-slate-800 text-slate-900 dark:text-cyan-300 font-bold'
              : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
          }`}
        >
          <FolderArchive className="w-3.5 h-3.5" />
          <span>Cases</span>
        </button>

        {/* Brand New: SIEM & Tools Integrations Tab */}
        <button
          onClick={() => onChangeTab('integrations')}
          className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg whitespace-nowrap transition-colors ${
            activeTab === 'integrations'
              ? 'bg-slate-100 dark:bg-slate-800 text-slate-900 dark:text-cyan-300 font-bold'
              : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
          }`}
        >
          <Network className="w-3.5 h-3.5" />
          <span>Integrations</span>
        </button>

        <button
          onClick={() => onChangeTab('admin')}
          className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg whitespace-nowrap transition-colors ${
            activeTab === 'admin'
              ? 'bg-slate-100 dark:bg-slate-800 text-slate-900 dark:text-cyan-300 font-bold'
              : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
          }`}
        >
          <Settings className="w-3.5 h-3.5" />
          <span>Admin & Rules</span>
        </button>
      </nav>

      {/* Zone 3: Window Selector, User Select, Light/Dark Toggle & Primary CTA */}
      <div className="flex items-center gap-3">
        {/* User Identity Switcher */}
        <div className="relative">
          <select
            value={selectedKey}
            onChange={(e) => onSelectUser(e.target.value)}
            className="appearance-none bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700/80 rounded-lg px-3 py-1.5 pr-7 text-xs font-mono text-slate-800 dark:text-slate-200 hover:border-slate-300 dark:hover:border-slate-600 focus:outline-none cursor-pointer"
          >
            {!availableUsers.some(u => u.id === selectedKey) && (
              <option value={selectedKey}>
                {selectedUser.username} (Risk: {selectedUser.riskScore})
              </option>
            )}
            {availableUsers.map((u) => (
              <option key={u.id} value={u.id}>
                {u.username} (Risk: {u.riskScore})
              </option>
            ))}
          </select>
          <ChevronDown className="w-3.5 h-3.5 text-slate-400 absolute right-2 top-1/2 -translate-y-1/2 pointer-events-none" />
        </div>

        {/* Light / Dark Mode Toggle Button (Matching Vocalyn Top Right) */}
        <button
          onClick={onToggleDarkMode}
          title={isDarkMode ? 'Switch to Light Theme' : 'Switch to Dark Theme'}
          className="p-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 dark:bg-slate-900 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-300 border border-slate-200 dark:border-slate-800 transition-colors"
        >
          {isDarkMode ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4 text-slate-400" />}
        </button>

        {/* Primary CTA Button matching Vocalyn "Test Your Agent" sleek pill */}
        <button
          onClick={onGenerateReplayClick}
          className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-all shadow-sm ${
            isRecording
              ? 'bg-red-600 text-white animate-pulse'
              : 'bg-cyan-600 hover:bg-cyan-500 text-white font-semibold'
          }`}
        >
          <Video className="w-3.5 h-3.5" />
          <span>{isRecording ? 'Recording...' : 'Generate Replay'}</span>
        </button>

        {onSignOut && (
          <button
            data-testid="sign-out"
            onClick={onSignOut}
            title="Sign out (demo)"
            className="p-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 dark:bg-slate-900 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-300 border border-slate-200 dark:border-slate-800 transition-colors"
          >
            <LogOut className="w-4 h-4" />
          </button>
        )}
      </div>
    </header>
  );
};
