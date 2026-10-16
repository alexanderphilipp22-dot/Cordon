import React from 'react';
import { Shield, AlertTriangle, Terminal, Lock } from 'lucide-react';

interface HeaderProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  pendingCount: number;
  onOpenNewRequestModal: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  pendingCount,
  onOpenNewRequestModal,
}) => {
  return (
    <header className="flex items-center justify-between gap-8 px-6 py-3.5 border-b border-slate-800 bg-slate-950/80 backdrop-blur sticky top-0 z-40">
      {/* Zone 1: Single text element wordmark */}
      <div className="flex items-center gap-3 whitespace-nowrap shrink-0">
        <div className="w-8 h-8 rounded bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
          <Shield className="w-4 h-4" />
        </div>
        <div>
          <span className="text-base font-bold tracking-tight text-white uppercase font-mono">
            C.O.R.D.O.N.
          </span>
          <span className="text-xs text-slate-400 ml-2 hidden sm:inline">
            Kernel-Enforced Windows Gateway
          </span>
        </div>
      </div>

      {/* Zone 2: Navigation Links */}
      <nav className="hidden lg:flex items-center gap-6 text-sm font-medium text-slate-300">
        <button
          onClick={() => setActiveTab('dashboard')}
          className={`hover:text-cyan-400 transition-colors whitespace-nowrap shrink-0 ${
            activeTab === 'dashboard' ? 'text-cyan-400 font-semibold' : ''
          }`}
        >
          Gateway Mesh
        </button>

        <button
          onClick={() => setActiveTab('policies')}
          className={`hover:text-cyan-400 transition-colors whitespace-nowrap shrink-0 ${
            activeTab === 'policies' ? 'text-cyan-400 font-semibold' : ''
          }`}
        >
          Policy Studio
        </button>

        <button
          onClick={() => setActiveTab('hitl')}
          className={`hover:text-cyan-400 transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 ${
            activeTab === 'hitl' ? 'text-cyan-400 font-semibold' : ''
          }`}
        >
          <span>HITL Choke Point</span>
          {pendingCount > 0 && (
            <span className="bg-amber-500/20 text-amber-300 text-xs px-1.5 py-0.2 rounded border border-amber-500/40 tabular-nums">
              {pendingCount}
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveTab('inspector')}
          className={`hover:text-cyan-400 transition-colors whitespace-nowrap shrink-0 ${
            activeTab === 'inspector' ? 'text-cyan-400 font-semibold' : ''
          }`}
        >
          Protocol Inspector
        </button>

        <button
          onClick={() => setActiveTab('threatlab')}
          className={`hover:text-cyan-400 transition-colors whitespace-nowrap shrink-0 ${
            activeTab === 'threatlab' ? 'text-cyan-400 font-semibold' : ''
          }`}
        >
          Threat Lab (T1–T10)
        </button>

        <button
          onClick={() => setActiveTab('audit')}
          className={`hover:text-cyan-400 transition-colors whitespace-nowrap shrink-0 ${
            activeTab === 'audit' ? 'text-cyan-400 font-semibold' : ''
          }`}
        >
          HMAC Audit Verifier
        </button>

        <button
          onClick={() => setActiveTab('codebase')}
          className={`hover:text-cyan-400 transition-colors whitespace-nowrap shrink-0 flex items-center gap-1 ${
            activeTab === 'codebase' ? 'text-cyan-400 font-semibold' : ''
          }`}
        >
          <Terminal className="w-3.5 h-3.5" />
          <span>C# Codebase</span>
        </button>
      </nav>

      {/* Zone 3: Primary Action */}
      <div className="flex items-center gap-3 shrink-0">
        <button
          onClick={onOpenNewRequestModal}
          className="px-3.5 py-1.5 text-xs font-semibold text-slate-900 bg-cyan-400 rounded hover:bg-cyan-300 transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5 cursor-pointer shadow-sm shadow-cyan-900/20"
        >
          <Lock className="w-3.5 h-3.5" />
          <span>Anfrage simulieren</span>
        </button>
      </div>
    </header>
  );
};
