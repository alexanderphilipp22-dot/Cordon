import React, { useState, useEffect } from 'react';
import { AlertOctagon, CheckCircle2, ShieldAlert, XCircle, Clock, Server, UserCheck, Cpu, HardDrive } from 'lucide-react';
import { PendingApprovalRequest } from '../types/cordon';

interface HumanApprovalModalProps {
  request: PendingApprovalRequest | null;
  onClose: () => void;
  onDecision: (requestId: string, decision: 'allow_once' | 'always_allow' | 'deny' | 'apoptosis') => void;
}

export const HumanApprovalModal: React.FC<HumanApprovalModalProps> = ({
  request,
  onClose,
  onDecision,
}) => {
  const [countdown, setCountdown] = useState(30);

  useEffect(() => {
    if (!request) return;
    setCountdown(30);

    const timer = setInterval(() => {
      setCountdown((prev) => {
        if (prev <= 1) {
          clearInterval(timer);
          // Fail-closed timeout
          onDecision(request.id, 'deny');
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [request]);

  if (!request) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-slate-900 border border-slate-700 rounded-lg max-w-2xl w-full shadow-2xl overflow-hidden flex flex-col">
        {/* Header Bar */}
        <div className="bg-amber-950/40 border-b border-amber-500/30 px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded bg-amber-500/20 border border-amber-500/40 flex items-center justify-center text-amber-400">
              <AlertOctagon className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                Interaktiver Choke Point — Anfrage Pausiert
              </h2>
              <p className="text-xs text-amber-300/80">
                Agent fordert ausgehende Verbindung an · Genehmigung erforderlich
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 text-xs font-mono text-amber-400 bg-amber-950/60 px-2.5 py-1 rounded border border-amber-500/30">
            <Clock className="w-3.5 h-3.5" />
            <span>Timeout: <strong className="tabular-nums">{countdown}s</strong> (Fail-Closed)</span>
          </div>
        </div>

        {/* Content Body */}
        <div className="p-6 space-y-5 text-sm">
          {/* Target Highlight Box */}
          <div className="bg-slate-950 border border-slate-800 rounded p-4 flex flex-col gap-2">
            <span className="text-xs uppercase tracking-wider text-slate-400 font-mono">
              Angeforderte Verbindung
            </span>
            <div className="flex items-baseline gap-3 flex-wrap">
              <span className="text-lg font-mono font-bold text-cyan-400">
                {request.targetHost}:{request.targetPort}
              </span>
              <span className="text-xs font-mono bg-cyan-950/60 text-cyan-300 border border-cyan-800 px-2 py-0.5 rounded">
                {request.method || 'CONNECT'} {request.path || '/'}
              </span>
              <span className="text-xs text-slate-400">
                Risikostufe: <strong className={`tabular-nums ${request.riskScore > 70 ? 'text-rose-400' : 'text-amber-400'}`}>{request.riskScore}/100</strong>
              </span>
            </div>
          </div>

          {/* Agent Identity Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="border border-slate-800 bg-slate-950/40 rounded p-3.5 space-y-2">
              <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
                <Cpu className="w-3.5 h-3.5 text-cyan-400" />
                <span>Kernel-attestierte Identität</span>
              </div>
              <div className="space-y-1 text-xs font-mono">
                <div className="flex justify-between">
                  <span className="text-slate-500">Agent Name:</span>
                  <span className="text-slate-200 font-medium">{request.agentName}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Kernel PID:</span>
                  <span className="text-cyan-300 tabular-nums">{request.pid}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Package-SID:</span>
                  <span className="text-slate-300 truncate max-w-[180px]" title={request.packageSid}>
                    {request.packageSid}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Integrität:</span>
                  <span className="text-emerald-400">AppContainer (Low)</span>
                </div>
              </div>
            </div>

            <div className="border border-slate-800 bg-slate-950/40 rounded p-3.5 space-y-2">
              <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
                <HardDrive className="w-3.5 h-3.5 text-cyan-400" />
                <span>Dateisystem &amp; Pfad</span>
              </div>
              <div className="space-y-1 text-xs font-mono">
                <div className="text-slate-500">Image Path:</div>
                <div className="text-slate-300 text-[11px] truncate" title={request.imagePath}>
                  {request.imagePath}
                </div>
                <div className="text-slate-500 pt-1">Sandbox-Workspace:</div>
                <div className="text-emerald-400 text-[11px]">
                  C:\CordonWorkspace\{request.agentId}\ (Lowbox ACL)
                </div>
              </div>
            </div>
          </div>

          {/* Risk Factors */}
          <div className="border border-rose-950/40 bg-rose-950/10 rounded p-3 text-xs text-rose-300 space-y-1">
            <span className="font-semibold block text-rose-200">Erkannte Risikofaktoren:</span>
            <ul className="list-disc list-inside space-y-0.5 text-rose-300/80">
              {request.riskFactors.map((factor, i) => (
                <li key={i}>{factor}</li>
              ))}
            </ul>
          </div>
        </div>

        {/* Action Buttons Bar */}
        <div className="bg-slate-950 border-t border-slate-800 p-4 flex flex-wrap items-center justify-between gap-3">
          <button
            onClick={() => {
              onDecision(request.id, 'apoptosis');
              onClose();
            }}
            className="px-3 py-2 text-xs font-semibold text-rose-400 bg-rose-950/30 border border-rose-800/60 rounded hover:bg-rose-900/40 transition-colors flex items-center gap-1.5 cursor-pointer"
            title="Sofortige Zerstörung des Job Objects (E-4 Apoptose)"
          >
            <ShieldAlert className="w-4 h-4 text-rose-400" />
            <span>Notfall-Apoptose</span>
          </button>

          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={() => {
                onDecision(request.id, 'deny');
                onClose();
              }}
              className="px-4 py-2 text-xs font-medium text-slate-300 bg-slate-800 border border-slate-700 rounded hover:bg-slate-700 transition-colors flex items-center gap-1.5 cursor-pointer"
            >
              <XCircle className="w-4 h-4 text-slate-400" />
              <span>Sofort blockieren (Deny)</span>
            </button>

            <button
              onClick={() => {
                onDecision(request.id, 'always_allow');
                onClose();
              }}
              className="px-4 py-2 text-xs font-medium text-amber-300 bg-amber-950/40 border border-amber-600/50 rounded hover:bg-amber-900/50 transition-colors flex items-center gap-1.5 cursor-pointer"
            >
              <CheckCircle2 className="w-4 h-4 text-amber-400" />
              <span>Permanent erlauben (Always Allow)</span>
            </button>

            <button
              onClick={() => {
                onDecision(request.id, 'allow_once');
                onClose();
              }}
              className="px-4 py-2 text-xs font-bold text-slate-950 bg-cyan-400 rounded hover:bg-cyan-300 transition-colors flex items-center gap-1.5 cursor-pointer shadow-sm shadow-cyan-950"
            >
              <UserCheck className="w-4 h-4 text-slate-950" />
              <span>Einmalig erlauben (Allow Once)</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
