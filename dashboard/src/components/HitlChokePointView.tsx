import React from 'react';
import {
  Activity,
  AlertOctagon,
  CheckCircle2,
  Clock,
  Cpu,
  HardDrive,
  Plus,
  Shield,
  ShieldAlert,
  UserCheck,
  XCircle,
} from 'lucide-react';
import { PendingApprovalRequest } from '../types/cordon';

interface HitlChokePointViewProps {
  pendingRequests: PendingApprovalRequest[];
  onDecision: (requestId: string, decision: 'allow_once' | 'always_allow' | 'deny' | 'apoptosis') => void;
  onOpenNewRequestModal: () => void;
}

export const HitlChokePointView: React.FC<HitlChokePointViewProps> = ({
  pendingRequests,
  onDecision,
  onOpenNewRequestModal,
}) => {
  const pending = pendingRequests.filter((r) => r.status === 'pending');
  const resolved = pendingRequests.filter((r) => r.status !== 'pending');

  return (
    <div className="space-y-6">
      {/* Overview Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded p-6 flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-amber-400 font-mono text-xs uppercase tracking-wider">
            <Activity className="w-4 h-4" />
            <span>Human-in-the-Loop Interaktiver Choke Point</span>
          </div>
          <h2 className="text-xl font-bold text-white font-mono mt-1">
            Verbindungs- und Aktions-Gatekeeper
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Agenten-Anfragen zu unbekannten oder sensiblen Zielen werden im Kernel-Gatekeeper pausiert
            (Pending State). Der Host-Entwickler entscheidet interaktiv über temporäre oder permanente Freigabe,
            Abweisung oder Notfall-Apoptose. Jede Aktion wird fälschungssicher mit HMAC-SHA256 protokolliert.
          </p>
        </div>

        <button
          onClick={onOpenNewRequestModal}
          className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs rounded transition-colors flex items-center gap-1.5 cursor-pointer shadow-sm shadow-cyan-950 font-mono"
        >
          <Plus className="w-4 h-4" />
          <span>Verbindungsanfrage simulieren</span>
        </button>
      </div>

      {/* Pending Queue Section */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wide flex items-center gap-2">
            <span>Aktuelle anhängige Anfragen (Pending Choke Point)</span>
            <span className="bg-amber-500/20 text-amber-300 text-xs px-2 py-0.5 rounded border border-amber-500/40 tabular-nums">
              {pending.length}
            </span>
          </h3>
          <span className="text-xs text-slate-500 font-mono">
            Standardmäßig Fail-Closed bei Timeout
          </span>
        </div>

        {pending.length === 0 ? (
          <div className="bg-slate-900 border border-slate-800 rounded p-8 text-center space-y-2">
            <div className="w-10 h-10 rounded-full bg-slate-800 flex items-center justify-center mx-auto text-emerald-400">
              <CheckCircle2 className="w-5 h-5" />
            </div>
            <div className="text-sm font-bold text-white font-mono">
              Keine pausierten Anfragen
            </div>
            <p className="text-xs text-slate-400 max-w-md mx-auto">
              Alle aktiven Agenten-Verbindungen laufen innerhalb der genehmigten statischen Scopes
              oder dynamischen Cache-Regeln.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-4">
            {pending.map((req) => (
              <div
                key={req.id}
                className="bg-slate-900 border border-amber-500/40 rounded-lg p-5 shadow-lg space-y-4"
              >
                <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-800 pb-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-bold font-mono text-cyan-300">
                        {req.targetHost}:{req.targetPort}
                      </span>
                      <span className="text-[11px] font-mono bg-cyan-950/60 text-cyan-300 border border-cyan-800 px-2 py-0.5 rounded">
                        {req.method || 'CONNECT'}
                      </span>
                      <span className="text-xs text-amber-400 font-mono font-semibold">
                        [PAUSIERT / PENDING]
                      </span>
                    </div>
                    <div className="text-xs text-slate-400 mt-1">
                      {req.actionDescription}
                    </div>
                  </div>

                  <div className="text-right font-mono text-xs text-slate-400">
                    <span className="text-slate-500">Request ID:</span> {req.id} ·{' '}
                    <span className="text-slate-500">Risiko:</span>{' '}
                    <strong className={req.riskScore > 70 ? 'text-rose-400' : 'text-amber-400'}>
                      {req.riskScore}/100
                    </strong>
                  </div>
                </div>

                {/* Identity breakdown */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono bg-slate-950/60 p-3 rounded border border-slate-800/80">
                  <div className="space-y-1">
                    <div className="text-slate-500 flex items-center gap-1.5">
                      <Cpu className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Agent: {req.agentName}</span>
                    </div>
                    <div className="text-slate-300">Kernel PID: <strong className="text-cyan-400">{req.pid}</strong></div>
                    <div className="text-slate-400 truncate" title={req.packageSid}>
                      Package-SID: {req.packageSid}
                    </div>
                  </div>

                  <div className="space-y-1">
                    <div className="text-slate-500 flex items-center gap-1.5">
                      <HardDrive className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Pfad: {req.imagePath}</span>
                    </div>
                    <div className="text-emerald-400">
                      Sandbox Workspace: C:\CordonWorkspace\{req.agentId}\
                    </div>
                    <div className="text-slate-400">
                      Integrität: AppContainer Lowbox
                    </div>
                  </div>
                </div>

                {/* Interactive Action Decision Buttons */}
                <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
                  <button
                    onClick={() => onDecision(req.id, 'apoptosis')}
                    className="px-3 py-2 text-xs font-semibold text-rose-400 bg-rose-950/30 border border-rose-800/60 rounded hover:bg-rose-900/40 transition-colors flex items-center gap-1.5 cursor-pointer font-mono"
                    title="Sofortige Beendigung des Job Objects"
                  >
                    <ShieldAlert className="w-4 h-4 text-rose-400" />
                    <span>Notfall-Apoptose (E-4)</span>
                  </button>

                  <div className="flex items-center gap-2 flex-wrap">
                    <button
                      onClick={() => onDecision(req.id, 'deny')}
                      className="px-3.5 py-2 text-xs font-medium text-slate-300 bg-slate-800 border border-slate-700 rounded hover:bg-slate-700 transition-colors flex items-center gap-1.5 cursor-pointer font-mono"
                    >
                      <XCircle className="w-4 h-4 text-slate-400" />
                      <span>Sofort blockieren (Deny)</span>
                    </button>

                    <button
                      onClick={() => onDecision(req.id, 'always_allow')}
                      className="px-3.5 py-2 text-xs font-medium text-amber-300 bg-amber-950/40 border border-amber-600/50 rounded hover:bg-amber-900/50 transition-colors flex items-center gap-1.5 cursor-pointer font-mono"
                    >
                      <CheckCircle2 className="w-4 h-4 text-amber-400" />
                      <span>Permanent erlauben (Always Allow)</span>
                    </button>

                    <button
                      onClick={() => onDecision(req.id, 'allow_once')}
                      className="px-4 py-2 text-xs font-bold text-slate-950 bg-cyan-400 rounded hover:bg-cyan-300 transition-colors flex items-center gap-1.5 cursor-pointer font-mono shadow-sm"
                    >
                      <UserCheck className="w-4 h-4 text-slate-950" />
                      <span>Einmalig erlauben (Allow Once)</span>
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Decision History Table */}
      <div className="bg-slate-900 border border-slate-800 rounded overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-800">
          <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wide">
            Historie der Entwickler-Entscheidungen (HMAC-Audit-gesichert)
          </h3>
          <p className="text-xs text-slate-400">
            Dokumentiert jede getroffene Freigabe oder Abweisung mit Operator-Signatur
          </p>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/60 text-slate-400 uppercase text-[11px]">
                <th className="py-3 px-4 font-semibold">Request ID</th>
                <th className="py-3 px-4 font-semibold">Agent</th>
                <th className="py-3 px-4 font-semibold">Ziel &amp; Port</th>
                <th className="py-3 px-4 font-semibold">Entscheidung</th>
                <th className="py-3 px-4 font-semibold">Entwickler / Host</th>
                <th className="py-3 px-4 font-semibold text-right">Zeitstempel</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {resolved.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-6 text-center text-slate-500">
                    Noch keine archivierten Entscheidungen in dieser Sitzung.
                  </td>
                </tr>
              ) : (
                resolved.map((r) => (
                  <tr key={r.id} className="hover:bg-slate-800/40">
                    <td className="py-3 px-4 text-slate-400 font-bold">{r.id}</td>
                    <td className="py-3 px-4 text-white">{r.agentName}</td>
                    <td className="py-3 px-4 text-cyan-300">
                      {r.targetHost}:{r.targetPort}
                    </td>
                    <td className="py-3 px-4">
                      {r.status === 'allowed_once' && (
                        <span className="text-emerald-400 font-bold">Einmalig erlaubt</span>
                      )}
                      {r.status === 'always_allowed' && (
                        <span className="text-amber-400 font-bold">Permanent erlaubt</span>
                      )}
                      {r.status === 'denied' && (
                        <span className="text-rose-400 font-bold">Abgewiesen</span>
                      )}
                      {r.status === 'apoptotic' && (
                        <span className="text-rose-500 font-bold">Apoptose</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-slate-400">{r.decisionBy || 'Host Operator'}</td>
                    <td className="py-3 px-4 text-right tabular-nums text-slate-500">
                      {r.decisionTimestamp ? new Date(r.decisionTimestamp).toLocaleTimeString() : '—'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
