import React, { useState, useEffect } from 'react';
import { AuditRecord } from '../types/cordon';
import { verifyAuditChain, VerificationResult } from '../services/crypto';
import { ShieldCheck, ShieldAlert, RefreshCw, Key, Database, AlertTriangle } from 'lucide-react';

interface AuditLogViewProps {
  auditLog: AuditRecord[];
  onTamperRecord: (index: number, newReason: string) => void;
  onRestoreRecord: (index: number) => void;
}

export const AuditLogView: React.FC<AuditLogViewProps> = ({
  auditLog,
  onTamperRecord,
  onRestoreRecord,
}) => {
  const [verification, setVerification] = useState<VerificationResult | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);

  const runVerification = async () => {
    setIsVerifying(true);
    const res = await verifyAuditChain(auditLog);
    setVerification(res);
    setIsVerifying(false);
  };

  useEffect(() => {
    runVerification();
  }, [auditLog]);

  return (
    <div className="space-y-6">
      {/* Overview Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded p-6 flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs uppercase tracking-wider">
            <Key className="w-4 h-4" />
            <span>Kryptografische HMAC-SHA256 Vorwärtskettung &amp; DPAPI</span>
          </div>
          <h2 className="text-xl font-bold text-white font-mono mt-1">
            Manipulationssicheres Audit-Log &amp; Chain Verifier
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Jedes Audit-Event wird in einer kontinuierlichen Hash-Kette
            <code className="text-cyan-300 ml-1">hmac_n = HMAC(K, hmac_{'{n-1}'} || canonical(event_n))</code>
            versiegelt. Der Schlüssel <span className="text-slate-200">K</span> ist über Windows DPAPI
            (LocalMachine-Scope) geschützt. Eine nachträgliche Modifikation wird mathematisch sofort lokalisiert.
          </p>
        </div>

        <button
          onClick={runVerification}
          disabled={isVerifying}
          className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white font-bold text-xs font-mono rounded border border-slate-700 transition-colors flex items-center gap-2 cursor-pointer shadow-sm"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isVerifying ? 'animate-spin' : ''}`} />
          <span>Kette neu verifizieren</span>
        </button>
      </div>

      {/* Verification Status Card */}
      <div
        className={`p-4 rounded border font-mono text-xs flex flex-wrap items-center justify-between gap-4 ${
          verification?.valid
            ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-300'
            : 'bg-rose-950/40 border-rose-500/60 text-rose-300'
        }`}
      >
        <div className="flex items-center gap-3">
          {verification?.valid ? (
            <ShieldCheck className="w-6 h-6 text-emerald-400" />
          ) : (
            <ShieldAlert className="w-6 h-6 text-rose-400" />
          )}

          <div>
            <div className="font-bold text-sm">
              {verification?.valid
                ? 'Kryptografische Integrität bestätigt (Chain Valid)'
                : 'ALARM: Manipulation erkannt! Ungültige HMAC-Signatur!'}
            </div>
            <div className="text-[11px] opacity-80 mt-0.5">
              {verification?.valid
                ? `Alle ${verification.totalRecords} Datensätze fehlerfrei mit DPAPI-Master-Key validiert.`
                : `Datensatz Index #${verification?.brokenIndex} weicht vom Hash ab! Manipulationsversuch nachgewiesen.`}
            </div>
          </div>
        </div>

        {/* Tamper Test Simulator Control */}
        <div className="flex items-center gap-2">
          {auditLog.some((l) => l.isTampered) ? (
            <button
              onClick={() => onRestoreRecord(auditLog.find((l) => l.isTampered)!.index)}
              className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white text-xs rounded transition-colors cursor-pointer"
            >
              Originalzustand wiederherstellen
            </button>
          ) : (
            <button
              onClick={() => {
                if (auditLog.length > 2) {
                  onTamperRecord(3, 'Angreifer hat diese Begründung unbemerkt geändert!');
                }
              }}
              className="px-3 py-1.5 bg-rose-700 hover:bg-rose-600 text-white text-xs rounded transition-colors cursor-pointer"
              title="Simuliert Angreifer, der versucht die Log-Datei im Text-Editor zu verändern"
            >
              Test: Datensatz #3 manipulieren
            </button>
          )}
        </div>
      </div>

      {/* Log Entries Table */}
      <div className="bg-slate-900 border border-slate-800 rounded overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
          <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wide">
            Append-Only JSONL Audit-Stream ({auditLog.length} Einträge)
          </h3>
          <span className="text-xs text-slate-500 font-mono">Format: canonical(JSON) + HMAC</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/60 text-slate-400 uppercase text-[11px]">
                <th className="py-3 px-4 font-semibold">Idx</th>
                <th className="py-3 px-4 font-semibold">Zeitstempel</th>
                <th className="py-3 px-4 font-semibold">Event Type</th>
                <th className="py-3 px-4 font-semibold">Agent</th>
                <th className="py-3 px-4 font-semibold">Details &amp; Payload</th>
                <th className="py-3 px-4 font-semibold text-right">HMAC-SHA256 Hash</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {auditLog.map((record) => {
                return (
                  <tr
                    key={record.index}
                    className={`hover:bg-slate-800/40 transition-colors ${
                      record.isTampered ? 'bg-rose-950/30' : ''
                    }`}
                  >
                    <td className="py-3 px-4 text-slate-500 font-bold tabular-nums">
                      #{record.index}
                    </td>

                    <td className="py-3 px-4 text-slate-400 whitespace-nowrap tabular-nums">
                      {new Date(record.timestamp).toLocaleTimeString()}
                    </td>

                    <td className="py-3 px-4">
                      <span
                        className={`font-semibold ${
                          record.eventType.includes('DENIED') || record.eventType.includes('APOPTOSIS')
                            ? 'text-rose-400'
                            : record.eventType.startsWith('HITL_')
                            ? 'text-amber-400'
                            : 'text-cyan-400'
                        }`}
                      >
                        {record.eventType}
                      </span>
                    </td>

                    <td className="py-3 px-4 text-slate-300 font-medium">{record.agentId}</td>

                    <td className="py-3 px-4 max-w-md">
                      <div className="text-slate-300 text-[11px] truncate" title={JSON.stringify(record.details)}>
                        {JSON.stringify(record.details)}
                      </div>
                      {record.isTampered && (
                        <div className="text-rose-400 font-bold text-[10px] mt-0.5">
                          [MANIPULIERT]: Details modifiziert ohne DPAPI-Key!
                        </div>
                      )}
                    </td>

                    <td className="py-3 px-4 text-right tabular-nums">
                      <span
                        className={`text-[10px] ${
                          record.isTampered ? 'text-rose-400 font-bold line-through' : 'text-slate-500'
                        }`}
                        title={`HMAC: ${record.hmac}`}
                      >
                        {record.hmac.substring(0, 16)}...
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
