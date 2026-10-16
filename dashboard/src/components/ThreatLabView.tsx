import React, { useState } from 'react';
import { ThreatScenario } from '../types/cordon';
import { ShieldAlert, Play, CheckCircle2, AlertOctagon, Terminal, Lock } from 'lucide-react';

interface ThreatLabViewProps {
  scenarios: ThreatScenario[];
  onRunScenario: (scenarioId: string) => void;
}

export const ThreatLabView: React.FC<ThreatLabViewProps> = ({
  scenarios,
  onRunScenario,
}) => {
  const [selectedId, setSelectedId] = useState<string>(scenarios[0]?.id || 'T1');
  const selectedScenario = scenarios.find((s) => s.id === selectedId) || scenarios[0];

  return (
    <div className="space-y-6">
      {/* Overview Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded p-6">
        <div className="flex items-center gap-2 text-rose-400 font-mono text-xs uppercase tracking-wider">
          <ShieldAlert className="w-4 h-4" />
          <span>Bedrohungsmodell &amp; Kernel-Penetration-Testing Suite</span>
        </div>
        <h2 className="text-xl font-bold text-white font-mono mt-1">
          Cordon Threat Simulation Lab (T1 bis T10 + E-1..E-4)
        </h2>
        <p className="text-xs text-slate-400 mt-1 max-w-3xl">
          Verifiziere, warum herkömmliche User-Mode Proxies versagen und wie Cordon kompromittierte Agenten
          auf Betriebssystemebene durch AppContainer, WFP, Job Objects, Lowbox ACLs und den interaktiven
          Human-in-the-Loop Choke Point unüberwindbar einsperrt.
        </p>
      </div>

      {/* Grid of Scenarios */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Scenarios List */}
        <div className="bg-slate-900 border border-slate-800 rounded p-4 space-y-2">
          <div className="text-xs font-mono text-slate-400 uppercase font-bold px-2 pb-1 border-b border-slate-800 flex justify-between">
            <span>Angriffsszenarien ({scenarios.length})</span>
            <span>Schicht</span>
          </div>

          <div className="space-y-1.5 max-h-[560px] overflow-y-auto">
            {scenarios.map((s) => {
              const isSelected = s.id === selectedId;

              return (
                <div
                  key={s.id}
                  onClick={() => setSelectedId(s.id)}
                  className={`p-3 rounded border text-xs font-mono cursor-pointer transition-colors ${
                    isSelected
                      ? 'bg-slate-800 border-cyan-500 shadow-sm'
                      : 'bg-slate-950/60 border-slate-800/80 hover:bg-slate-800/40'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-cyan-400">{s.code}</span>
                    <span className="text-[10px] text-slate-400 bg-slate-800 px-1.5 py-0.5 rounded">
                      {s.layer}
                    </span>
                  </div>

                  <div className="text-white font-medium mt-1 truncate">
                    {s.title}
                  </div>

                  <div className="flex items-center justify-between mt-2 pt-1 border-t border-slate-800/80 text-[10px]">
                    <span className="text-slate-500">{s.category}</span>
                    {s.status === 'blocked' && (
                      <span className="text-emerald-400 font-bold flex items-center gap-1">
                        <CheckCircle2 className="w-3 h-3" />
                        <span>Abgewehrt</span>
                      </span>
                    )}
                    {s.status === 'running' && (
                      <span className="text-amber-400 animate-pulse font-bold">
                        Wird getestet...
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Selected Scenario Details & Execution Terminal */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded p-6 space-y-5">
          <div className="flex flex-wrap items-start justify-between gap-4 border-b border-slate-800 pb-4">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-lg font-bold font-mono text-cyan-400">
                  [{selectedScenario.code}] {selectedScenario.title}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Kategorie: <strong className="text-slate-200">{selectedScenario.category}</strong> ·
                Erzwingungsebene: <strong className="text-emerald-400">{selectedScenario.layer}</strong>
              </p>
            </div>

            <button
              onClick={() => onRunScenario(selectedScenario.id)}
              disabled={selectedScenario.status === 'running'}
              className="px-4 py-2 bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white font-bold text-xs font-mono rounded transition-colors flex items-center gap-2 cursor-pointer shadow-sm shadow-rose-950"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Angriff ausführen &amp; prüfen</span>
            </button>
          </div>

          {/* Description & Attack Vector */}
          <div className="space-y-3 text-xs font-mono">
            <div>
              <span className="text-slate-400 uppercase text-[11px] block mb-1">
                Angriffsbeschreibung &amp; Bedrohung:
              </span>
              <p className="text-slate-200 bg-slate-950/60 p-3 rounded border border-slate-800">
                {selectedScenario.description}
              </p>
            </div>

            <div>
              <span className="text-slate-400 uppercase text-[11px] block mb-1">
                Syscall / Exploit-Vektor:
              </span>
              <pre className="bg-slate-950 p-3 rounded border border-slate-800 text-rose-300 overflow-x-auto">
                {selectedScenario.attackVector}
              </pre>
            </div>

            <div>
              <span className="text-slate-400 uppercase text-[11px] block mb-1">
                Erwartetes Kernel-Verhalten:
              </span>
              <p className="text-emerald-300 bg-emerald-950/30 border border-emerald-800/40 p-3 rounded">
                {selectedScenario.expectedResult}
              </p>
            </div>
          </div>

          {/* Execution Log Console */}
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs font-mono text-slate-400 uppercase">
              <span className="flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                <span>Kernel-Audit-Protokoll &amp; Tracer</span>
              </span>
              <span className="text-emerald-400 font-bold">STATUS: ENFORCED</span>
            </div>

            <div className="bg-slate-950 rounded border border-slate-800 p-4 font-mono text-xs text-slate-300 space-y-1.5 max-h-52 overflow-y-auto">
              {selectedScenario.log.map((line, i) => (
                <div key={i} className="flex gap-2">
                  <span className="text-slate-600 select-none">&gt;</span>
                  <span
                    className={
                      line.includes('[BLOCK]') || line.includes('[ENFORCEMENT]') || line.includes('[ALARM]')
                        ? 'text-emerald-400 font-semibold'
                        : line.includes('[KERNEL]') || line.includes('[JOB-OBJECT]')
                        ? 'text-cyan-300'
                        : 'text-slate-300'
                    }
                  >
                    {line}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
