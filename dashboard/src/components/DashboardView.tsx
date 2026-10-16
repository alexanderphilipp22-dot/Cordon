import React, { useState } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  ArrowUpRight,
  CheckCircle2,
  Cpu,
  Database,
  ExternalLink,
  Flame,
  HardDrive,
  Network,
  RefreshCw,
  RotateCcw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Zap,
} from 'lucide-react';
import { AgentProfile, AuditRecord } from '../types/cordon';

interface DashboardViewProps {
  agents: AgentProfile[];
  auditLog: AuditRecord[];
  pendingCount: number;
  isLearnModeActive?: boolean;
  tpmActive?: boolean;
  onRotateGenotype: (agentId: string) => void;
  onTriggerApoptosis: (agentId: string) => void;
  onTriggerCanaryAccess?: (agentId: string, baitName: string) => void;
  onTestInterAgentIsolation?: (sourceId: string, targetId: string) => void;
  onSelectAgent: (agent: AgentProfile) => void;
  onOpenHitl: () => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  agents,
  auditLog,
  pendingCount,
  isLearnModeActive = false,
  tpmActive = true,
  onRotateGenotype,
  onTriggerApoptosis,
  onTriggerCanaryAccess,
  onTestInterAgentIsolation,
  onSelectAgent,
  onOpenHitl,
}) => {
  const [timeRange, setTimeRange] = useState<'1h' | '24h' | 'all'>('1h');
  const [eventFilter, setEventFilter] = useState<string>('all');

  // Compute aggregate metrics
  const totalBytesUp = agents.reduce((acc, a) => acc + a.bytesUp, 0);
  const totalBytesDown = agents.reduce((acc, a) => acc + a.bytesDown, 0);
  const totalActiveSockets = agents.reduce((acc, a) => acc + a.activeSockets, 0);
  const activeCount = agents.filter((a) => a.status === 'active').length;
  const isolatedCount = agents.filter((a) => a.status === 'isolated').length;
  const apoptoticCount = agents.filter((a) => a.status === 'apoptotic').length;

  // Filter security violations
  const securityViolations = auditLog.filter((l) =>
    [
      'DNS_REBINDING_BLOCKED',
      'LOWBOX_ACL_VIOLATION',
      'JOB_LIMIT_ENFORCED',
      'APOPTOSIS_EXECUTED',
      'HITL_DECISION_DENIED',
    ].includes(l.eventType)
  );

  const formatBytes = (bytes: number) => {
    if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(2)} MB`;
    if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${bytes} B`;
  };

  // Mock timeline series data for the SVG network throughput chart
  const timelinePoints = [
    { time: '10:00', up: 120, down: 450 },
    { time: '10:10', up: 280, down: 890 },
    { time: '10:20', up: 190, down: 620 },
    { time: '10:30', up: 410, down: 1250 },
    { time: '10:40', up: 350, down: 980 },
    { time: '10:50', up: 580, down: 1890 },
    { time: '11:00', up: 310, down: 1420 },
    { time: '11:10', up: 640, down: 2150 },
  ];

  const maxVal = Math.max(...timelinePoints.map((p) => p.down));
  const chartHeight = 140;
  const chartWidth = 560;

  const pointsDown = timelinePoints
    .map(
      (p, i) =>
        `${(i / (timelinePoints.length - 1)) * chartWidth},${
          chartHeight - (p.down / maxVal) * (chartHeight - 20)
        }`
    )
    .join(' ');

  const pointsUp = timelinePoints
    .map(
      (p, i) =>
        `${(i / (timelinePoints.length - 1)) * chartWidth},${
          chartHeight - (p.up / maxVal) * (chartHeight - 20)
        }`
    )
    .join(' ');

  const areaDown = `0,${chartHeight} ${pointsDown} ${chartWidth},${chartHeight}`;

  return (
    <div className="space-y-6">
      {/* Top Banner & KPI Stat Strip */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* KPI 1: Active Agents */}
        <div className="bg-slate-900 border border-slate-800 rounded p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>ISOLIERTE AGENTEN</span>
            <Cpu className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="my-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-white tabular-nums">
              {agents.length}
            </span>
            <span className="text-xs text-emerald-400 font-mono">
              {activeCount} Aktiv · {isolatedCount} Isoliert
            </span>
          </div>
          <div className="flex items-center gap-1.5 text-[11px] text-slate-400 border-t border-slate-800/80 pt-2 font-mono">
            <span>AppContainer Sandbox</span>
            <span className="text-slate-600">/</span>
            <span>Job Limits: 64 Procs</span>
          </div>
        </div>

        {/* KPI 2: Total Network Activity */}
        <div className="bg-slate-900 border border-slate-800 rounded p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>NETZWERK-DATEN (RELAY)</span>
            <Network className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="my-2 flex items-baseline gap-3">
            <div className="flex items-center gap-1 text-emerald-400 font-mono text-lg font-bold">
              <ArrowDownRight className="w-4 h-4" />
              <span className="tabular-nums">{formatBytes(totalBytesDown)}</span>
            </div>
            <div className="flex items-center gap-1 text-cyan-400 font-mono text-sm">
              <ArrowUpRight className="w-3.5 h-3.5" />
              <span className="tabular-nums">{formatBytes(totalBytesUp)}</span>
            </div>
          </div>
          <div className="flex items-center gap-1.5 text-[11px] text-slate-400 border-t border-slate-800/80 pt-2 font-mono">
            <span>Opaque Relay (E-3)</span>
            <span className="text-slate-600">·</span>
            <span className="text-cyan-400 tabular-nums">{totalActiveSockets} Sockets</span>
          </div>
        </div>

        {/* KPI 3: Security Violations Blocked */}
        <div className="bg-slate-900 border border-slate-800 rounded p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono">
            <span>ABGEWEHRTE VERSTÖSSE</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="my-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-rose-400 tabular-nums">
              {securityViolations.length}
            </span>
            <span className="text-xs text-rose-300 font-mono">
              Kernel &amp; Gate Blocks
            </span>
          </div>
          <div className="flex items-center gap-1.5 text-[11px] text-slate-400 border-t border-slate-800/80 pt-2 font-mono">
            <span>T1–T10 + DNS-Rebind</span>
            <span className="text-slate-600">·</span>
            <span>Fail-Closed</span>
          </div>
        </div>

        {/* KPI 4: HITL Choke Point */}
        <div
          onClick={onOpenHitl}
          className="bg-slate-900 border border-amber-600/40 rounded p-4 flex flex-col justify-between cursor-pointer hover:border-amber-500 transition-colors"
        >
          <div className="flex items-center justify-between text-amber-300 text-xs font-mono">
            <span>HITL CHOKE POINT</span>
            <Activity className="w-4 h-4 text-amber-400" />
          </div>
          <div className="my-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-amber-300 tabular-nums">
              {pendingCount}
            </span>
            <span className="text-xs text-amber-200/80 font-mono">
              Anfragen warten auf Prüfung
            </span>
          </div>
          <div className="flex items-center justify-between text-[11px] text-amber-300/80 border-t border-slate-800/80 pt-2 font-mono">
            <span>Klicke zum Öffnen</span>
            <ExternalLink className="w-3 h-3" />
          </div>
        </div>
      </div>

      {/* Main Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Network Bandwidth Chart (SVG Area Chart) */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wide">
                Echtzeit-Netzwerkdurchsatz (Relay Traffic)
              </h3>
              <p className="text-xs text-slate-400">
                Opaque Byte-Relay Datenpfad (E-3) ohne In-Band HTTP Parsing
              </p>
            </div>
            <div className="flex items-center gap-3 text-xs font-mono">
              <span className="flex items-center gap-1 text-emerald-400">
                <span className="w-2.5 h-2.5 rounded-sm bg-emerald-500 inline-block"></span>
                <span>Download (KB/s)</span>
              </span>
              <span className="flex items-center gap-1 text-cyan-400">
                <span className="w-2.5 h-2.5 rounded-sm bg-cyan-400 inline-block"></span>
                <span>Upload (KB/s)</span>
              </span>
            </div>
          </div>

          {/* Responsive SVG Chart */}
          <div className="h-44 w-full bg-slate-950/60 rounded border border-slate-800/80 p-2 relative flex flex-col justify-end">
            <svg
              viewBox={`0 0 ${chartWidth} ${chartHeight}`}
              className="w-full h-full overflow-visible"
              preserveAspectRatio="none"
            >
              <defs>
                <linearGradient id="gradDown" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#10b981" stopOpacity="0.3" />
                  <stop offset="100%" stopColor="#10b981" stopOpacity="0.0" />
                </linearGradient>
              </defs>

              {/* Grid Lines */}
              <line x1="0" y1="35" x2={chartWidth} y2="35" stroke="#1e293b" strokeDasharray="3 3" />
              <line x1="0" y1="70" x2={chartWidth} y2="70" stroke="#1e293b" strokeDasharray="3 3" />
              <line x1="0" y1="105" x2={chartWidth} y2="105" stroke="#1e293b" strokeDasharray="3 3" />

              {/* Down Area */}
              <polygon points={areaDown} fill="url(#gradDown)" />

              {/* Lines */}
              <polyline
                fill="none"
                stroke="#10b981"
                strokeWidth="2"
                strokeLinecap="round"
                points={pointsDown}
              />
              <polyline
                fill="none"
                stroke="#38bdf8"
                strokeWidth="2"
                strokeLinecap="round"
                points={pointsUp}
              />
            </svg>

            {/* X Axis Timestamps */}
            <div className="flex justify-between text-[10px] text-slate-500 font-mono pt-1">
              {timelinePoints.map((p, idx) => (
                <span key={idx}>{p.time}</span>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-3 gap-2 pt-1 text-xs font-mono text-slate-400">
            <div className="bg-slate-950/40 p-2 rounded border border-slate-800">
              <div className="text-[10px] text-slate-500">PEAK DURCHSATZ</div>
              <div className="text-white font-bold tabular-nums">2.15 MB/s</div>
            </div>
            <div className="bg-slate-950/40 p-2 rounded border border-slate-800">
              <div className="text-[10px] text-slate-500">SCHNITT LATENZ</div>
              <div className="text-emerald-400 font-bold tabular-nums">1.4 ms (Local Pipe)</div>
            </div>
            <div className="bg-slate-950/40 p-2 rounded border border-slate-800">
              <div className="text-[10px] text-slate-500">PARSER-OVERHEAD</div>
              <div className="text-cyan-400 font-bold tabular-nums">0.00 ms (Opaque)</div>
            </div>
          </div>
        </div>

        {/* Data Transfer by Agent (Proportional Bars) */}
        <div className="bg-slate-900 border border-slate-800 rounded p-5 space-y-4 flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wide">
              Datenaufkommen je Agent
            </h3>
            <p className="text-xs text-slate-400">
              Überwachte Quotas &amp; Bandbreitenlimits
            </p>
          </div>

          <div className="space-y-4">
            {agents.map((agent) => {
              const agentTotal = agent.bytesUp + agent.bytesDown;
              const maxQuota = agent.jobLimits.maxMemoryBytes;
              const percent = Math.min(100, Math.round((agentTotal / 10485760) * 100));

              return (
                <div key={agent.id} className="space-y-1.5">
                  <div className="flex justify-between text-xs font-mono">
                    <span className="text-white font-medium truncate max-w-[140px]">
                      {agent.name}
                    </span>
                    <span className="text-slate-400 tabular-nums">
                      {formatBytes(agentTotal)}
                    </span>
                  </div>

                  {/* Dual Bar (Up vs Down) */}
                  <div className="h-2 w-full bg-slate-950 rounded overflow-hidden flex">
                    <div
                      className="bg-cyan-500 h-full"
                      style={{
                        width: `${agentTotal > 0 ? (agent.bytesUp / agentTotal) * 100 : 0}%`,
                      }}
                      title={`Upload: ${formatBytes(agent.bytesUp)}`}
                    ></div>
                    <div
                      className="bg-emerald-500 h-full"
                      style={{
                        width: `${agentTotal > 0 ? (agent.bytesDown / agentTotal) * 100 : 0}%`,
                      }}
                      title={`Download: ${formatBytes(agent.bytesDown)}`}
                    ></div>
                  </div>

                  <div className="flex justify-between text-[10px] text-slate-500 font-mono">
                    <span>PID: {agent.pid}</span>
                    <span>{agent.activeSockets} aktiver Socket</span>
                  </div>
                </div>
              );
            })}
          </div>

          <div className="border-t border-slate-800 pt-3 text-[11px] font-mono text-slate-400 flex items-center justify-between">
            <span className="flex items-center gap-1.5 text-emerald-400">
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>Alle Quotas im Limit</span>
            </span>
            <span className="text-slate-500">Max 256MB / Job</span>
          </div>
        </div>
      </div>

      {/* Active Agents Monitoring Table */}
      <div className="bg-slate-900 border border-slate-800 rounded overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-4">
          <div>
            <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wide">
              Echtzeit-Agenten-Gefängnis (AppContainer &amp; Job Objects)
            </h3>
            <p className="text-xs text-slate-400">
              Laufende Prozesse, Ephemere PackageSIDs und Genotyp-Status
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400 font-mono">Status:</span>
            <div className="flex items-center gap-1.5 text-xs font-mono text-slate-300">
              <span className="inline-block w-2 h-2 rounded-full bg-emerald-400"></span>
              <span>Aktiv</span>
              <span className="text-slate-600">·</span>
              <span className="inline-block w-2 h-2 rounded-full bg-amber-400"></span>
              <span>Gedrosselt</span>
              <span className="text-slate-600">·</span>
              <span className="inline-block w-2 h-2 rounded-full bg-rose-400"></span>
              <span>Apoptotisch</span>
            </div>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/60 text-slate-400 uppercase text-[11px]">
                <th className="py-3 px-4 font-semibold">Agent &amp; ID</th>
                <th className="py-3 px-4 font-semibold">Kernel PID</th>
                <th className="py-3 px-4 font-semibold">Genotyp &amp; Package-SID (E-1)</th>
                <th className="py-3 px-4 font-semibold">Status</th>
                <th className="py-3 px-4 font-semibold text-right">Sockets</th>
                <th className="py-3 px-4 font-semibold text-right">Relay Traffic</th>
                <th className="py-3 px-4 font-semibold">Job Limits</th>
                <th className="py-3 px-4 font-semibold text-right">Aktionen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {agents.map((agent) => (
                <tr key={agent.id} className="hover:bg-slate-800/40 transition-colors">
                  <td className="py-3 px-4">
                    <div className="font-semibold text-white">{agent.name}</div>
                    <div className="text-[10px] text-slate-400">{agent.id}</div>
                  </td>

                  <td className="py-3 px-4 font-bold text-cyan-300 tabular-nums">
                    {agent.pid}
                  </td>

                  <td className="py-3 px-4">
                    <div className="text-slate-300 truncate max-w-[200px]" title={agent.packageSid}>
                      {agent.packageSid}
                    </div>
                    <div className="text-[10px] text-slate-500">
                      Genotyp v{agent.genotypeVersion} · Nonce: {agent.ephemeralNonce}
                    </div>
                  </td>

                  <td className="py-3 px-4">
                    {agent.status === 'active' && (
                      <span className="text-emerald-400 font-semibold flex items-center gap-1">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                        Aktiv
                      </span>
                    )}
                    {agent.status === 'isolated' && (
                      <span className="text-slate-400 font-semibold flex items-center gap-1">
                        <span className="w-1.5 h-1.5 rounded-full bg-slate-400"></span>
                        Isoliert
                      </span>
                    )}
                    {agent.status === 'choked' && (
                      <span className="text-amber-400 font-semibold flex items-center gap-1">
                        <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
                        Entropie-Tax (E-2)
                      </span>
                    )}
                    {agent.status === 'apoptotic' && (
                      <span className="text-rose-400 font-semibold flex items-center gap-1">
                        <span className="w-1.5 h-1.5 rounded-full bg-rose-400"></span>
                        Apoptose (E-4)
                      </span>
                    )}
                  </td>

                  <td className="py-3 px-4 text-right tabular-nums text-slate-300 font-semibold">
                    {agent.activeSockets}
                  </td>

                  <td className="py-3 px-4 text-right tabular-nums">
                    <div className="text-emerald-400 font-semibold">
                      ↓ {formatBytes(agent.bytesDown)}
                    </div>
                    <div className="text-cyan-400 text-[10px]">
                      ↑ {formatBytes(agent.bytesUp)}
                    </div>
                  </td>

                  <td className="py-3 px-4">
                    <div className="text-slate-300 text-[11px]">
                      Procs: max {agent.jobLimits.maxActiveProcesses}
                    </div>
                    <div className="text-amber-400/90 text-[10px]">
                      Köder: .env + id_rsa ({agent.canaryBaits?.length || 2} aktiv)
                    </div>
                  </td>

                  <td className="py-3 px-4 text-right">
                    <div className="flex items-center justify-end gap-1.5">
                      {onTriggerCanaryAccess && (
                        <button
                          onClick={() => onTriggerCanaryAccess(agent.id, '.env')}
                          className="px-2 py-1 text-[11px] bg-amber-950/40 hover:bg-amber-900/60 text-amber-300 rounded border border-amber-800/60 transition-colors cursor-pointer"
                          title="Simuliert unerlaubten Lesezugriff auf Canary .env Datei -> Löst Notfall-Apoptose aus"
                        >
                          Bait Test
                        </button>
                      )}

                      <button
                        onClick={() => onRotateGenotype(agent.id)}
                        className="px-2 py-1 text-[11px] bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 transition-colors cursor-pointer"
                        title="E-1: Ephemere SID & Pipe rotieren"
                      >
                        Rotate
                      </button>

                      <button
                        onClick={() => onTriggerApoptosis(agent.id)}
                        className="px-2 py-1 text-[11px] bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 rounded border border-rose-800/60 transition-colors cursor-pointer"
                        title="E-4: Job Object hart terminieren"
                      >
                        Apoptose
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Security Events & Violations Live Feed */}
      <div className="bg-slate-900 border border-slate-800 rounded p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wide">
              Sicherheitsereignisse &amp; Regelverstöße (Live Audit Feed)
            </h3>
            <p className="text-xs text-slate-400">
              Kryptografisch gesicherte HMAC-SHA256 Ereigniskette
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400 font-mono">Filter:</span>
            <select
              value={eventFilter}
              onChange={(e) => setEventFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 rounded px-2.5 py-1"
            >
              <option value="all">Alle Ereignisse</option>
              <option value="violations">Nur Verstöße / Blocks</option>
              <option value="hitl">Nur HITL-Entscheidungen</option>
            </select>
          </div>
        </div>

        <div className="divide-y divide-slate-800/80 border border-slate-800 rounded bg-slate-950/40 max-h-80 overflow-y-auto">
          {auditLog
            .slice()
            .reverse()
            .filter((entry) => {
              if (eventFilter === 'violations') {
                return [
                  'DNS_REBINDING_BLOCKED',
                  'LOWBOX_ACL_VIOLATION',
                  'JOB_LIMIT_ENFORCED',
                  'APOPTOSIS_EXECUTED',
                  'HITL_DECISION_DENIED',
                ].includes(entry.eventType);
              }
              if (eventFilter === 'hitl') {
                return entry.eventType.startsWith('HITL_');
              }
              return true;
            })
            .map((entry) => {
              const isViolation = [
                'DNS_REBINDING_BLOCKED',
                'LOWBOX_ACL_VIOLATION',
                'JOB_LIMIT_ENFORCED',
                'APOPTOSIS_EXECUTED',
                'HITL_DECISION_DENIED',
              ].includes(entry.eventType);

              return (
                <div key={entry.index} className="p-3 flex items-start gap-3 text-xs font-mono">
                  <div className="mt-0.5">
                    {isViolation ? (
                      <ShieldAlert className="w-4 h-4 text-rose-400" />
                    ) : entry.eventType.startsWith('HITL_') ? (
                      <Activity className="w-4 h-4 text-amber-400" />
                    ) : (
                      <ShieldCheck className="w-4 h-4 text-emerald-400" />
                    )}
                  </div>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between flex-wrap gap-2">
                      <span
                        className={`font-bold ${
                          isViolation ? 'text-rose-400' : 'text-slate-200'
                        }`}
                      >
                        {entry.eventType}
                      </span>
                      <span className="text-[10px] text-slate-500 tabular-nums">
                        {new Date(entry.timestamp).toLocaleTimeString()}
                      </span>
                    </div>

                    <div className="text-slate-400 text-[11px] mt-0.5 truncate">
                      Agent: <strong className="text-cyan-300">{entry.agentId}</strong> · Details:{' '}
                      {JSON.stringify(entry.details)}
                    </div>
                  </div>

                  <div className="text-[10px] text-slate-600 whitespace-nowrap self-center hidden sm:block">
                    HMAC: {entry.hmac.substring(0, 10)}...
                  </div>
                </div>
              );
            })}
        </div>
      </div>
    </div>
  );
};
