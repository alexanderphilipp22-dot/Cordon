import React, { useState } from 'react';
import {
  CordonPolicy,
  DiscoveredPolicyCandidate,
  PolicyScope,
  ScopeTarget,
} from '../types/cordon';
import {
  AlertCircle,
  Check,
  CheckCircle2,
  Copy,
  Download,
  Edit2,
  FileCode,
  FileText,
  Lightbulb,
  Plus,
  Radio,
  Search,
  Shield,
  Trash2,
  Upload,
  X,
  Zap,
} from 'lucide-react';

interface PolicyManagerViewProps {
  policy: CordonPolicy;
  discoveredCandidates: DiscoveredPolicyCandidate[];
  onSavePolicy: (policy: CordonPolicy) => { valid: boolean; errors: string[] };
  onAddScope: (scope: PolicyScope) => { valid: boolean; error?: string };
  onUpdateScope: (scope: PolicyScope) => { valid: boolean; error?: string };
  onDeleteScope: (scopeId: string) => void;
  onImportCandidate: (candidateId: string) => void;
  onToggleLearnMode: (enabled: boolean) => void;
}

export const PolicyManagerView: React.FC<PolicyManagerViewProps> = ({
  policy,
  discoveredCandidates,
  onSavePolicy,
  onAddScope,
  onUpdateScope,
  onDeleteScope,
  onImportCandidate,
  onToggleLearnMode,
}) => {
  const [activeTab, setActiveTab] = useState<'visual' | 'json' | 'learn'>('visual');
  const [jsonText, setJsonText] = useState(JSON.stringify(policy, null, 2));
  const [jsonErrors, setJsonErrors] = useState<string[]>([]);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [editingScope, setEditingScope] = useState<PolicyScope | null>(null);
  const [isCreatingNew, setIsCreatingNew] = useState(false);
  const [scopeSearch, setScopeSearch] = useState('');

  // Form State for Scope Editor
  const [formScopeId, setFormScopeId] = useState('');
  const [formDescription, setFormDescription] = useState('');
  const [formAgentIds, setFormAgentIds] = useState('research-alpha');
  const [formImageRoots, setFormImageRoots] = useState('C:\\Agents\\research\\');
  const [formTargets, setFormTargets] = useState<ScopeTarget[]>([
    { host: 'api.github.com', ports: [443], allowedMethods: ['GET', 'POST'] },
  ]);
  const [formTlsMode, setFormTlsMode] = useState<'passthrough' | 'intercept'>('passthrough');
  const [formRequireHitl, setFormRequireHitl] = useState(false);
  const [formMaxConns, setFormMaxConns] = useState(16);
  const [formMaxBytesUp, setFormMaxBytesUp] = useState(67108864);
  const [formMaxBytesDown, setFormMaxBytesDown] = useState(268435456);
  const [formTtl, setFormTtl] = useState(3600);
  const [formError, setFormError] = useState<string | null>(null);

  const openCreateScope = () => {
    setIsCreatingNew(true);
    setEditingScope(null);
    setFormScopeId(`custom-scope-${policy.scopes.length + 1}`);
    setFormDescription('Erlaubt definierte Ziel-Hosts');
    setFormAgentIds('*');
    setFormImageRoots('C:\\Agents\\');
    setFormTargets([{ host: 'api.example.com', ports: [443], allowedMethods: ['GET'] }]);
    setFormTlsMode('passthrough');
    setFormRequireHitl(false);
    setFormMaxConns(16);
    setFormMaxBytesUp(67108864);
    setFormMaxBytesDown(268435456);
    setFormTtl(3600);
    setFormError(null);
  };

  const openEditScope = (scope: PolicyScope) => {
    setIsCreatingNew(false);
    setEditingScope(scope);
    setFormScopeId(scope.id);
    setFormDescription(scope.description);
    setFormAgentIds(scope.principals.agentIds.join(', '));
    setFormImageRoots(scope.principals.imageRoots.join(', '));
    setFormTargets(JSON.parse(JSON.stringify(scope.targets)));
    setFormTlsMode(scope.inspection.tls);
    setFormRequireHitl(scope.inspection.requireHitlApproval || false);
    setFormMaxConns(scope.limits.maxConcurrentConnections);
    setFormMaxBytesUp(scope.limits.maxBytesUp);
    setFormMaxBytesDown(scope.limits.maxBytesDown);
    setFormTtl(scope.limits.sessionTtlSeconds);
    setFormError(null);
  };

  const handleSaveScopeForm = (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);

    if (!formScopeId.trim()) {
      setFormError('Scope ID darf nicht leer sein.');
      return;
    }

    if (formTargets.length === 0) {
      setFormError('Mindestens ein Ziel (Host/Port) erforderlich.');
      return;
    }

    const newScope: PolicyScope = {
      id: formScopeId.trim(),
      description: formDescription.trim(),
      principals: {
        agentIds: formAgentIds.split(',').map((s) => s.trim()).filter(Boolean),
        imageRoots: formImageRoots.split(',').map((s) => s.trim()).filter(Boolean),
      },
      targets: formTargets,
      inspection: {
        tls: formTlsMode,
        requireHitlApproval: formRequireHitl,
      },
      limits: {
        maxConcurrentConnections: formMaxConns,
        maxBytesUp: formMaxBytesUp,
        maxBytesDown: formMaxBytesDown,
        sessionTtlSeconds: formTtl,
      },
    };

    let result;
    if (isCreatingNew) {
      result = onAddScope(newScope);
    } else {
      result = onUpdateScope(newScope);
    }

    if (!result.valid) {
      setFormError(result.error || 'Fehler beim Speichern des Scopes.');
    } else {
      setEditingScope(null);
      setIsCreatingNew(false);
      setJsonText(JSON.stringify(policy, null, 2));
    }
  };

  const handleJsonApply = () => {
    try {
      const parsed = JSON.parse(jsonText) as CordonPolicy;
      const res = onSavePolicy(parsed);
      if (res.valid) {
        setJsonErrors([]);
        setSaveSuccess(true);
        setTimeout(() => setSaveSuccess(false), 2000);
      } else {
        setJsonErrors(res.errors);
      }
    } catch (e: any) {
      setJsonErrors([`Syntax-Fehler im JSON: ${e.message}`]);
    }
  };

  const handleExportJson = () => {
    const blob = new Blob([JSON.stringify(policy, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'cordon-policy.json';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const filteredScopes = policy.scopes.filter(
    (s) =>
      s.id.toLowerCase().includes(scopeSearch.toLowerCase()) ||
      s.description.toLowerCase().includes(scopeSearch.toLowerCase()) ||
      s.targets.some((t) => t.host.toLowerCase().includes(scopeSearch.toLowerCase()))
  );

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded p-6 flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs uppercase tracking-wider">
            <Shield className="w-4 h-4" />
            <span>Policy Studio &amp; Scope-Konfiguration</span>
          </div>
          <h2 className="text-xl font-bold text-white font-mono mt-1">
            Cordon Richtlinien- und Scope-Management
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-3xl">
            Definiere feingranulare Erlaubnisbereiche (Scopes) für Agenten-Identitäten, Image-Pfade,
            Ziel-Domains, Port-Bereiche und Inspektionsregeln. Unterstützt statische Scopes,
            visuelle Bearbeitung, Schema-Validierung und automatisches Lernen via Learn-Mode.
          </p>
        </div>

        {/* Global Controls */}
        <div className="flex items-center gap-3">
          {/* Learn Mode Toggle */}
          <div className="flex items-center gap-2 bg-slate-950 px-3 py-1.5 rounded border border-slate-800 font-mono text-xs">
            <span className="text-slate-400">Learn-Mode:</span>
            <button
              onClick={() => onToggleLearnMode(!policy.learnModeEnabled)}
              className={`px-2 py-0.5 rounded font-bold transition-colors cursor-pointer ${
                policy.learnModeEnabled
                  ? 'bg-amber-500 text-slate-950 shadow-sm'
                  : 'bg-slate-800 text-slate-400 hover:text-white'
              }`}
            >
              {policy.learnModeEnabled ? 'AKTIV (--learn-mode)' : 'INAKTIV'}
            </button>
          </div>

          <button
            onClick={openCreateScope}
            className="px-3.5 py-1.5 bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs font-mono rounded flex items-center gap-1.5 transition-colors cursor-pointer shadow-sm shadow-cyan-950"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Scope erstellen</span>
          </button>
        </div>
      </div>

      {/* Mode Navigation Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
        <button
          onClick={() => setActiveTab('visual')}
          className={`px-4 py-1.5 text-xs font-mono rounded transition-colors flex items-center gap-1.5 cursor-pointer ${
            activeTab === 'visual'
              ? 'bg-slate-800 text-white font-bold border border-slate-700'
              : 'text-slate-400 hover:text-white'
          }`}
        >
          <Shield className="w-3.5 h-3.5 text-cyan-400" />
          <span>Visuelle Scopes ({policy.scopes.length})</span>
        </button>

        <button
          onClick={() => {
            setActiveTab('json');
            setJsonText(JSON.stringify(policy, null, 2));
          }}
          className={`px-4 py-1.5 text-xs font-mono rounded transition-colors flex items-center gap-1.5 cursor-pointer ${
            activeTab === 'json'
              ? 'bg-slate-800 text-white font-bold border border-slate-700'
              : 'text-slate-400 hover:text-white'
          }`}
        >
          <FileCode className="w-3.5 h-3.5 text-amber-400" />
          <span>JSON Policy Editor &amp; Schema</span>
        </button>

        <button
          onClick={() => setActiveTab('learn')}
          className={`px-4 py-1.5 text-xs font-mono rounded transition-colors flex items-center gap-1.5 cursor-pointer ${
            activeTab === 'learn'
              ? 'bg-slate-800 text-white font-bold border border-slate-700'
              : 'text-slate-400 hover:text-white'
          }`}
        >
          <Lightbulb className="w-3.5 h-3.5 text-yellow-400" />
          <span>Learn-Mode Kandidaten ({discoveredCandidates.length})</span>
        </button>
      </div>

      {/* TAB 1: VISUAL SCOPE LIST */}
      {activeTab === 'visual' && (
        <div className="space-y-4">
          {/* Search bar */}
          <div className="flex items-center justify-between gap-4">
            <div className="relative flex-1 max-w-md">
              <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Scopes durchsuchen (ID, Host, Beschreibung)..."
                value={scopeSearch}
                onChange={(e) => setScopeSearch(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded pl-9 pr-4 py-1.5 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
              />
            </div>
            <span className="text-xs font-mono text-slate-500">
              Standard-Urteil: <strong className="text-rose-400">{policy.defaultVerdict.toUpperCase()}</strong> (Fail-Closed)
            </span>
          </div>

          {/* Scopes Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filteredScopes.map((scope) => (
              <div
                key={scope.id}
                className="bg-slate-900 border border-slate-800 rounded p-5 space-y-4 flex flex-col justify-between hover:border-slate-700 transition-colors"
              >
                <div>
                  <div className="flex items-start justify-between gap-2 border-b border-slate-800 pb-3">
                    <div>
                      <span className="text-sm font-bold font-mono text-cyan-300">
                        {scope.id}
                      </span>
                      <p className="text-xs text-slate-400 mt-0.5">{scope.description}</p>
                    </div>

                    <div className="flex items-center gap-1.5">
                      <button
                        onClick={() => openEditScope(scope)}
                        className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 transition-colors cursor-pointer"
                        title="Scope bearbeiten"
                      >
                        <Edit2 className="w-3.5 h-3.5" />
                      </button>

                      <button
                        onClick={() => onDeleteScope(scope.id)}
                        className="p-1.5 bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 rounded border border-rose-800/60 transition-colors cursor-pointer"
                        title="Scope löschen"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>

                  {/* Principals Section */}
                  <div className="mt-3 space-y-1 text-xs font-mono">
                    <span className="text-slate-500 text-[10px] uppercase block">
                      Autorisierte Principals:
                    </span>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-slate-400">Agent IDs:</span>
                      {scope.principals.agentIds.map((a) => (
                        <span key={a} className="bg-slate-950 text-cyan-300 px-2 py-0.5 rounded border border-slate-800">
                          {a}
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Target Endpoints */}
                  <div className="mt-3 space-y-1.5 text-xs font-mono">
                    <span className="text-slate-500 text-[10px] uppercase block">
                      Erlaubte Ziele ({scope.targets.length}):
                    </span>
                    <div className="space-y-1">
                      {scope.targets.map((t, idx) => (
                        <div
                          key={idx}
                          className="bg-slate-950 p-2 rounded border border-slate-800 flex items-center justify-between"
                        >
                          <div className="flex items-center gap-2">
                            <span className="text-emerald-400 font-bold">{t.host}</span>
                            <span className="text-slate-500">Port:</span>
                            <span className="text-slate-300 tabular-nums">
                              {t.ports.join(', ')}
                            </span>
                          </div>
                          {t.allowedMethods && (
                            <span className="text-[10px] text-cyan-400 bg-cyan-950/60 border border-cyan-800/80 px-1.5 py-0.5 rounded">
                              {t.allowedMethods.join(' / ')}
                            </span>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Scope Limits Footer */}
                <div className="pt-3 border-t border-slate-800/80 text-[11px] font-mono text-slate-500 flex items-center justify-between">
                  <span>TLS: {scope.inspection.tls}</span>
                  <span>Conns: max {scope.limits.maxConcurrentConnections}</span>
                  <span>TTL: {scope.limits.sessionTtlSeconds}s</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 2: JSON POLICY EDITOR */}
      {activeTab === 'json' && (
        <div className="bg-slate-900 border border-slate-800 rounded p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-white font-mono uppercase">
                Roh-JSON Richtlinien-Editor mit Schema-Validierung
              </h3>
              <p className="text-xs text-slate-400">
                Passe die globale <code className="text-cyan-300">cordon-policy.json</code> direkt an
              </p>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={handleExportJson}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono rounded border border-slate-700 flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Exportieren</span>
              </button>

              <button
                onClick={handleJsonApply}
                className="px-4 py-1.5 bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold text-xs font-mono rounded flex items-center gap-1.5 transition-colors cursor-pointer shadow-sm shadow-cyan-950"
              >
                <Check className="w-3.5 h-3.5" />
                <span>Validieren &amp; Anwenden</span>
              </button>
            </div>
          </div>

          {/* Validation Feedback */}
          {jsonErrors.length > 0 && (
            <div className="bg-rose-950/40 border border-rose-500/60 rounded p-3 text-xs font-mono text-rose-300 space-y-1">
              <div className="flex items-center gap-2 font-bold text-rose-200">
                <AlertCircle className="w-4 h-4" />
                <span>Validierungsfehler gefunden:</span>
              </div>
              <ul className="list-disc list-inside space-y-0.5">
                {jsonErrors.map((err, i) => (
                  <li key={i}>{err}</li>
                ))}
              </ul>
            </div>
          )}

          {saveSuccess && (
            <div className="bg-emerald-950/40 border border-emerald-500/60 rounded p-3 text-xs font-mono text-emerald-300 flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4" />
              <span>Richtlinie erfolgreich validiert und gespeichert!</span>
            </div>
          )}

          <textarea
            value={jsonText}
            onChange={(e) => setJsonText(e.target.value)}
            className="w-full h-96 bg-slate-950 border border-slate-800 rounded p-4 font-mono text-xs text-cyan-300 leading-relaxed focus:outline-none focus:border-cyan-500"
            spellCheck={false}
          />
        </div>
      )}

      {/* TAB 3: LEARN-MODE AUTO-DISCOVERY */}
      {activeTab === 'learn' && (
        <div className="bg-slate-900 border border-slate-800 rounded p-5 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-3">
            <div>
              <h3 className="text-sm font-bold text-white font-mono uppercase flex items-center gap-2">
                <Lightbulb className="w-4 h-4 text-yellow-400" />
                <span>Auto-Discovery: Gelernte Richtlinien-Kandidaten</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Im Learn-Mode aufgezeichnete Ziel-Hosts. Übernehme diese mit einem Klick in feste Scopes.
              </p>
            </div>

            <div className="text-xs font-mono text-amber-300 bg-amber-950/40 px-3 py-1 rounded border border-amber-500/30">
              Modus: {policy.learnModeEnabled ? 'AKTIV (--learn-mode)' : 'INAKTIV'}
            </div>
          </div>

          <div className="space-y-3">
            {discoveredCandidates.length === 0 ? (
              <div className="text-center py-10 text-slate-500 text-xs font-mono">
                Noch keine Endpoints entdeckt. Aktiviere den Learn-Mode und simuliere Anfragen!
              </div>
            ) : (
              discoveredCandidates.map((c) => (
                <div
                  key={c.id}
                  className="bg-slate-950 p-4 rounded border border-slate-800 flex flex-wrap items-center justify-between gap-4 text-xs font-mono"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-white">{c.targetHost}:{c.targetPort}</span>
                      <span className="text-[10px] bg-slate-800 text-slate-300 px-1.5 py-0.5 rounded">
                        {c.method}
                      </span>
                      <span className="text-slate-500 text-[10px]">
                        Aufrufe: {c.frequency}x
                      </span>
                    </div>
                    <div className="text-slate-400 text-[11px]">
                      Agent: <strong className="text-cyan-400">{c.agentId}</strong> · Erfasst: {new Date(c.timestamp).toLocaleTimeString()}
                    </div>
                  </div>

                  <div>
                    {c.status === 'imported' ? (
                      <span className="text-emerald-400 font-bold flex items-center gap-1.5">
                        <CheckCircle2 className="w-4 h-4" />
                        <span>In Richtlinie übernommen</span>
                      </span>
                    ) : (
                      <button
                        onClick={() => onImportCandidate(c.id)}
                        className="px-3 py-1.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold rounded flex items-center gap-1.5 cursor-pointer shadow-sm transition-colors"
                      >
                        <Plus className="w-3.5 h-3.5" />
                        <span>In Scope übernehmen</span>
                      </button>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* CREATE / EDIT SCOPE MODAL DIALOG */}
      {(isCreatingNew || editingScope) && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="bg-slate-900 border border-slate-700 rounded-lg max-w-2xl w-full shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
            <div className="bg-slate-950 px-6 py-4 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Shield className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-bold text-white font-mono uppercase">
                  {isCreatingNew ? 'Neuen Scope erstellen' : `Scope bearbeiten: ${editingScope?.id}`}
                </h3>
              </div>
              <button
                onClick={() => {
                  setEditingScope(null);
                  setIsCreatingNew(false);
                }}
                className="text-slate-400 hover:text-white transition-colors cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleSaveScopeForm} className="p-6 space-y-4 overflow-y-auto text-xs font-mono">
              {formError && (
                <div className="p-3 bg-rose-950/40 border border-rose-500/60 rounded text-rose-300">
                  {formError}
                </div>
              )}

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-slate-300 font-semibold block">Scope ID:</label>
                  <input
                    type="text"
                    value={formScopeId}
                    onChange={(e) => setFormScopeId(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-cyan-300 focus:outline-none focus:border-cyan-500"
                    required
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-slate-300 font-semibold block">Beschreibung:</label>
                  <input
                    type="text"
                    value={formDescription}
                    onChange={(e) => setFormDescription(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-slate-300 font-semibold block">Agent IDs (kommagetrennt oder *):</label>
                  <input
                    type="text"
                    value={formAgentIds}
                    onChange={(e) => setFormAgentIds(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-slate-300 font-semibold block">Image Roots (Verzeichnisse):</label>
                  <input
                    type="text"
                    value={formImageRoots}
                    onChange={(e) => setFormImageRoots(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>

              {/* Targets Section */}
              <div className="space-y-2 pt-2 border-t border-slate-800">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-200">Ziele (Targets &amp; Ports):</span>
                  <button
                    type="button"
                    onClick={() =>
                      setFormTargets([...formTargets, { host: 'new-target.com', ports: [443], allowedMethods: ['GET'] }])
                    }
                    className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-cyan-300 rounded text-[11px] cursor-pointer"
                  >
                    + Ziel hinzufügen
                  </button>
                </div>

                {formTargets.map((target, idx) => (
                  <div key={idx} className="p-3 bg-slate-950 border border-slate-800 rounded space-y-2">
                    <div className="grid grid-cols-3 gap-2">
                      <div className="col-span-2">
                        <label className="text-slate-500 text-[10px] block">Host / Domain (*.domain.org):</label>
                        <input
                          type="text"
                          value={target.host}
                          onChange={(e) => {
                            const updated = [...formTargets];
                            updated[idx].host = e.target.value;
                            setFormTargets(updated);
                          }}
                          className="w-full bg-slate-900 border border-slate-800 rounded p-1.5 text-white"
                        />
                      </div>
                      <div>
                        <label className="text-slate-500 text-[10px] block">Ports (z.B. 443, 8080):</label>
                        <input
                          type="text"
                          value={target.ports.join(', ')}
                          onChange={(e) => {
                            const updated = [...formTargets];
                            updated[idx].ports = e.target.value
                              .split(',')
                              .map((p) => parseInt(p.trim(), 10))
                              .filter((p) => !isNaN(p));
                            setFormTargets(updated);
                          }}
                          className="w-full bg-slate-900 border border-slate-800 rounded p-1.5 text-white"
                        />
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              {/* Inspection and Limits */}
              <div className="grid grid-cols-2 gap-3 pt-2 border-t border-slate-800">
                <div className="space-y-1">
                  <label className="text-slate-300 font-semibold block">TLS Modus:</label>
                  <select
                    value={formTlsMode}
                    onChange={(e) => setFormTlsMode(e.target.value as any)}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white"
                  >
                    <option value="passthrough">passthrough (Opaque Relay)</option>
                    <option value="intercept">intercept (TLS Inspection)</option>
                  </select>
                </div>

                <div className="space-y-1 flex items-center pt-5">
                  <label className="flex items-center gap-2 text-slate-300 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={formRequireHitl}
                      onChange={(e) => setFormRequireHitl(e.target.checked)}
                      className="rounded bg-slate-950 border-slate-800"
                    />
                    <span>Erzwinge Human-in-the-Loop Freigabe</span>
                  </label>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex justify-end gap-2 pt-4 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => {
                    setEditingScope(null);
                    setIsCreatingNew(false);
                  }}
                  className="px-4 py-2 bg-slate-800 text-slate-300 rounded hover:bg-slate-700 transition-colors cursor-pointer"
                >
                  Abbrechen
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-bold rounded transition-colors cursor-pointer shadow-sm shadow-cyan-950"
                >
                  Scope Speichern
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
