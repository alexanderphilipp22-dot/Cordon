import React, { useState, useEffect } from 'react';
import { simulationEngine } from './services/simulationEngine';
import {
  AgentProfile,
  AuditRecord,
  BinaryFrame,
  CordonPolicy,
  DiscoveredPolicyCandidate,
  PendingApprovalRequest,
  PolicyScope,
  ThreatScenario,
} from './types/cordon';
import { Header } from './components/Header';
import { DashboardView } from './components/DashboardView';
import { PolicyManagerView } from './components/PolicyManagerView';
import { HitlChokePointView } from './components/HitlChokePointView';
import { ProtocolInspectorView } from './components/ProtocolInspectorView';
import { ThreatLabView } from './components/ThreatLabView';
import { AuditLogView } from './components/AuditLogView';
import { CodebaseView } from './components/CodebaseView';
import { HumanApprovalModal } from './components/HumanApprovalModal';
import { NewRequestModal } from './components/NewRequestModal';

export default function App() {
  const [agents, setAgents] = useState<AgentProfile[]>(simulationEngine.getAgents());
  const [pendingRequests, setPendingRequests] = useState<PendingApprovalRequest[]>(
    simulationEngine.getPendingRequests()
  );
  const [discoveredCandidates, setDiscoveredCandidates] = useState<DiscoveredPolicyCandidate[]>(
    simulationEngine.getDiscoveredCandidates()
  );
  const [policy, setPolicy] = useState<CordonPolicy>(simulationEngine.getPolicy());
  const [frames, setFrames] = useState<BinaryFrame[]>(simulationEngine.getFrames());
  const [auditLog, setAuditLog] = useState<AuditRecord[]>(simulationEngine.getAuditLog());
  const [threatScenarios, setThreatScenarios] = useState<ThreatScenario[]>(
    simulationEngine.getThreatScenarios()
  );

  const [activeTab, setActiveTab] = useState<string>('dashboard');
  const [modalRequest, setModalRequest] = useState<PendingApprovalRequest | null>(null);
  const [isNewRequestModalOpen, setIsNewRequestModalOpen] = useState(false);

  // Subscribe to simulation state changes
  useEffect(() => {
    const unsubscribe = simulationEngine.subscribe(() => {
      setAgents(simulationEngine.getAgents());
      setPendingRequests(simulationEngine.getPendingRequests());
      setDiscoveredCandidates(simulationEngine.getDiscoveredCandidates());
      setPolicy(simulationEngine.getPolicy());
      setFrames(simulationEngine.getFrames());
      setAuditLog(simulationEngine.getAuditLog());
      setThreatScenarios(simulationEngine.getThreatScenarios());
    });
    return unsubscribe;
  }, []);

  const pendingCount = pendingRequests.filter((r) => r.status === 'pending').length;

  const handleDecision = async (
    requestId: string,
    decision: 'allow_once' | 'always_allow' | 'deny' | 'apoptosis'
  ) => {
    await simulationEngine.handleApprovalDecision(requestId, decision);
  };

  const handleInjectFrame = (kind: number, headerJson: Record<string, any>, payload: string) => {
    const newFrame = simulationEngine.createBinaryFrame(
      kind,
      0x00,
      frames.length + 101,
      headerJson,
      payload,
      kind === 0x02 ? 'data' : 'control'
    );
    setFrames((prev) => [newFrame, ...prev]);
  };

  const handleSimulateNewRequest = async (targetHost: string, targetPort: number, method: string) => {
    await simulationEngine.simulateNewAgentRequest(targetHost, targetPort, method);
    if (policy.learnModeEnabled) {
      setActiveTab('policies');
    } else {
      setActiveTab('hitl');
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col selection:bg-cyan-500 selection:text-slate-950 font-sans">
      {/* Universal Top Navigation Header */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        pendingCount={pendingCount}
        onOpenNewRequestModal={() => setIsNewRequestModalOpen(true)}
      />

      {/* Main Viewport Container (1440px max width desktop baseline) */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8">
        {activeTab === 'dashboard' && (
          <DashboardView
            agents={agents}
            auditLog={auditLog}
            pendingCount={pendingCount}
            isLearnModeActive={policy.learnModeEnabled}
            tpmActive={policy.tpmHardwareAnchoring}
            onRotateGenotype={(id) => simulationEngine.rotateAgentGenotype(id)}
            onTriggerApoptosis={(id) =>
              simulationEngine.triggerApoptosis(id, 'Manuelle Apoptose über Dashboard')
            }
            onTriggerCanaryAccess={(agentId, baitName) =>
              simulationEngine.triggerCanaryAccess(agentId, baitName)
            }
            onSelectAgent={(agent) => {
              setActiveTab('inspector');
            }}
            onOpenHitl={() => setActiveTab('hitl')}
          />
        )}

        {activeTab === 'policies' && (
          <PolicyManagerView
            policy={policy}
            discoveredCandidates={discoveredCandidates}
            onSavePolicy={(newPol) => simulationEngine.updatePolicy(newPol)}
            onAddScope={(scope) => simulationEngine.addScope(scope)}
            onUpdateScope={(scope) => simulationEngine.updateScope(scope)}
            onDeleteScope={(id) => simulationEngine.deleteScope(id)}
            onImportCandidate={(id) => simulationEngine.importCandidateAsPolicyScope(id)}
            onToggleLearnMode={(enabled) => simulationEngine.toggleLearnMode(enabled)}
          />
        )}

        {activeTab === 'hitl' && (
          <HitlChokePointView
            pendingRequests={pendingRequests}
            onDecision={handleDecision}
            onOpenNewRequestModal={() => setIsNewRequestModalOpen(true)}
          />
        )}

        {activeTab === 'inspector' && (
          <ProtocolInspectorView
            frames={frames}
            onInjectFrame={handleInjectFrame}
          />
        )}

        {activeTab === 'threatlab' && (
          <ThreatLabView
            scenarios={threatScenarios}
            onRunScenario={(id) => simulationEngine.runThreatScenario(id)}
          />
        )}

        {activeTab === 'audit' && (
          <AuditLogView
            auditLog={auditLog}
            onTamperRecord={(idx, reason) => simulationEngine.tamperAuditRecord(idx, reason)}
            onRestoreRecord={(idx) => simulationEngine.restoreAuditRecord(idx)}
          />
        )}

        {activeTab === 'codebase' && <CodebaseView />}
      </main>

      {/* Interactive Human Approval Modal */}
      <HumanApprovalModal
        request={modalRequest}
        onClose={() => setModalRequest(null)}
        onDecision={handleDecision}
      />

      {/* Modal to simulate custom agent connection request */}
      <NewRequestModal
        isOpen={isNewRequestModalOpen}
        onClose={() => setIsNewRequestModalOpen(false)}
        onSubmit={handleSimulateNewRequest}
      />

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/80 px-6 py-4 text-xs font-mono text-slate-500 flex flex-wrap items-center justify-between gap-4 mt-auto">
        <div className="flex items-center gap-3">
          <span className="text-slate-400 font-bold">C.O.R.D.O.N. Gateway 2.0</span>
          <span>·</span>
          <span>Kernel Enforcement: Windows AppContainer + WFP + Job Objects + Lowbox ACLs</span>
          <span>·</span>
          <span>Fail-Closed</span>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-emerald-400">TPM 2.0 Hardware-Anchored</span>
          <span>·</span>
          <span>Canary Bait Active</span>
        </div>
      </footer>
    </div>
  );
}
