/**
 * C.O.R.D.O.N. — Gemeinsame Typdefinitionen für das Security Workbench Dashboard.
 * Diese Typen bilden die Simulations-/Visualisierungsmodelle ab, die von der
 * SimulationEngine und den Views verwendet werden.
 */

// ---------------------------------------------------------------------------
// Agenten & Sandbox
// ---------------------------------------------------------------------------

export type AgentStatus = 'active' | 'isolated' | 'choked' | 'apoptotic';

export interface JobUiLimits {
  handles: boolean;
  readClipboard: boolean;
  writeClipboard: boolean;
  systemParameters: boolean;
  displaySettings: boolean;
  globalAtoms: boolean;
  desktopIsolation: boolean;
}

export interface JobLimits {
  killOnJobClose: boolean;
  breakawayOk: boolean;
  maxActiveProcesses: number;
  maxMemoryBytes: number;
  uiLimits: JobUiLimits;
}

export interface CanaryBaitFile {
  name: string;
  relativePath: string;
  fakeContent: string;
  trapType: string;
  accessCount: number;
  triggered: boolean;
  lastTriggeredAt?: number;
}

export interface AgentProfile {
  id: string;
  name: string;
  packageSid: string;
  ephemeralNonce: string;
  imagePath: string;
  pid: number;
  integrityLevel: string;
  isAppContainer: boolean;
  workspacePath: string;
  pipePath: string;
  status: AgentStatus;
  jobLimits: JobLimits;
  canaryBaits: CanaryBaitFile[];
  genotypeVersion: number;
  bytesUp: number;
  bytesDown: number;
  activeSockets: number;
  createdAt: number;
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

export interface AuditRecord {
  index: number;
  timestamp: string;
  eventType: string;
  agentId: string;
  details: Record<string, any>;
  prevHmac: string;
  hmac: string;
  tpmSealed: boolean;
  isTampered?: boolean;
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

export interface ScopeTarget {
  host: string;
  ports: number[];
  allowedMethods?: string[];
}

export interface ScopePrincipal {
  agentIds: string[];
  imageRoots: string[];
}

export interface ScopeInspection {
  tls: 'passthrough' | 'intercept';
  requireHitlApproval: boolean;
}

export interface ScopeLimits {
  maxConcurrentConnections: number;
  maxBytesUp: number;
  maxBytesDown: number;
  sessionTtlSeconds: number;
}

export interface PolicyScope {
  id: string;
  description: string;
  principals: ScopePrincipal;
  targets: ScopeTarget[];
  inspection: ScopeInspection;
  limits: ScopeLimits;
}

export interface CordonPolicy {
  version: number;
  defaultVerdict: 'allow' | 'deny';
  requireHitlOnUnknownTargets: boolean;
  enforceDnsRebindingGuard: boolean;
  entropyTaxEnabled: boolean;
  learnModeEnabled: boolean;
  tpmHardwareAnchoring: boolean;
  scopes: PolicyScope[];
}

export interface DiscoveredPolicyCandidate {
  id: string;
  timestamp: number;
  agentId: string;
  targetHost: string;
  targetPort: number;
  method: string;
  frequency: number;
  status: 'discovered' | 'imported';
}

// ---------------------------------------------------------------------------
// HITL (Human-in-the-Loop)
// ---------------------------------------------------------------------------

export type ApprovalRequestStatus =
  | 'pending'
  | 'allowed_once'
  | 'always_allowed'
  | 'denied'
  | 'apoptotic';

export interface PendingApprovalRequest {
  id: string;
  timestamp: number;
  agentId: string;
  agentName: string;
  pid: number;
  packageSid: string;
  imagePath: string;
  targetHost: string;
  targetPort: number;
  method: string;
  path?: string;
  actionDescription: string;
  riskScore: number;
  riskFactors: string[];
  status: ApprovalRequestStatus;
  decisionTimestamp?: number;
  decisionBy?: string;
}

// ---------------------------------------------------------------------------
// Frame-Protokoll
// ---------------------------------------------------------------------------

export type FramePlane = 'control' | 'data';

export interface BinaryFrame {
  kind: number;
  flags: number;
  seq: number;
  length: number;
  headerJson: Record<string, any>;
  payload: string;
  rawHex: string;
  timestamp: number;
  plane: FramePlane;
}

/**
 * Bekannte Frame-Typen des Cordon-Pipe-Protokolls. Wird von einzelnen Views
 * zur semantischen Zuordnung referenziert.
 */
export const FrameKind = {
  Connect: 0x01,
  Data: 0x02,
  Ack: 0x03,
  Close: 0x04,
  Error: 0x05,
  TargetGateAuth: 0x06,
} as const;

// ---------------------------------------------------------------------------
// Threat Lab
// ---------------------------------------------------------------------------

export interface ThreatScenario {
  id: string;
  code: string;
  title: string;
  category: string;
  layer: string;
  description: string;
  attackVector: string;
  expectedResult: string;
  status: 'blocked' | 'running';
  log: string[];
}
