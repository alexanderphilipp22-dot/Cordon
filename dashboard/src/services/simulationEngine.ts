/**
 * Cordon Simulation Engine
 * Koordiniert Agenten-Lifecycle, HITL Choke Point, Binär-Frames,
 * Kernel-Erzwingungsregeln, Learn-Mode, Canary-Bait und TPM-Audit-Kette.
 */

import {
  AgentProfile,
  AuditRecord,
  BinaryFrame,
  CanaryBaitFile,
  CordonPolicy,
  DiscoveredPolicyCandidate,
  PendingApprovalRequest,
  PolicyScope,
  ThreatScenario,
} from '../types/cordon';
import { canonicalize, computeHmacSha256 } from './crypto';

export class SimulationEngine {
  private agents: AgentProfile[] = [];
  private pendingRequests: PendingApprovalRequest[] = [];
  private discoveredCandidates: DiscoveredPolicyCandidate[] = [];
  private frames: BinaryFrame[] = [];
  private auditLog: AuditRecord[] = [];
  private policy: CordonPolicy;
  private threatScenarios: ThreatScenario[] = [];
  private subscribers: (() => void)[] = [];
  private frameSequence = 100;
  private logSequence = 0;
  private lastHmac = '0000000000000000000000000000000000000000000000000000000000000000';

  constructor() {
    this.policy = {
      version: 1,
      defaultVerdict: 'deny',
      requireHitlOnUnknownTargets: true,
      enforceDnsRebindingGuard: true,
      entropyTaxEnabled: true,
      learnModeEnabled: false,
      tpmHardwareAnchoring: true,
      scopes: [
        {
          id: 'research-web',
          description: 'Dokumentations-Hosts und Wissensdatenbanken für Research-Agent',
          principals: {
            agentIds: ['research-alpha'],
            imageRoots: ['C:\\Agents\\research\\'],
          },
          targets: [
            { host: 'docs.python.org', ports: [443], allowedMethods: ['GET', 'HEAD'] },
            { host: '*.wikipedia.org', ports: [443], allowedMethods: ['GET', 'HEAD'] },
          ],
          inspection: {
            tls: 'passthrough',
            requireHitlApproval: false,
          },
          limits: {
            maxConcurrentConnections: 16,
            maxBytesUp: 67108864,
            maxBytesDown: 268435456,
            sessionTtlSeconds: 3600,
          },
        },
        {
          id: 'github-api-scope',
          description: 'Git-Repository-Zugriff für Entwickler- und Code-Synthese-Agenten',
          principals: {
            agentIds: ['coder-copilot'],
            imageRoots: ['C:\\Agents\\coder\\'],
          },
          targets: [
            { host: 'api.github.com', ports: [443], allowedMethods: ['GET', 'POST'] },
            { host: 'raw.githubusercontent.com', ports: [443], allowedMethods: ['GET'] },
          ],
          inspection: {
            tls: 'passthrough',
            requireHitlApproval: false,
          },
          limits: {
            maxConcurrentConnections: 8,
            maxBytesUp: 33554432,
            maxBytesDown: 134217728,
            sessionTtlSeconds: 1800,
          },
        },
      ],
    };

    this.initializeAgents();
    this.initializeThreatScenarios();
    this.initializeDefaultAuditLog();
    this.initializeDemoPendingRequests();
    this.initializeDemoDiscoveredCandidates();
    this.initializeDemoFrames();
  }

  public subscribe(cb: () => void): () => void {
    this.subscribers.push(cb);
    return () => {
      this.subscribers = this.subscribers.filter((s) => s !== cb);
    };
  }

  private notify() {
    for (const sub of this.subscribers) {
      sub();
    }
  }

  private createDefaultBaits(): CanaryBaitFile[] {
    return [
      {
        name: '.env',
        relativePath: '.env',
        fakeContent: 'OPENAI_API_KEY=sk-cordon-trap-bait-88910248109\nAWS_SECRET_ACCESS_KEY=cordon-canary-aws-key-99120',
        trapType: 'API_KEY',
        accessCount: 0,
        triggered: false,
      },
      {
        name: 'id_rsa_backup',
        relativePath: 'id_rsa_backup',
        fakeContent: '-----BEGIN OPENSSH PRIVATE KEY-----\nCANARY_TRAP_DO_NOT_READ\n-----END OPENSSH PRIVATE KEY-----',
        trapType: 'SSH_KEY',
        accessCount: 0,
        triggered: false,
      },
    ];
  }

  private initializeAgents() {
    this.agents = [
      {
        id: 'research-alpha',
        name: 'Research & Knowledge Agent',
        packageSid: 'S-1-15-2-CORDON-E91B3341',
        ephemeralNonce: 'e91b3341',
        imagePath: 'C:\\Agents\\research\\python.exe',
        pid: 4892,
        integrityLevel: 'Low',
        isAppContainer: true,
        workspacePath: 'C:\\CordonWorkspace\\research-alpha\\',
        pipePath: '\\\\.\\pipe\\CordonGateway\\research-alpha_e91b3341',
        status: 'active',
        jobLimits: {
          killOnJobClose: true,
          breakawayOk: false,
          maxActiveProcesses: 64,
          maxMemoryBytes: 268435456,
          uiLimits: {
            handles: true,
            readClipboard: true,
            writeClipboard: true,
            systemParameters: true,
            displaySettings: true,
            globalAtoms: true,
            desktopIsolation: true,
          },
        },
        canaryBaits: this.createDefaultBaits(),
        genotypeVersion: 3,
        bytesUp: 1420800,
        bytesDown: 8940300,
        activeSockets: 2,
        createdAt: Date.now() - 3600000,
      },
      {
        id: 'coder-copilot',
        name: 'Code Synthesizer & Tool Worker',
        packageSid: 'S-1-15-2-CORDON-A47C8902',
        ephemeralNonce: 'a47c8902',
        imagePath: 'C:\\Agents\\coder\\node.exe',
        pid: 6120,
        integrityLevel: 'Low',
        isAppContainer: true,
        workspacePath: 'C:\\CordonWorkspace\\coder-copilot\\',
        pipePath: '\\\\.\\pipe\\CordonGateway\\coder-copilot_a47c8902',
        status: 'isolated',
        jobLimits: {
          killOnJobClose: true,
          breakawayOk: false,
          maxActiveProcesses: 32,
          maxMemoryBytes: 536870912,
          uiLimits: {
            handles: true,
            readClipboard: true,
            writeClipboard: true,
            systemParameters: true,
            displaySettings: true,
            globalAtoms: true,
            desktopIsolation: true,
          },
        },
        canaryBaits: this.createDefaultBaits(),
        genotypeVersion: 1,
        bytesUp: 450200,
        bytesDown: 1204000,
        activeSockets: 1,
        createdAt: Date.now() - 1800000,
      },
      {
        id: 'external-tool-cli',
        name: 'Autonomous Web Crawler',
        packageSid: 'S-1-15-2-CORDON-F12D7791',
        ephemeralNonce: 'f12d7791',
        imagePath: 'C:\\Agents\\crawler\\agent.exe',
        pid: 8312,
        integrityLevel: 'Low',
        isAppContainer: true,
        workspacePath: 'C:\\CordonWorkspace\\external-tool-cli\\',
        pipePath: '\\\\.\\pipe\\CordonGateway\\external-tool-cli_f12d7791',
        status: 'choked',
        jobLimits: {
          killOnJobClose: true,
          breakawayOk: false,
          maxActiveProcesses: 16,
          maxMemoryBytes: 134217728,
          uiLimits: {
            handles: true,
            readClipboard: true,
            writeClipboard: true,
            systemParameters: true,
            displaySettings: true,
            globalAtoms: true,
            desktopIsolation: true,
          },
        },
        canaryBaits: this.createDefaultBaits(),
        genotypeVersion: 2,
        bytesUp: 98000,
        bytesDown: 340000,
        activeSockets: 0,
        createdAt: Date.now() - 900000,
      },
    ];
  }

  private async initializeDefaultAuditLog() {
    await this.appendAuditRecord('GATEWAY_STARTUP', 'SYSTEM', {
      service: 'Cordon Gateway Service 2.0',
      mode: 'StrictlyClosed',
      tpmProvider: 'Microsoft Platform Crypto Provider (TPM 2.0)',
      pcrRegisters: [0, 2, 7],
      canaryBaitActive: true,
      interAgentIsolation: 'Enforced via PackageSid DACL',
    });

    await this.appendAuditRecord('TPM_KEY_SEALED', 'SYSTEM', {
      keyName: 'Cordon_Audit_HMAC_MasterKey_TPM20',
      algorithm: 'HMAC-SHA256',
      hardwareBacked: true,
    });

    await this.appendAuditRecord('GENOTYPE_ROTATED', 'research-alpha', {
      genotype: 3,
      packageSid: 'S-1-15-2-CORDON-E91B3341',
      ephemeralNonce: 'e91b3341',
      pipePath: '\\\\.\\pipe\\CordonGateway\\research-alpha_e91b3341',
    });
  }

  private initializeDemoPendingRequests() {
    this.pendingRequests = [
      {
        id: 'REQ-901',
        timestamp: Date.now() - 14000,
        agentId: 'research-alpha',
        agentName: 'Research & Knowledge Agent',
        pid: 4892,
        packageSid: 'S-1-15-2-CORDON-E91B3341',
        imagePath: 'C:\\Agents\\research\\python.exe',
        targetHost: 'api.github.com',
        targetPort: 443,
        method: 'POST',
        path: '/repos/test-org/code-eval/issues',
        actionDescription: 'Agent versucht POST-Anfrage an GitHub API (nicht im statischen research-web Scope)',
        riskScore: 78,
        riskFactors: [
          'Zielhost api.github.com nicht in vordefinierter research-web Whitelist',
          'HTTP POST-Methode kann zur Datenexfiltration genutzt werden',
          'Erfordert explizite Genehmigung des Host-Entwicklers',
        ],
        status: 'pending',
      },
    ];
  }

  private initializeDemoDiscoveredCandidates() {
    this.discoveredCandidates = [
      {
        id: 'DISC-01',
        timestamp: Date.now() - 80000,
        agentId: 'research-alpha',
        targetHost: 'huggingface.co',
        targetPort: 443,
        method: 'GET',
        frequency: 4,
        status: 'discovered',
      },
      {
        id: 'DISC-02',
        timestamp: Date.now() - 40000,
        agentId: 'coder-copilot',
        targetHost: 'registry.npmjs.org',
        targetPort: 443,
        method: 'GET',
        frequency: 12,
        status: 'discovered',
      },
      {
        id: 'DISC-03',
        timestamp: Date.now() - 10000,
        agentId: 'coder-copilot',
        targetHost: 'cdn.jsdelivr.net',
        targetPort: 443,
        method: 'GET',
        frequency: 3,
        status: 'discovered',
      },
    ];
  }

  private initializeDemoFrames() {
    this.frames = [
      this.createBinaryFrame(
        0x01,
        0x00,
        101,
        {
          action: 'CONNECT',
          target: 'docs.python.org',
          port: 443,
          agentId: 'research-alpha',
          scope: 'research-web',
        },
        'SYN-REQ host=docs.python.org:443',
        'control'
      ),
      this.createBinaryFrame(
        0x06,
        0x01,
        102,
        {
          status: 'PERMITTED',
          gateToken: 'GATETOKEN_e91b3341_443',
          relayPort: 443,
          tlsMode: 'passthrough',
        },
        'AUTH-OK TargetGate session ready',
        'control'
      ),
      this.createBinaryFrame(
        0x02,
        0x00,
        103,
        {
          streamId: 1,
          direction: 'UPSTREAM',
          bytes: 1420,
        },
        'GET /3/library/asyncio.html HTTP/1.1\r\nHost: docs.python.org\r\n\r\n',
        'data'
      ),
    ];
  }

  private initializeThreatScenarios() {
    this.threatScenarios = [
      {
        id: 'T1',
        code: 'T1',
        title: 'Direkter TCP-Socket Verbindungsversuch',
        category: 'Netzwerk',
        layer: 'AppContainer',
        description: 'Agent versucht über Winsock (WSASocketW / connect) eine direkte Socket-Verbindung zu öffnen.',
        attackVector: 'socket(AF_INET, SOCK_STREAM, 0) -> connect("198.51.100.1:443")',
        expectedResult: 'Sofortige Kernel-Verweigerung mit 0x80070005 (E_ACCESSDENIED).',
        status: 'blocked',
        log: [
          '[T1-TEST] Agent versucht WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP)...',
          '[KERNEL] AppContainer Token besitzt KEINE Capability internetClient.',
          '[BLOCK] Rückgabe: 0x80070005 E_ACCESSDENIED. Kein Paket verlässt den Rechner.',
        ],
      },
      {
        id: 'T-CANARY',
        code: 'T-BAIT',
        title: 'Canary-Bait Diebstahlversuch (.env / Honeytrap)',
        category: 'Canary & Honeytrap',
        layer: 'Canary Bait Monitor',
        description: 'Kompromittierter Agent durchsucht das Workspace-Verzeichnis nach API-Keys und öffnet die Köder-Datei .env.',
        attackVector: 'open("C:\\\\CordonWorkspace\\\\research-alpha\\\\.env", "r")',
        expectedResult: 'FileSystemWatcher schlägt Alarm; sofortige harte Apoptose via Job Object.',
        status: 'blocked',
        log: [
          '[CANARY-TEST] Agent öffnet handle auf C:\\CordonWorkspace\\research-alpha\\.env...',
          '[HONEYTRAP] FileSystemWatcher detektiert LastAccess auf Köder-Datei.',
          '[ALARM] CANARY_HONEYPOT_TRIGGERED Event geloggt.',
          '[APOPTOSE] TerminateJobObject(hJob, 0xC0000409) ausgelöst. Alle Prozesse sofort beendet.',
        ],
      },
      {
        id: 'T-ISOLATION',
        code: 'T-MICRO',
        title: 'Inter-Agenten Cross-Pipe Infiltration',
        category: 'Micro-Segmentierung',
        layer: 'Named Pipe DACL',
        description: 'Agent A versucht die Named Pipe oder das Workspace-Verzeichnis von Agent B zu infiltrieren.',
        attackVector: 'CreateFileW("\\\\.\\pipe\\CordonGateway\\coder-copilot_a47c8902", GENERIC_READ|WRITE)',
        expectedResult: 'DACL verweigert Zugriff für fremde PackageSid (ERROR_ACCESS_DENIED 5).',
        status: 'blocked',
        log: [
          '[ISOLATION-TEST] Agent research-alpha versucht Pipe von coder-copilot zu öffnen...',
          '[KERNEL] AccessCheck() gegen Pipe DACL (Erlaubt nur S-1-15-2-CORDON-A47C8902).',
          '[BLOCK] Rückgabe: ERROR_ACCESS_DENIED (5). Inter-Agenten-Mikro-Segmentierung intakt.',
        ],
      },
      {
        id: 'T-TPM',
        code: 'T-TPM',
        title: 'Offline-Manipulation der Audit-Logs auf Festplatte',
        category: 'Audit',
        layer: 'HMAC / DPAPI',
        description: 'Angreifer modifiziert JSONL-Logs auf der Festplatte im Offline-Zustand.',
        attackVector: 'Edit cordon-audit.jsonl with custom payload without TPM 2.0 key',
        expectedResult: 'Hardware TPM 2.0 Signatur-Verifikation schlägt fehl; Integritätsbruch lokalisiert.',
        status: 'blocked',
        log: [
          '[TPM-TEST] Log-Eintrag auf Datenträger modifiziert...',
          '[TPM-CNG] NCryptOpenKey("Microsoft Platform Crypto Provider") verifiziert Hardware-HMAC...',
          '[ALARM] Hardware-Signature Mismatch! Modifikation auf Hardware-Ebene abgewiesen.',
        ],
      },
      {
        id: 'T6',
        code: 'T6',
        title: 'Ransomware / Dateisystem-Schreibversuch außerhalb Workspace',
        category: 'Dateisystem',
        layer: 'Lowbox ACL',
        description: 'Agent versucht Systemdateien auf C:\\Windows zu manipulieren.',
        attackVector: 'CreateFileW("C:\\\\Windows\\\\System32\\\\hosts", GENERIC_WRITE)',
        expectedResult: 'Lowbox ACL verweigert Schreibrechte außerhalb C:\\CordonWorkspace\\ (5).',
        status: 'blocked',
        log: [
          '[T6-TEST] Schreibversuch auf C:\\Windows\\System32...',
          '[LOWBOX-ACL] PackageSid besitzt nur Schreibrechte auf dediziertem Workspace.',
          '[BLOCK] Dateizugriff verweigert: ERROR_ACCESS_DENIED (5).',
        ],
      },
      {
        id: 'T8',
        code: 'T8',
        title: 'DNS-Rebinding & SSRF-Angriff (169.254.169.254 / Loopback)',
        category: 'SSRF & Rebinding',
        layer: 'TargetGate / Rebinding',
        description: 'Agent steuert Domain an, die auf Cloud-Metadaten oder 127.0.0.1 zeigt.',
        attackVector: 'Target="metadata.attacker.com" -> IP resolves to 169.254.169.254',
        expectedResult: 'TargetGate Post-Resolve Sanitizer blockiert Verbindung vor Socket-Connect.',
        status: 'blocked',
        log: [
          '[T8-TEST] Agent fordert Connect zu "attacker-rebind.net:80"...',
          '[RESOLVE] IP aufgelöst: 169.254.169.254 (Cloud Metadata).',
          '[BLOCK] Pre-Connect Sanitizer wirft Sicherheitsverletzung. Socket geschlossen.',
        ],
      },
    ];
  }

  // --- Public Getters ---
  public getAgents(): AgentProfile[] {
    return [...this.agents];
  }

  public getPendingRequests(): PendingApprovalRequest[] {
    return [...this.pendingRequests];
  }

  public getDiscoveredCandidates(): DiscoveredPolicyCandidate[] {
    return [...this.discoveredCandidates];
  }

  public getFrames(): BinaryFrame[] {
    return [...this.frames];
  }

  public getAuditLog(): AuditRecord[] {
    return [...this.auditLog];
  }

  public getPolicy(): CordonPolicy {
    return JSON.parse(JSON.stringify(this.policy));
  }

  public getThreatScenarios(): ThreatScenario[] {
    return [...this.threatScenarios];
  }

  // --- Learn-Mode & Canary-Bait Actions ---

  public toggleLearnMode(enabled: boolean): void {
    this.policy.learnModeEnabled = enabled;
    this.appendAuditRecord('LEARN_MODE_CANDIDATE_CAPTURED', 'SYSTEM', {
      action: enabled ? 'LEARN_MODE_ACTIVATED' : 'LEARN_MODE_DEACTIVATED',
      mode: enabled ? 'Auto-Discovery & Candidate Capture' : 'Strict Enforcement',
    });
    this.notify();
  }

  public async triggerCanaryAccess(agentId: string, baitName: string): Promise<void> {
    const agent = this.agents.find((a) => a.id === agentId);
    if (!agent) return;

    const bait = agent.canaryBaits.find((b) => b.name === baitName);
    if (bait) {
      bait.accessCount++;
      bait.triggered = true;
      bait.lastTriggeredAt = Date.now();
    }

    await this.appendAuditRecord('CANARY_HONEYPOT_TRIGGERED', agentId, {
      pid: agent.pid,
      baitFile: baitName,
      trapType: bait?.trapType || 'CREDENTIALS',
      verdict: 'CRITICAL: Agent attempted honeytrap credential exfiltration!',
    });

    // Sofortige harte Apoptose!
    await this.triggerApoptosis(
      agentId,
      `Canary-Bait '${baitName}' kompromittiert! Sofortige Apoptose (Not-Aus).`
    );
  }

  public async testInterAgentIsolation(sourceAgentId: string, targetAgentId: string): Promise<void> {
    await this.appendAuditRecord('INTER_AGENT_ISOLATION_BLOCKED', sourceAgentId, {
      targetAgentId,
      reason: 'Named Pipe DACL violation: AppContainer SIDs are mutually isolated.',
      errorCode: '0x00000005 (ERROR_ACCESS_DENIED)',
    });
    this.notify();
  }

  public importCandidateAsPolicyScope(candidateId: string): void {
    const candidate = this.discoveredCandidates.find((c) => c.id === candidateId);
    if (!candidate) return;

    candidate.status = 'imported';

    // Check if target already in scope or create new scope
    let scope = this.policy.scopes.find((s) => s.principals.agentIds.includes(candidate.agentId));
    if (!scope) {
      scope = {
        id: `learned-${candidate.agentId}`,
        description: `Automatisch gelernte Richtlinie für ${candidate.agentId}`,
        principals: {
          agentIds: [candidate.agentId],
          imageRoots: [`C:\\Agents\\${candidate.agentId}\\`],
        },
        targets: [],
        inspection: { tls: 'passthrough', requireHitlApproval: false },
        limits: {
          maxConcurrentConnections: 16,
          maxBytesUp: 67108864,
          maxBytesDown: 268435456,
          sessionTtlSeconds: 3600,
        },
      };
      this.policy.scopes.push(scope);
    }

    scope.targets.push({
      host: candidate.targetHost,
      ports: [candidate.targetPort],
      allowedMethods: [candidate.method],
    });

    this.appendAuditRecord('LEARN_MODE_CANDIDATE_CAPTURED', candidate.agentId, {
      action: 'CANDIDATE_IMPORTED_TO_POLICY',
      target: `${candidate.targetHost}:${candidate.targetPort}`,
      scopeId: scope.id,
    });

    this.notify();
  }

  // --- Policy Management CRUD ---

  public updatePolicy(newPolicy: CordonPolicy): { valid: boolean; errors: string[] } {
    const validation = this.validatePolicy(newPolicy);
    if (validation.valid) {
      this.policy = newPolicy;
      this.notify();
    }
    return validation;
  }

  public addScope(scope: PolicyScope): { valid: boolean; error?: string } {
    if (!scope.id || !scope.id.trim()) {
      return { valid: false, error: 'Scope ID darf nicht leer sein.' };
    }
    if (this.policy.scopes.some((s) => s.id === scope.id)) {
      return { valid: false, error: `Scope mit ID '${scope.id}' existiert bereits.` };
    }
    this.policy.scopes.push(scope);
    this.notify();
    return { valid: true };
  }

  public updateScope(scope: PolicyScope): { valid: boolean; error?: string } {
    const idx = this.policy.scopes.findIndex((s) => s.id === scope.id);
    if (idx === -1) {
      return { valid: false, error: `Scope '${scope.id}' nicht gefunden.` };
    }
    this.policy.scopes[idx] = scope;
    this.notify();
    return { valid: true };
  }

  public deleteScope(scopeId: string): void {
    this.policy.scopes = this.policy.scopes.filter((s) => s.id !== scopeId);
    this.notify();
  }

  public validatePolicy(policy: CordonPolicy): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    if (!policy.version || typeof policy.version !== 'number') {
      errors.push('Ungültige Policy-Version (muss Zahl sein).');
    }
    if (!['allow', 'deny'].includes(policy.defaultVerdict)) {
      errors.push("defaultVerdict muss 'deny' oder 'allow' sein.");
    }
    if (!Array.isArray(policy.scopes)) {
      errors.push('Scopes muss ein Array sein.');
    } else {
      policy.scopes.forEach((scope, i) => {
        if (!scope.id || typeof scope.id !== 'string') {
          errors.push(`Scope #${i + 1}: ID fehlt oder ist ungültig.`);
        }
        if (!scope.principals || !Array.isArray(scope.principals.agentIds)) {
          errors.push(`Scope '${scope.id}': principals.agentIds muss ein Array sein.`);
        }
        if (!Array.isArray(scope.targets) || scope.targets.length === 0) {
          errors.push(`Scope '${scope.id}': Mindestens ein Ziel (target) muss definiert sein.`);
        } else {
          scope.targets.forEach((t, j) => {
            if (!t.host || typeof t.host !== 'string') {
              errors.push(`Scope '${scope.id}' Ziel #${j + 1}: Host fehlt.`);
            }
            if (!Array.isArray(t.ports) || t.ports.some((p) => p < 1 || p > 65535)) {
              errors.push(`Scope '${scope.id}' Ziel #${j + 1}: Ports müssen zwischen 1 und 65535 liegen.`);
            }
          });
        }
      });
    }

    return { valid: errors.length === 0, errors };
  }

  // --- HITL & Apoptosis Handlers ---

  public async handleApprovalDecision(
    requestId: string,
    decision: 'allow_once' | 'always_allow' | 'deny' | 'apoptosis'
  ): Promise<void> {
    const req = this.pendingRequests.find((r) => r.id === requestId);
    if (!req) return;

    req.status = decision === 'allow_once'
      ? 'allowed_once'
      : decision === 'always_allow'
      ? 'always_allowed'
      : decision === 'apoptosis'
      ? 'apoptotic'
      : 'denied';
    req.decisionTimestamp = Date.now();
    req.decisionBy = 'Developer (Host Console)';

    const eventType = decision === 'allow_once'
      ? 'HITL_DECISION_ALLOW_ONCE'
      : decision === 'always_allow'
      ? 'HITL_DECISION_ALWAYS_ALLOW'
      : decision === 'apoptosis'
      ? 'APOPTOSIS_EXECUTED'
      : 'HITL_DECISION_DENIED';

    await this.appendAuditRecord(eventType, req.agentId, {
      requestId: req.id,
      decision,
      targetHost: req.targetHost,
      targetPort: req.targetPort,
      method: req.method,
      operator: 'Developer / Security Engineer',
    });

    if (decision === 'always_allow') {
      const existingScope = this.policy.scopes.find((s) => s.principals.agentIds.includes(req.agentId));
      if (existingScope) {
        existingScope.targets.push({
          host: req.targetHost,
          ports: [req.targetPort],
          allowedMethods: req.method ? [req.method] : ['GET', 'POST'],
        });
      }
    }

    if (decision === 'apoptosis') {
      await this.triggerApoptosis(req.agentId, `Emergency Apoptosis via HITL prompt für ${req.targetHost}`);
    }

    this.notify();
  }

  public async triggerApoptosis(agentId: string, reason: string): Promise<void> {
    const agent = this.agents.find((a) => a.id === agentId);
    if (!agent) return;

    agent.status = 'apoptotic';
    agent.activeSockets = 0;

    await this.appendAuditRecord('APOPTOSIS_EXECUTED', agentId, {
      pid: agent.pid,
      packageSid: agent.packageSid,
      reason,
      exitCode: '0xC0000409 (STATUS_SECURITY_CHECK_FAILURE)',
      action: 'All processes in Job Object instantly terminated (KILL_ON_JOB_CLOSE)',
    });

    setTimeout(async () => {
      this.rotateAgentGenotype(agentId);
      agent.status = 'active';
      this.notify();
    }, 2500);

    this.notify();
  }

  public async rotateAgentGenotype(agentId: string): Promise<void> {
    const agent = this.agents.find((a) => a.id === agentId);
    if (!agent) return;

    const newNonce = Math.random().toString(16).substring(2, 10);
    agent.ephemeralNonce = newNonce;
    agent.packageSid = `S-1-15-2-CORDON-${newNonce.toUpperCase()}`;
    agent.pipePath = `\\\\.\\pipe\\CordonGateway\\${agent.id}_${newNonce}`;
    agent.pid = Math.floor(4000 + Math.random() * 5000);
    agent.genotypeVersion += 1;
    agent.status = 'active';

    await this.appendAuditRecord('GENOTYPE_ROTATED', agentId, {
      newVersion: agent.genotypeVersion,
      newPackageSid: agent.packageSid,
      newPipePath: agent.pipePath,
      newPid: agent.pid,
    });

    this.notify();
  }

  public async runThreatScenario(scenarioId: string): Promise<void> {
    const scenario = this.threatScenarios.find((s) => s.id === scenarioId);
    if (!scenario) return;

    scenario.status = 'running';
    this.notify();

    await new Promise((r) => setTimeout(r, 600));

    scenario.status = 'blocked';
    await this.appendAuditRecord('JOB_LIMIT_ENFORCED', 'TEST_HARNESS', {
      scenario: scenario.id,
      title: scenario.title,
      enforcementLayer: scenario.layer,
      verdict: 'ATTACK_BLOCKED_AND_ISOLATED',
    });

    this.notify();
  }

  public async simulateNewAgentRequest(targetHost: string, targetPort: number, method: string): Promise<void> {
    const reqId = `REQ-${Math.floor(1000 + Math.random() * 9000)}`;
    const agent = this.agents[0];

    // If learn mode is enabled, record as candidate
    if (this.policy.learnModeEnabled) {
      this.discoveredCandidates.unshift({
        id: `DISC-${Math.floor(10 + Math.random() * 90)}`,
        timestamp: Date.now(),
        agentId: agent.id,
        targetHost,
        targetPort,
        method,
        frequency: 1,
        status: 'discovered',
      });
      await this.appendAuditRecord('LEARN_MODE_CANDIDATE_CAPTURED', agent.id, {
        targetHost,
        targetPort,
        method,
        status: 'RECORDED_IN_LEARN_MODE',
      });
      this.notify();
      return;
    }

    const newReq: PendingApprovalRequest = {
      id: reqId,
      timestamp: Date.now(),
      agentId: agent.id,
      agentName: agent.name,
      pid: agent.pid,
      packageSid: agent.packageSid,
      imagePath: agent.imagePath,
      targetHost,
      targetPort,
      method,
      path: '/api/v1/resource',
      actionDescription: `Agent ${agent.name} fordert ausgehende Verbindung an`,
      riskScore: targetHost.includes('internal') || targetHost.includes('169.254') ? 95 : 65,
      riskFactors: [
        'Zieldomäne erfordert Host-Entwickler Freigabe',
        'Kernel AppContainer Socket-Entzug verlangt Choke Point Genehmigung',
      ],
      status: 'pending',
    };

    this.pendingRequests.unshift(newReq);

    await this.appendAuditRecord('HITL_PROMPT_TRIGGERED', agent.id, {
      requestId: reqId,
      pid: agent.pid,
      targetHost,
      targetPort,
      method,
    });

    this.notify();
  }

  public async tamperAuditRecord(index: number, newReason: string): Promise<void> {
    const record = this.auditLog.find((r) => r.index === index);
    if (!record) return;

    record.details = { ...record.details, Reason: newReason, _TAMPERED_: true };
    record.isTampered = true;
    this.notify();
  }

  public async restoreAuditRecord(index: number): Promise<void> {
    const record = this.auditLog.find((r) => r.index === index);
    if (!record) return;

    delete record.details._TAMPERED_;
    record.isTampered = false;
    this.notify();
  }

  // --- Helper Methods ---
  private async appendAuditRecord(
    eventType: AuditRecord['eventType'],
    agentId: string,
    details: Record<string, any>
  ): Promise<AuditRecord> {
    this.logSequence++;
    const timestamp = new Date().toISOString();

    const canonical = canonicalize({
      index: this.logSequence,
      timestamp,
      eventType,
      agentId,
      details,
    });

    const currentHmac = await computeHmacSha256(this.lastHmac, canonical);

    const record: AuditRecord = {
      index: this.logSequence,
      timestamp,
      eventType,
      agentId,
      details,
      prevHmac: this.lastHmac,
      hmac: currentHmac,
      tpmSealed: this.policy.tpmHardwareAnchoring,
    };

    this.lastHmac = currentHmac;
    this.auditLog.push(record);
    return record;
  }

  public createBinaryFrame(
    kind: number,
    flags: number,
    seq: number,
    headerJson: Record<string, any>,
    payload: string,
    plane: 'control' | 'data'
  ): BinaryFrame {
    const headerStr = JSON.stringify(headerJson);
    const headerBytes = new TextEncoder().encode(headerStr);
    const payloadBytes = new TextEncoder().encode(payload);

    const totalLen = 8 + headerBytes.length + payloadBytes.length;
    const buf = new Uint8Array(totalLen);
    const view = new DataView(buf.buffer);

    view.setUint8(0, kind);
    view.setUint8(1, flags);
    view.setUint16(2, seq, false);
    view.setUint32(4, headerBytes.length, false);

    buf.set(headerBytes, 8);
    buf.set(payloadBytes, 8 + headerBytes.length);

    const hex = Array.from(buf.slice(0, 32))
      .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
      .join(' ');

    return {
      kind: kind as any,
      flags,
      seq,
      length: totalLen,
      headerJson,
      payload,
      rawHex: hex,
      timestamp: Date.now(),
      plane,
    };
  }
}

export const simulationEngine = new SimulationEngine();
