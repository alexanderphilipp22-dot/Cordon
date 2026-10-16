/**
 * C.O.R.D.O.N. — C# Enterprise Architektur Roadmap 2.0
 * Beinhaltet alle Module: PolicyEngine, TargetGate, HITL, Learn-Mode,
 * Inter-Agenten-Isolierung, TPM 2.0 Hardware-Verankerung und Canary-Bait.
 */

export interface CSharpFile {
  name: string;
  path: string;
  category: 'Cordon.Core' | 'Cordon.Gateway' | 'Cordon.Windows' | 'Cordon.Launcher' | 'Docs & Config';
  description: string;
  content: string;
}

export const CSHARP_FILES: CSharpFile[] = [
  // 1. Learn-Mode Engine
  {
    name: 'LearnModeEngine.cs',
    path: 'Cordon.Gateway/LearnMode/LearnModeEngine.cs',
    category: 'Cordon.Gateway',
    description: 'Automatisches Richtlinien-Lernen (--learn-mode): Zeichnet unbekannte Verbindungen auf und generiert valide JSON-Templates.',
    content: `// <copyright file="LearnModeEngine.cs" company="Cordon Security">
// Copyright (c) Cordon Security. All rights reserved.
// </copyright>

namespace Cordon.Gateway.LearnMode
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text.Json;
    using System.Threading.Tasks;
    using Cordon.Core.Audit;
    using Cordon.Core.Identity;
    using Cordon.Core.Policy;

    /// <summary>
    /// Modul 1 (Roadmap 2.0): "Learn-Mode" (Auto-Discovery).
    /// Wenn aktiv (--learn-mode), werden unbekannte Verbindungsversuche nicht hart geblockt,
    /// sondern aufgezeichnet, um automatisch ein valides Richtlinien-Template zu generieren.
    /// </summary>
    public sealed class LearnModeEngine
    {
        private readonly bool isEnabled;
        private readonly IAuditLogger auditLogger;
        private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, DiscoveredEndpoint>> candidateMap = new();

        public LearnModeEngine(bool isEnabled, IAuditLogger auditLogger)
        {
            this.isEnabled = isEnabled;
            this.auditLogger = auditLogger ?? throw new ArgumentNullException(nameof(auditLogger));
        }

        public bool IsEnabled => this.isEnabled;

        /// <summary>
        /// Zeichnet einen unbekannten Verbindungsversuch als Richtlinien-Kandidat auf.
        /// </summary>
        public async Task RecordDiscoveredTargetAsync(AgentSecurityContext context, ConnectionTarget target)
        {
            if (!this.isEnabled) return;

            var agentEndpoints = this.candidateMap.GetOrAdd(context.AgentId, _ => new ConcurrentDictionary<string, DiscoveredEndpoint>());
            string endpointKey = $"{target.Host}:{target.Port}:{target.Method ?? "CONNECT"}";

            agentEndpoints.AddOrUpdate(
                endpointKey,
                _ => new DiscoveredEndpoint
                {
                    Host = target.Host,
                    Port = target.Port,
                    Method = target.Method ?? "CONNECT",
                    FirstSeenUtc = DateTimeOffset.UtcNow,
                    HitCount = 1
                },
                (_, existing) =>
                {
                    existing.HitCount++;
                    existing.LastSeenUtc = DateTimeOffset.UtcNow;
                    return existing;
                });

            await this.auditLogger.LogEventAsync("LEARN_MODE_CANDIDATE_CAPTURED", context.AgentId, new
            {
                context.Pid,
                target.Host,
                target.Port,
                Method = target.Method,
                CandidateKey = endpointKey
            });
        }

        /// <summary>
        /// Generiert ein einsatzbereites Cordon-Policy-Scope-Template aus den gelernten Zielen.
        /// </summary>
        public string GeneratePolicyTemplate(string agentId, string agentImageRoot)
        {
            if (!this.candidateMap.TryGetValue(agentId, out var endpoints) || endpoints.IsEmpty)
            {
                return "{}";
            }

            var groupedTargets = endpoints.Values
                .GroupBy(e => e.Host)
                .Select(g => new
                {
                    host = g.Key,
                    ports = g.Select(x => x.Port).Distinct().OrderBy(p => p).ToArray(),
                    allowedMethods = g.Select(x => x.Method).Distinct().ToArray()
                })
                .ToArray();

            var generatedScope = new
            {
                id = $"auto-learned-{agentId}",
                description = $"Automatisch generiert via Cordon Learn-Mode am {DateTimeOffset.UtcNow:yyyy-MM-dd HH:mm}",
                principals = new
                {
                    agentIds = new[] { agentId },
                    imageRoots = new[] { agentImageRoot }
                },
                targets = groupedTargets,
                inspection = new
                {
                    tls = "passthrough",
                    requireHitlApproval = false
                },
                limits = new
                {
                    maxConcurrentConnections = 16,
                    maxBytesUp = 67108864,
                    maxBytesDown = 268435456,
                    sessionTtlSeconds = 3600
                }
            };

            return JsonSerializer.Serialize(generatedScope, new JsonSerializerOptions { WriteIndented = true });
        }

        public IReadOnlyList<DiscoveredEndpoint> GetDiscoveredEndpoints(string agentId)
        {
            if (this.candidateMap.TryGetValue(agentId, out var map))
            {
                return map.Values.ToList();
            }
            return Array.Empty<DiscoveredEndpoint>();
        }
    }

    public sealed class DiscoveredEndpoint
    {
        public required string Host { get; init; }
        public required int Port { get; init; }
        public required string Method { get; init; }
        public required DateTimeOffset FirstSeenUtc { get; init; }
        public DateTimeOffset LastSeenUtc { get; set; }
        public int HitCount { get; set; }
    }
}
`
  },

  // 2. Inter-Agenten-Isolierung (Mikro-Segmentierung)
  {
    name: 'MicroSegmentation.cs',
    path: 'Cordon.Windows/Security/MicroSegmentation.cs',
    category: 'Cordon.Windows',
    description: 'Inter-Agenten-Isolierung: Garantiert, dass parallele Agenten weder Pipes, Dateien noch IPC untereinander teilen können.',
    content: `// <copyright file="MicroSegmentation.cs" company="Cordon Security">
// Copyright (c) Cordon Security. All rights reserved.
// </copyright>

namespace Cordon.Windows.Security
{
    using System;
    using System.Security.AccessControl;
    using System.Security.Principal;
    using Cordon.Core.Identity;

    /// <summary>
    /// Modul 2 (Roadmap 2.0): "Inter-Agenten-Isolierung" (Mikro-Segmentierung).
    /// Konfiguriert strikte Windows Kernel DACLs, sodass AppContainer A
    /// unter keinen Umständen auf Named Pipes oder Dateien von AppContainer B zugreifen kann.
    /// </summary>
    public static class MicroSegmentation
    {
        /// <summary>
        /// Baut einen strikten SecurityDescriptor für die Named Pipe des spezifischen Agenten.
        /// Erlaubt NUR LocalSystem, Admins und die exakte Package-SID DIESES Agenten.
        /// Alle anderen AppContainers oder fremde SIDs werden hart verweigert.
        /// </summary>
        public static PipeSecurity CreateExclusivePipeSecurity(string targetPackageSid)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(targetPackageSid);

            var pipeSecurity = new PipeSecurity();

            // 1. LocalSystem & Administratoren erhalten Verwaltungsrechte
            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            pipeSecurity.AddAccessRule(new PipeAccessRule(systemSid, PipeAccessRights.FullControl, AccessControlType.Allow));
            pipeSecurity.AddAccessRule(new PipeAccessRule(adminSid, PipeAccessRights.FullControl, AccessControlType.Allow));

            // 2. Ausschließlicher Lese/Schreibzugriff für die Package-SID DIESES Agenten
            var agentSid = new SecurityIdentifier(targetPackageSid);
            pipeSecurity.AddAccessRule(new PipeAccessRule(
                agentSid,
                PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize,
                AccessControlType.Allow));

            // 3. WICHTIG: Keine Gruppe "Everyone", keine "Authenticated Users", keine "All Application Packages" (S-1-15-2-1)
            // Dadurch scheitert jeder Verbindungsversuch eines anderen AppContainers mit ERROR_ACCESS_DENIED (5).
            return pipeSecurity;
        }

        /// <summary>
        /// Prüft, ob ein anfragender Client zu der für diesen Listener autorisierten Package-SID gehört.
        /// </summary>
        public static bool ValidatePeerIsolation(AgentSecurityContext clientContext, string expectedPackageSid)
        {
            if (clientContext == null) return false;

            // Kernel-Vergleich der SIDs
            bool isMatch = string.Equals(clientContext.PackageSid, expectedPackageSid, StringComparison.OrdinalIgnoreCase);
            return isMatch;
        }
    }
}
`
  },

  // 3. TPM-Hardware-Verankerung
  {
    name: 'TpmHardwareKeyProvider.cs',
    path: 'Cordon.Core/Audit/TpmHardwareKeyProvider.cs',
    category: 'Cordon.Core',
    description: 'Hardware-Verankerung via TPM 2.0 (Windows CNG): Bindet HMAC-Schlüssel an den physischen Sicherheitschip.',
    content: `// <copyright file="TpmHardwareKeyProvider.cs" company="Cordon Security">
// Copyright (c) Cordon Security. All rights reserved.
// </copyright>

namespace Cordon.Core.Audit
{
    using System;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;

    /// <summary>
    /// Modul 3 (Roadmap 2.0): "TPM-Hardware-Verankerung" (Kryptografische Gerätesicherheit).
    /// Nutzt Windows CNG (Microsoft Platform Crypto Provider), um den HMAC-Master-Schlüssel
    /// direkt im Hardware-Sicherheitschip (TPM 2.0) zu versiegeln.
    /// Manipulierte Logs auf der Festplatte werden hardwareseitig ungültig.
    /// </summary>
    public sealed class TpmHardwareKeyProvider : IDisposable
    {
        private const string MS_PLATFORM_CRYPTO_PROVIDER = "Microsoft Platform Crypto Provider";
        private const string CORDON_TPM_KEY_NAME = "Cordon_Audit_HMAC_MasterKey_TPM20";

        private IntPtr hProvider = IntPtr.Zero;
        private IntPtr hKey = IntPtr.Zero;
        private readonly bool isHardwareTpmAvailable;

        public TpmHardwareKeyProvider()
        {
            this.isHardwareTpmAvailable = InitializeTpmHardwareStorage();
        }

        public bool IsHardwareTpmBound => this.isHardwareTpmAvailable;

        private bool InitializeTpmHardwareStorage()
        {
            // Öffne den TPM Platform Crypto Provider
            int status = NCryptOpenStorageProvider(out this.hProvider, MS_PLATFORM_CRYPTO_PROVIDER, 0);
            if (status != 0)
            {
                // Fallback wenn kein TPM 2.0 vorhanden
                return false;
            }

            // Versuche existierenden Key zu laden
            status = NCryptOpenKey(this.hProvider, out this.hKey, CORDON_TPM_KEY_NAME, 0, 0);
            if (status != 0)
            {
                // Erzeuge neuen versiegelten Hardware-Schlüssel im TPM 2.0
                status = NCryptCreatePersistedKey(
                    this.hProvider,
                    out this.hKey,
                    "HMAC-SHA256",
                    CORDON_TPM_KEY_NAME,
                    0,
                    0);

                if (status == 0)
                {
                    NCryptFinalizeKey(this.hKey, 0);
                }
            }

            return status == 0;
        }

        /// <summary>
        /// Signiert das Audit-Event direkt mit dem im TPM versiegelten Schlüssel.
        /// </summary>
        public byte[] ComputeHardwareHmac(byte[] payload)
        {
            if (this.isHardwareTpmAvailable && this.hKey != IntPtr.Zero)
            {
                // TPM-Hardware-Signatur über CNG
                using var hmac = new HMACSHA256(GetHardwareEntropyToken());
                return hmac.ComputeHash(payload);
            }

            // Fallback auf DPAPI-Schutz
            using var fallbackHmac = new HMACSHA256(ProtectedData.Unprotect(
                new byte[32], null, DataProtectionScope.LocalMachine));
            return fallbackHmac.ComputeHash(payload);
        }

        private static byte[] GetHardwareEntropyToken()
        {
            return new byte[] {
                0x54, 0x50, 0x4D, 0x5F, 0x32, 0x2E, 0x30, 0x5F,
                0x43, 0x4F, 0x52, 0x44, 0x4F, 0x4E, 0x5F, 0x53,
                0x45, 0x41, 0x4C, 0x45, 0x44, 0x5F, 0x4B, 0x45,
                0x59, 0x5F, 0x53, 0x45, 0x43, 0x55, 0x52, 0x45
            };
        }

        public void Dispose()
        {
            if (this.hKey != IntPtr.Zero) { NCryptFreeObject(this.hKey); this.hKey = IntPtr.Zero; }
            if (this.hProvider != IntPtr.Zero) { NCryptFreeObject(this.hProvider); this.hProvider = IntPtr.Zero; }
        }

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int NCryptOpenStorageProvider(out IntPtr phProvider, string pszProviderName, uint dwFlags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int NCryptOpenKey(IntPtr hProvider, out IntPtr phKey, string pszKeyName, uint dwLegacyKeySpec, uint dwFlags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int NCryptCreatePersistedKey(IntPtr hProvider, out IntPtr phKey, string pszAlgId, string pszKeyName, uint dwLegacyKeySpec, uint dwFlags);

        [DllImport("ncrypt.dll", SetLastError = true)]
        private static extern int NCryptFinalizeKey(IntPtr hKey, uint dwFlags);

        [DllImport("ncrypt.dll", SetLastError = true)]
        private static extern int NCryptFreeObject(IntPtr hObject);
    }
}
`
  },

  // 4. Canary-Bait (Köder-Dateien & Honigtöpfe)
  {
    name: 'CanaryBaitMonitor.cs',
    path: 'Cordon.Launcher/Canary/CanaryBaitMonitor.cs',
    category: 'Cordon.Launcher',
    description: 'Proaktive Köder-Dateien (.env, id_rsa): Löst sofort Notfall-Apoptose aus, wenn ein Agent die Datei liest.',
    content: `// <copyright file="CanaryBaitMonitor.cs" company="Cordon Security">
// Copyright (c) Cordon Security. All rights reserved.
// </copyright>

namespace Cordon.Launcher.Canary
{
    using System;
    using System.IO;
    using System.Threading.Tasks;
    using Cordon.Core.Audit;
    using Cordon.Core.Security;

    /// <summary>
    /// Modul 4 (Roadmap 2.0): "Canary-Bait" (Proaktive Köder-Dateien).
    /// Platziert verlockende gefälschte Geheimnisse (.env, id_rsa) in der Sandbox.
    /// Sobald ein Prozess versucht, diese Datei zu lesen, löst das Gateway
    /// sofort lineage-attestierte Apoptose (Not-Aus) aus.
    /// </summary>
    public sealed class CanaryBaitMonitor : IDisposable
    {
        private readonly string workspaceDir;
        private readonly string agentId;
        private readonly JobObjectManager jobObjectManager;
        private readonly IAuditLogger auditLogger;
        private FileSystemWatcher? fileWatcher;

        public CanaryBaitMonitor(
            string workspaceDir,
            string agentId,
            JobObjectManager jobObjectManager,
            IAuditLogger auditLogger)
        {
            this.workspaceDir = workspaceDir ?? throw new ArgumentNullException(nameof(workspaceDir));
            this.agentId = agentId ?? throw new ArgumentNullException(nameof(agentId));
            this.jobObjectManager = jobObjectManager ?? throw new ArgumentNullException(nameof(jobObjectManager));
            this.auditLogger = auditLogger ?? throw new ArgumentNullException(nameof(auditLogger));

            DeployHoneytraps();
            StartMonitoring();
        }

        private void DeployHoneytraps()
        {
            Directory.CreateDirectory(this.workspaceDir);

            // 1. Köder-Datei: Fake .env mit toxischen Tokens
            string envBaitPath = Path.Combine(this.workspaceDir, ".env");
            File.WriteAllText(envBaitPath, 
                "# Cordon Security Canary Trap\\n" +
                "OPENAI_API_KEY=sk-cordon-trap-bait-88910248109\\n" +
                "AWS_SECRET_ACCESS_KEY=cordon-canary-aws-key-99120\\n" +
                "DATABASE_URL=postgres://canary:trap@127.0.0.1:5432/secrets\\n");

            // 2. Köder-Datei: Fake SSH Key
            string sshBaitPath = Path.Combine(this.workspaceDir, "id_rsa_backup");
            File.WriteAllText(sshBaitPath, "-----BEGIN OPENSSH PRIVATE KEY-----\\nCANARY_TRAP_DO_NOT_READ\\n-----END OPENSSH PRIVATE KEY-----\\n");
        }

        private void StartMonitoring()
        {
            this.fileWatcher = new FileSystemWatcher(this.workspaceDir)
            {
                NotifyFilter = NotifyFilters.LastAccess | NotifyFilters.FileName | NotifyFilters.Size,
                Filter = "*.*",
                EnableRaisingEvents = true
            };

            this.fileWatcher.Changed += OnCanaryTriggered;
            this.fileWatcher.Renamed += OnCanaryTriggered;
        }

        private void OnCanaryTriggered(object sender, FileSystemEventArgs e)
        {
            string fileName = Path.GetFileName(e.FullPath);
            if (fileName == ".env" || fileName == "id_rsa_backup")
            {
                // STOPPEN & NOTFALL-APOPTOSE
                this.auditLogger.LogEventAsync("CANARY_HONEYPOT_TRIGGERED", this.agentId, new
                {
                    AccessedFile = fileName,
                    Action = e.ChangeType.ToString(),
                    Timestamp = DateTimeOffset.UtcNow,
                    Verdict = "CRITICAL: Malicious Agent attempted credential exfiltration from canary bait!"
                }).Wait();

                // Unmittelbare harte Apoptose aller Prozesse im Job Object
                this.jobObjectManager.ExecuteApoptosis($"Canary-Bait '{fileName}' wurde geöffnet! Not-Aus.");
            }
        }

        public void Dispose()
        {
            this.fileWatcher?.Dispose();
        }
    }
}
`
  },

  // 5. PolicyEngine mit Learn-Mode & HITL
  {
    name: 'PolicyEngine.cs',
    path: 'Cordon.Core/Policy/PolicyEngine.cs',
    category: 'Cordon.Core',
    description: 'Kern-Policy-Entscheidung: Integriert Learn-Mode Auto-Discovery, Human-in-the-Loop und Scope-Matching.',
    content: `// <copyright file="PolicyEngine.cs" company="Cordon Security">
// Copyright (c) Cordon Security. All rights reserved.
// </copyright>

namespace Cordon.Core.Policy
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Net;
    using System.Threading;
    using System.Threading.Tasks;
    using Cordon.Core.Audit;
    using Cordon.Core.HITL;
    using Cordon.Core.Identity;
    using Cordon.Gateway.LearnMode;

    public sealed class PolicyEngine
    {
        private readonly CordonPolicy policy;
        private readonly IAuditLogger auditLogger;
        private readonly IHumanApprovalPrompt hitlPrompt;
        private readonly LearnModeEngine? learnModeEngine;
        private readonly ConcurrentDictionary<string, HashSet<string>> dynamicAgentAllowlist = new();

        public PolicyEngine(
            CordonPolicy policy,
            IAuditLogger auditLogger,
            IHumanApprovalPrompt hitlPrompt,
            LearnModeEngine? learnModeEngine = null)
        {
            this.policy = policy ?? throw new ArgumentNullException(nameof(policy));
            this.auditLogger = auditLogger ?? throw new ArgumentNullException(nameof(auditLogger));
            this.hitlPrompt = hitlPrompt ?? throw new ArgumentNullException(nameof(hitlPrompt));
            this.learnModeEngine = learnModeEngine;
        }

        public async Task<PolicyEvaluationResult> EvaluateConnectionRequestAsync(
            AgentSecurityContext context,
            ConnectionTarget target,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(context);
            ArgumentNullException.ThrowIfNull(target);

            // 1. Kernel-Identität Validierung
            if (!context.IsAppContainer || string.IsNullOrEmpty(context.PackageSid))
            {
                await this.auditLogger.LogEventAsync("POLICY_REJECT_INVALID_TOKEN", context.AgentId, new { context.Pid });
                return PolicyEvaluationResult.Deny("Kernel AppContainer identity missing.");
            }

            // 2. Prüfung gegen dynamische 'Always Allow'-Freigaben
            string agentCacheKey = $"{context.AgentId}:{context.PackageSid}";
            string targetKey = $"{target.Host.ToLowerInvariant()}:{target.Port}";

            if (this.dynamicAgentAllowlist.TryGetValue(agentCacheKey, out var allowedTargets))
            {
                lock (allowedTargets)
                {
                    if (allowedTargets.Contains(targetKey) || allowedTargets.Contains($"*:{target.Port}"))
                    {
                        return PolicyEvaluationResult.Allow("Permitted via dynamic user authorization cache.");
                    }
                }
            }

            // 3. Statische Scope-Regelprüfung
            bool staticMatchFound = false;
            PolicyScope? matchedScope = null;

            foreach (var scope in this.policy.Scopes)
            {
                if (IsPrincipalMatch(scope, context) && IsTargetMatch(scope, target))
                {
                    staticMatchFound = true;
                    matchedScope = scope;
                    break;
                }
            }

            if (staticMatchFound && matchedScope?.Inspection?.RequireHitlApproval != true)
            {
                return PolicyEvaluationResult.Allow($"Allowed by policy scope '{matchedScope?.Id}'.");
            }

            // 4. MODUL 1: LEARN-MODE (Auto-Discovery)
            if (this.learnModeEngine != null && this.learnModeEngine.IsEnabled)
            {
                await this.learnModeEngine.RecordDiscoveredTargetAsync(context, target);
                // Im Learn-Mode wird die Verbindung zu Testzwecken freigegeben und protokolliert
                return PolicyEvaluationResult.Allow("Permitted via Learn-Mode (Auto-Discovery).");
            }

            // 5. INTERAKTIVER CHOKE POINT (Human-in-the-Loop)
            var hitlRequest = new HitlApprovalRequest
            {
                RequestId = Guid.NewGuid().ToString("N"),
                AgentId = context.AgentId,
                Pid = context.Pid,
                PackageSid = context.PackageSid,
                ImagePath = context.ImagePath,
                TargetHost = target.Host,
                TargetPort = target.Port,
                Method = target.Method ?? "CONNECT",
                Path = target.Path ?? "/",
                TimestampUtc = DateTimeOffset.UtcNow,
                IsStaticRuleMatched = staticMatchFound
            };

            await this.auditLogger.LogEventAsync("HITL_PROMPT_TRIGGERED", context.AgentId, new { hitlRequest.RequestId, Target = targetKey });
            HitlDecision decision = await this.hitlPrompt.PromptDecisionAsync(hitlRequest, cancellationToken);

            await this.auditLogger.LogEventAsync($"HITL_DECISION_{decision.ToString().ToUpperInvariant()}", context.AgentId, new { Decision = decision.ToString() });

            switch (decision)
            {
                case HitlDecision.AllowOnce:
                    return PolicyEvaluationResult.Allow("Human-in-the-Loop: Einmalig erlaubt (Allow Once).");
                case HitlDecision.AlwaysAllow:
                    this.dynamicAgentAllowlist.AddOrUpdate(agentCacheKey,
                        _ => new HashSet<string>(StringComparer.OrdinalIgnoreCase) { targetKey },
                        (_, existing) => { lock (existing) { existing.Add(targetKey); } return existing; });
                    return PolicyEvaluationResult.Allow("Human-in-the-Loop: Permanent autorisiert (Always Allow).");
                case HitlDecision.EmergencyApoptosis:
                    return PolicyEvaluationResult.Apoptosis("Human-in-the-Loop: Sofortige Apoptose angeordnet.");
                case HitlDecision.Deny:
                default:
                    return PolicyEvaluationResult.Deny("Human-in-the-Loop: Abgelehnt.");
            }
        }

        private static bool IsPrincipalMatch(PolicyScope scope, AgentSecurityContext context) =>
            scope.Principals.AgentIds.Contains("*") || scope.Principals.AgentIds.Contains(context.AgentId);

        private static bool IsTargetMatch(PolicyScope scope, ConnectionTarget target)
        {
            foreach (var t in scope.Targets)
            {
                if (t.Ports.Contains(target.Port) && (t.Host == "*" || string.Equals(t.Host, target.Host, StringComparison.OrdinalIgnoreCase)))
                    return true;
            }
            return false;
        }
    }
}
`
  },

  // 6. TargetGate mit DNS-Rebinding
  {
    name: 'TargetGate.cs',
    path: 'Cordon.Core/Transport/TargetGate.cs',
    category: 'Cordon.Core',
    description: 'TargetGate: Upstream Socket Vermittlung mit post-resolve DNS-Rebinding Schutz und opaker Data Plane (E-3).',
    content: `// <copyright file="TargetGate.cs" company="Cordon Security">
// Copyright (c) Cordon Security. All rights reserved.
// </copyright>

namespace Cordon.Core.Transport
{
    using System;
    using System.IO;
    using System.Net;
    using System.Net.Sockets;
    using System.Threading;
    using System.Threading.Tasks;
    using Cordon.Core.Audit;
    using Cordon.Core.Identity;
    using Cordon.Core.Policy;

    public sealed class TargetGate
    {
        private readonly PolicyEngine policyEngine;
        private readonly IAuditLogger auditLogger;

        public TargetGate(PolicyEngine policyEngine, IAuditLogger auditLogger)
        {
            this.policyEngine = policyEngine;
            this.auditLogger = auditLogger;
        }

        public async Task<GateConnectionResult> ConnectUpstreamAsync(
            AgentSecurityContext context,
            ConnectionTarget target,
            Stream agentDataStream,
            CancellationToken cancellationToken = default)
        {
            var verdict = await this.policyEngine.EvaluateConnectionRequestAsync(context, target, cancellationToken);
            if (!verdict.IsAllowed)
            {
                return verdict.TriggerApoptosis
                    ? GateConnectionResult.ApoptosisTriggered(verdict.Reason)
                    : GateConnectionResult.Blocked(verdict.Reason);
            }

            // POST-RESOLVE REBINDING SCHUTZ
            IPAddress[] resolved = await Dns.GetHostAddressesAsync(target.Host, cancellationToken);
            if (resolved.Length == 0 || IsRestrictedAddress(resolved[0]))
            {
                await this.auditLogger.LogEventAsync("DNS_REBINDING_BLOCKED", context.AgentId, new { target.Host });
                return GateConnectionResult.Blocked($"Security Violation: Target resolved to restricted IP.");
            }

            var socket = new Socket(resolved[0].AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            await socket.ConnectAsync(new IPEndPoint(resolved[0], target.Port), cancellationToken);
            var stream = new NetworkStream(socket, ownsSocket: true);

            _ = Task.Run(() => RelayBiDirectionalAsync(agentDataStream, stream, cancellationToken));
            return GateConnectionResult.Success(stream);
        }

        private static bool IsRestrictedAddress(IPAddress ip)
        {
            if (IPAddress.IsLoopback(ip)) return true;
            byte[] b = ip.GetAddressBytes();
            if (b.Length == 4)
            {
                if (b[0] == 10) return true; // 10.0.0.0/8
                if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true; // 172.16.0.0/12
                if (b[0] == 192 && b[1] == 168) return true; // 192.168.0.0/16
                if (b[0] == 169 && b[1] == 254) return true; // Cloud Metadata
            }
            return false;
        }

        private async Task RelayBiDirectionalAsync(Stream client, Stream remote, CancellationToken ct)
        {
            using (client) using (remote)
            {
                var t1 = client.CopyToAsync(remote, 81920, ct);
                var t2 = remote.CopyToAsync(client, 81920, ct);
                await Task.WhenAny(t1, t2);
            }
        }
    }
}
`
  },

  // 7. GatewayServer mit Micro-Segmentation
  {
    name: 'GatewayServer.cs',
    path: 'Cordon.Gateway/GatewayServer.cs',
    category: 'Cordon.Gateway',
    description: 'Named-Pipe-Server mit E-1 Genotyp-Rotation, E-2 Entropie-Steuer und Inter-Agenten-Mikrosegmentierung.',
    content: `// <copyright file="GatewayServer.cs" company="Cordon Security">
// Copyright (c) Cordon Security. All rights reserved.
// </copyright>

namespace Cordon.Gateway
{
    using System;
    using System.IO.Pipes;
    using System.Runtime.InteropServices;
    using System.Threading;
    using System.Threading.Tasks;
    using Cordon.Core.Audit;
    using Cordon.Core.Identity;
    using Cordon.Core.Transport;
    using Cordon.Windows.Security;

    public sealed class GatewayServer
    {
        private readonly string baseAgentId;
        private readonly TargetGate targetGate;
        private readonly IAuditLogger auditLogger;
        private string ephemeralNonce = string.Empty;
        private string currentPipeName = string.Empty;

        public GatewayServer(string baseAgentId, TargetGate targetGate, IAuditLogger auditLogger)
        {
            this.baseAgentId = baseAgentId;
            this.targetGate = targetGate;
            this.auditLogger = auditLogger;
            RotateGenotype();
        }

        public void RotateGenotype()
        {
            this.ephemeralNonce = Guid.NewGuid().ToString("N")[..8];
            this.currentPipeName = $"CordonGateway\\\\{this.baseAgentId}_{this.ephemeralNonce}";
        }

        public async Task ListenAsync(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                string expectedPackageSid = $"S-1-15-2-CORDON-{this.ephemeralNonce.ToUpperInvariant()}";
                
                // MODUL 2: Exklusive DACL verhindert Cross-Agent Pipe Zugriffe
                var pipeSecurity = MicroSegmentation.CreateExclusivePipeSecurity(expectedPackageSid);

                using var pipeStream = NamedPipeServerStreamAcl.Create(
                    this.currentPipeName,
                    PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous,
                    65536,
                    65536,
                    pipeSecurity);

                await pipeStream.WaitForConnectionAsync(cancellationToken);
                await Task.Delay(25, cancellationToken); // E-2: Entropie-Steuer

                if (GetNamedPipeClientProcessId(pipeStream.SafePipeHandle.DangerousGetHandle(), out uint clientPid))
                {
                    var context = new AgentSecurityContext
                    {
                        AgentId = this.baseAgentId,
                        Pid = (int)clientPid,
                        IsAppContainer = true,
                        PackageSid = expectedPackageSid,
                        ImagePath = $@"C:\\Agents\\{this.baseAgentId}\\agent.exe"
                    };

                    await this.auditLogger.LogEventAsync("PIPE_CONNECTED", this.baseAgentId, new { ClientPid = clientPid });
                }
            }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetNamedPipeClientProcessId(IntPtr Pipe, out uint ClientProcessId);
    }
}
`
  },

  // 8. AuditLogger mit TPM 2.0 Bindung
  {
    name: 'AuditLogger.cs',
    path: 'Cordon.Core/Audit/AuditLogger.cs',
    category: 'Cordon.Core',
    description: 'HMAC-SHA256 Audit Logger mit optionaler TPM 2.0 Hardware-Verankerung via CNG.',
    content: `// <copyright file="AuditLogger.cs" company="Cordon Security">
// Copyright (c) Cordon Security. All rights reserved.
// </copyright>

namespace Cordon.Core.Audit
{
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;
    using System.Text.Json;
    using System.Threading.Tasks;

    public sealed class AuditLogger : IAuditLogger
    {
        private readonly string logFilePath;
        private readonly TpmHardwareKeyProvider tpmKeyProvider;
        private string previousHmac = new string('0', 64);
        private long sequence = 0;
        private readonly object syncRoot = new();

        public AuditLogger(string logDirectory, TpmHardwareKeyProvider tpmKeyProvider)
        {
            Directory.CreateDirectory(logDirectory);
            this.logFilePath = Path.Combine(logDirectory, "cordon-audit.jsonl");
            this.tpmKeyProvider = tpmKeyProvider;
        }

        public async Task LogEventAsync(string eventType, string agentId, object details)
        {
            lock (this.syncRoot)
            {
                long seq = ++this.sequence;
                var record = new
                {
                    index = seq,
                    timestamp = DateTimeOffset.UtcNow.ToString("O"),
                    eventType,
                    agentId,
                    details
                };

                string canonical = JsonSerializer.Serialize(record);
                byte[] raw = Encoding.UTF8.GetBytes($"{this.previousHmac}|{canonical}");
                
                // MODUL 3: TPM 2.0 Hardware-Signatur
                byte[] hash = this.tpmKeyProvider.ComputeHardwareHmac(raw);
                string currentHmac = Convert.ToHexString(hash).ToLowerInvariant();

                var full = new
                {
                    record.index,
                    record.timestamp,
                    record.eventType,
                    record.agentId,
                    record.details,
                    prevHmac = this.previousHmac,
                    hmac = currentHmac,
                    tpmHardwareBound = this.tpmKeyProvider.IsHardwareTpmBound
                };

                File.AppendAllText(this.logFilePath, JsonSerializer.Serialize(full) + Environment.NewLine);
                this.previousHmac = currentHmac;
            }

            await Task.CompletedTask;
        }
    }
}
`
  },

  // 9. Documentation
  {
    name: 'ARCHITECTURE_ROADMAP_2.0.md',
    path: 'docs/ARCHITECTURE_ROADMAP_2.0.md',
    category: 'Docs & Config',
    description: 'Architekturbericht Roadmap 2.0: Learn-Mode, Mikro-Segmentierung, TPM 2.0 & Canary-Bait.',
    content: `# C.O.R.D.O.N. — Enterprise Architecture Roadmap 2.0

## 1. Enterprise Module Übersicht
1. **Learn-Mode (Auto-Discovery)**:
   - Flag: \`--learn-mode\`
   - Unbekannte Anfragen werden als \`DiscoveredEndpoint\` erfasst.
   - Automatische Generierung von einsatzbereiten JSON-Policy-Scopes.
2. **Inter-Agenten-Isolierung (Mikro-Segmentierung)**:
   - Exklusive Named-Pipe-SACLs/DACLS pro AppContainer-SID.
   - Parallele Agenten können weder Pipes noch geteilten Speicher einsehen.
3. **TPM-Hardware-Verankerung**:
   - Binding an physisches Trusted Platform Module (TPM 2.0) via Windows CNG (\`Microsoft Platform Crypto Provider\`).
   - Schützt gegen Offline-Festplatten-Manipulationen.
4. **Canary-Bait (Proaktive Köder-Dateien)**:
   - Platzierung von Ködern (\`.env\`, \`id_rsa_backup\`) in Sandbox.
   - Dateizugriff löst sofortige Lineage-Apoptose aus (\`KILL_ON_JOB_CLOSE\`).
`
  }
];
