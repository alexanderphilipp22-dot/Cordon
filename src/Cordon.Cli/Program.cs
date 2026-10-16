using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using Cordon.Core;
using Cordon.Core.Audit;
using Cordon.Core.Configuration;
using Cordon.Core.Model;
using Cordon.Core.Policy;
using Cordon.Core.Protocol;
using Cordon.Gateway;
using Cordon.Gateway.Tls;
using Cordon.Launcher;
using Cordon.Windows;

namespace Cordon.Cli;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;

        if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
        {
            PrintUsage();
            return args.Length == 0 ? 2 : 0;
        }

        using var cancellation = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            Console.WriteLine("[cordon] Abbruch angefordert ...");
            cancellation.Cancel();
        };

        try
        {
            var command = args[0];
            var rest = args.Skip(1).ToArray();

            return command switch
            {
                "serve" => await ServeAsync(rest, cancellation.Token).ConfigureAwait(false),
                "init" => Init(rest),
                "run" => await RunCommandAsync(rest, cancellation.Token).ConfigureAwait(false),
                "scope" => ScopeCommand(rest),
                "audit" => AuditCommand(rest),
                "profile" => ProfileCommand(rest),
                "doctor" => Doctor(rest),
                "install-service" => InstallService(rest),
                "uninstall-service" => UninstallService(rest),
                "version" or "--version" => PrintVersion(),
                _ => UnknownCommand(command),
            };
        }
        catch (OperationCanceledException)
        {
            return 130;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Fehler: {ex.Message}");
            return 1;
        }
    }

    // =====================================================================
    // serve
    // =====================================================================

    private static async Task<int> ServeAsync(string[] args, CancellationToken cancellationToken)
    {
        var options = CommandLine.Parse(args);
        var policyPath = options.Get("--policy") ?? CordonPaths.ScopesFile;
        var auditDirectory = options.Get("--audit-dir") ?? CordonPaths.AuditDirectory;
        var connectTimeout = options.GetSeconds("--connect-timeout", 15);
        var enableInterception = options.Has("--enable-interception");
        var caDirectory = options.Get("--ca-dir") ?? CordonPaths.CaDirectory;

        Console.WriteLine("[cordon] Cordon Control startet.");
        Console.WriteLine($"[cordon] Policy      : {policyPath}");
        Console.WriteLine($"[cordon] Audit       : {auditDirectory}");

        // ------------------------------------------------------------------
        // Audit-Schluessel
        // ------------------------------------------------------------------
        AuditKeyStore.KeyResult keyResult;
        try
        {
            keyResult = AuditKeyStore.LoadOrCreate();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            Console.Error.WriteLine($"Fehler: Audit-Schluessel nicht verfuegbar: {ex.Message}");
            Console.Error.WriteLine("Der Dienst startet NICHT. Ohne Audit gibt es keinen Nachweis.");
            return 3;
        }

        Console.WriteLine($"[cordon] Audit-Key   : {keyResult.Description}");

        // ------------------------------------------------------------------
        // CA (nur bei Interception)
        // ------------------------------------------------------------------
        CertificateAuthority? authority = null;

        if (enableInterception)
        {
            try
            {
                Directory.CreateDirectory(caDirectory);
                authority = CertificateAuthority.LoadOrCreate(caDirectory);
                Console.WriteLine($"[cordon] TLS-CA      : {authority.Subject}");
                Console.WriteLine(
                    "[cordon] Interception ist nur fuer Ziele aktiv, die im Scope unter "
                    + "inspection.interceptAllowlist stehen.");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                or System.Security.Cryptography.CryptographicException)
            {
                Console.Error.WriteLine($"Fehler: CA konnte nicht geladen werden: {ex.Message}");
                return 4;
            }
        }
        else
        {
            Console.WriteLine("[cordon] TLS         : Passthrough (keine CA, kein Klartext, kein Schluessel)");
        }

        // ------------------------------------------------------------------
        // Policy
        // ------------------------------------------------------------------
        using var policyStore = new PolicyStore(policyPath, watch: !options.Has("--no-watch"));

        await using var audit = new AuditLog(auditDirectory, keyResult.Key);

        policyStore.Reloaded += (success, errors) =>
        {
            if (success)
            {
                Console.WriteLine($"[cordon] Policy geladen: {policyStore.Current?.ScopeCount ?? 0} Scope(s).");
            }
            else
            {
                Console.Error.WriteLine("[cordon] POLICY-FEHLER - die zuletzt gueltige Policy bleibt aktiv:");
                foreach (var error in errors)
                {
                    Console.Error.WriteLine($"  - {error}");
                }
            }
        };

        if (!policyStore.Load())
        {
            Console.Error.WriteLine("Fehler: Die Policy konnte nicht geladen werden:");
            foreach (var error in policyStore.LastErrors)
            {
                Console.Error.WriteLine($"  - {error}");
            }

            Console.Error.WriteLine(
                "Der Dienst startet NICHT. Es gibt keinen 'permit all'-Fallback - "
                + "ohne Policy wird nicht gelauscht.");
            return 5;
        }

        // ------------------------------------------------------------------
        // Erwarteter Image-Pfad (zweite Identitaetsbindung)
        // ------------------------------------------------------------------
        // Default: pro Agent aus den imageRoots des Scopes ableiten. Der
        // Schalter ist nur ein Override fuer Sonderfaelle.
        var imageRootOverride = options.Get("--expected-image-root");

        Console.WriteLine(imageRootOverride is null
            ? "[cordon] Image-Root  : pro Agent aus dem Scope (imageRoots)"
            : $"[cordon] Image-Root  : Override {imageRootOverride}");

        var gatewayOptions = new GatewayOptions
        {
            Authority = authority,
            ConnectTimeout = connectTimeout,
            ExpectedImagePathOverride = imageRootOverride,
        };

        if (imageRootOverride is null && !HasAnyImageRoot(policyStore.Current))
        {
            Console.Error.WriteLine(
                "[cordon] WARNUNG: kein Scope definiert imageRoots. Damit fehlt die zweite "
                + "Identitaetsbindung; die Identitaet stuetzt sich allein auf Pipe-DACL und "
                + "Package-SID. Fuer den Produktivbetrieb imageRoots setzen.");
        }

        await using var server = new GatewayServer(gatewayOptions, policyStore, audit);

        try
        {
            await server.RunAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            Console.WriteLine("[cordon] Cordon Control beendet sich.");

            foreach (var status in server.Status)
            {
                Console.WriteLine(
                    $"[cordon]   {status.AgentId}: {status.TotalConnections} Verbindung(en) insgesamt.");
            }

            audit.Write(AuditLog.Event(AuditEvents.GatewayStop));
            await audit.FlushAsync(CancellationToken.None).ConfigureAwait(false);

            authority?.Dispose();
        }

        return 0;
    }

    private static bool HasAnyImageRoot(CompiledPolicy? policy)
    {
        if (policy is null)
        {
            return false;
        }

        foreach (var scope in policy.Scopes)
        {
            foreach (var root in scope.Grant.Principals.ImageRoots)
            {
                if (!string.IsNullOrWhiteSpace(root))
                {
                    return true;
                }
            }
        }

        return false;
    }

    // =====================================================================
    // init
    // =====================================================================

    private static int Init(string[] args)
    {
        var options = CommandLine.Parse(args);
        var force = options.Has("--force");
        var harden = options.Has("--harden");
        var installInterceptionCa = options.Has("--with-interception-ca");

        Console.WriteLine($"[cordon] Initialisiere {CordonPaths.RootDirectory}");

        foreach (var directory in CordonPaths.AllDirectories)
        {
            Directory.CreateDirectory(directory);
            Console.WriteLine($"[cordon]   angelegt: {directory}");
        }

        if (File.Exists(CordonPaths.ScopesFile) && !force)
        {
            Console.WriteLine($"[cordon] Policy existiert bereits, wird nicht ueberschrieben: {CordonPaths.ScopesFile}");
            Console.WriteLine("[cordon] Mit --force ueberschreiben.");
        }
        else
        {
            var template = CreateTemplatePolicy();
            File.WriteAllText(
                CordonPaths.ScopesFile,
                JsonSerializer.Serialize(template, CordonJson.WriteIndentedOptions));
            Console.WriteLine($"[cordon]   Beispiel-Policy geschrieben: {CordonPaths.ScopesFile}");
        }

        var keyResult = AuditKeyStore.LoadOrCreate();
        Console.WriteLine($"[cordon]   Audit-Schluessel: {keyResult.Description}");

        if (installInterceptionCa)
        {
            using var authority = CertificateAuthority.LoadOrCreate(CordonPaths.CaDirectory);
            var publicPath = Path.Combine(CordonPaths.CaDirectory, "cordon-ca.cer");
            File.WriteAllBytes(publicPath, authority.Certificate.Export(
                System.Security.Cryptography.X509Certificates.X509ContentType.Cert));
            Console.WriteLine($"[cordon]   CA-Zertifikat (oeffentlich): {publicPath}");
            Console.WriteLine(
                "[cordon]   Die CA wird NICHT in den Windows-Trust-Store geschrieben. "
                + "Sie wird nur dem Agenten uebergeben, der Interception anfordert.");
        }

        if (harden)
        {
            if (!FileAcl.IsElevated())
            {
                Console.Error.WriteLine("[cordon] --harden benoetigt erhoehte Rechte. Uebersprungen.");
                return 1;
            }

            FileAcl.RestrictDirectoryToAdministrators(CordonPaths.RootDirectory, administratorsCanWrite: true);
            FileAcl.SecureAuditDirectory(CordonPaths.AuditDirectory);
            FileAcl.RestrictFileToAdministrators(CordonPaths.AuditHmacKeyFile);
            FileAcl.RestrictFileToAdministrators(CordonPaths.ScopesFile);
            FileAcl.SecureCaDirectory(CordonPaths.CaDirectory);
            Console.WriteLine("[cordon]   ACLs gesetzt (LocalSystem/Administratoren).");
        }
        else
        {
            Console.WriteLine(
                "[cordon] Hinweis: ACLs wurden nicht gesetzt. Fuer den Produktivbetrieb "
                + "'cordon init --harden' mit erhoehten Rechten ausfuehren.");
        }

        Console.WriteLine("[cordon] Fertig. Naechster Schritt: 'cordon serve' (oder als Dienst installieren).");
        return 0;
    }

    private static ScopeConfiguration CreateTemplatePolicy() => new()
    {
        Version = 1,
        DefaultVerdict = Verdict.Deny,
        AllowLoopback = false,
        AllowLinkLocal = false,
        RequireSignature = false,
        AllowedCapabilities = [],
        Scopes =
        [
            new ScopeGrant
            {
                Id = "example-docs",
                Description = "Beispiel: nur Dokumentations-Hosts ueber HTTPS, TLS-Passthrough.",
                Principals = new ScopePrincipal
                {
                    AgentIds = ["example"],
                    ImageRoots = [@"C:\Agents\example\"],
                },
                Targets =
                [
                    new ScopeTarget { Host = "docs.python.org", Ports = [443] },
                    new ScopeTarget { Host = "*.wikipedia.org", Ports = [443] },
                ],
                Inspection = new ScopeInspection
                {
                    Tls = TlsMode.Passthrough,
                    InterceptAllowlist = [],
                },
                Limits = new ScopeLimits
                {
                    MaxConcurrentConnections = 8,
                    MaxBytesUp = 32L * 1024 * 1024,
                    MaxBytesDown = 128L * 1024 * 1024,
                    SessionTtlSeconds = 3600,
                },
                Rules = new ScopeHttpRules(),
            },
        ],
    };

    // =====================================================================
    // run
    // =====================================================================

    private static async Task<int> RunCommandAsync(string[] args, CancellationToken cancellationToken)
    {
        var agentId = OptionParser.TakeValue(args, "--agent", out var remaining);

        if (string.IsNullOrWhiteSpace(agentId))
        {
            Console.Error.WriteLine("Fehler: --agent <id> ist erforderlich.");
            return 2;
        }

        var command = OptionParser.SplitCommand(remaining);

        var options = new AgentRunOptions
        {
            AgentId = agentId,
            Command = command,
            HardeningEnabled = !remaining.Contains("--no-wfp", StringComparer.Ordinal),
            PersistentWfp = remaining.Contains("--wfp-persistent", StringComparer.Ordinal),
            WorkingDirectory = OptionParser.TakeValue(remaining, "--workdir", out _),
            ActiveProcessLimit = OptionParser.TakeInt(remaining, "--max-processes", 64),
            ProcessMemoryLimitBytes = OptionParser.TakeLong(remaining, "--max-process-memory-mb", 4096) * 1024 * 1024,
            JobMemoryLimitBytes = OptionParser.TakeLong(remaining, "--max-job-memory-mb", 8192) * 1024 * 1024,
            CpuTimeSeconds = OptionParser.TakeLong(remaining, "--max-cpu-seconds", 0),
            WaitForExit = !remaining.Contains("--no-wait", StringComparer.Ordinal),
        };

        WarnIfNoScope(agentId);

        var result = await AgentRunOrchestrator
            .ExecuteAsync(options, Console.Out, Console.Error, cancellationToken)
            .ConfigureAwait(false);

        return result.ExitCode;
    }

    private static void WarnIfNoScope(string agentId)
    {
        try
        {
            var path = CordonPaths.ScopesFile;
            if (!File.Exists(path))
            {
                Console.Error.WriteLine(
                    $"[cordon] WARNUNG: keine Policy unter {path}. Der Agent startet netzlos und "
                    + "kann auch das Gateway nicht nutzen (kein Listener ohne Scope).");
                return;
            }

            using var store = new PolicyStore(path, watch: false);
            if (!store.Load())
            {
                Console.Error.WriteLine("[cordon] WARNUNG: Policy nicht ladbar:");
                foreach (var error in store.LastErrors)
                {
                    Console.Error.WriteLine($"  - {error}");
                }

                return;
            }

            var hasScope = store.Current?.Scopes.Any(s =>
                s.Grant.Principals.AgentIds.Contains(agentId, StringComparer.OrdinalIgnoreCase)) ?? false;

            if (!hasScope)
            {
                Console.Error.WriteLine(
                    $"[cordon] WARNUNG: kein Scope fuer Agent '{agentId}'. Der Agent startet "
                    + "netzlos und das Gateway lauscht nicht fuer ihn.");
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            Console.Error.WriteLine($"[cordon] WARNUNG: Policy-Pruefung fehlgeschlagen: {ex.Message}");
        }
    }

    // =====================================================================
    // scope
    // =====================================================================

    private static int ScopeCommand(string[] args)
    {
        var subcommand = args.Length > 0 ? args[0] : "show";
        var rest = args.Skip(1).ToArray();

        switch (subcommand)
        {
            case "show":
            case "list":
            {
                using var store = new PolicyStore(CordonPaths.ScopesFile, watch: false);
                if (!store.Load())
                {
                    Console.Error.WriteLine("Policy nicht ladbar:");
                    foreach (var error in store.LastErrors)
                    {
                        Console.Error.WriteLine($"  - {error}");
                    }

                    return 1;
                }

                var policy = store.Current!;
                Console.WriteLine($"Policy: {store.Path}");
                Console.WriteLine($"Scopes: {policy.ScopeCount}, defaultVerdict={policy.Configuration.DefaultVerdict}");
                Console.WriteLine(
                    $"allowLoopback={policy.Configuration.AllowLoopback}, "
                    + $"allowLinkLocal={policy.Configuration.AllowLinkLocal}, "
                    + $"requireSignature={policy.Configuration.RequireSignature}");

                foreach (var scope in policy.Scopes)
                {
                    Console.WriteLine();
                    Console.WriteLine($"  [{scope.Grant.Id}] {scope.Grant.Description}");
                    Console.WriteLine($"    Agenten   : {string.Join(", ", scope.Grant.Principals.AgentIds)}");
                    Console.WriteLine($"    ImageRoots: {string.Join(", ", scope.Grant.Principals.ImageRoots)}");
                    Console.WriteLine($"    TLS       : {scope.Grant.Inspection.Tls}");

                    foreach (var target in scope.Grant.Targets)
                    {
                        Console.WriteLine(
                            $"    Ziel      : {target.Host} -> Ports {string.Join(",", target.Ports)}");
                    }
                }

                return 0;
            }

            case "validate":
            {
                var path = rest.Length > 0 ? rest[0] : CordonPaths.ScopesFile;
                var json = File.ReadAllText(path);
                var configuration = JsonSerializer.Deserialize(
                    json,
                    CordonJsonContext.Default.ScopeConfiguration);

                if (configuration is null)
                {
                    Console.Error.WriteLine("Policy ist leer.");
                    return 1;
                }

                var result = PolicyEngine.Compile(configuration);
                if (result.Success)
                {
                    Console.WriteLine($"OK: {result.Policy!.ScopeCount} Scope(s) kompiliert.");
                    return 0;
                }

                Console.Error.WriteLine("Policy ist UNGUELTIG:");
                foreach (var error in result.Errors)
                {
                    Console.Error.WriteLine($"  - {error}");
                }

                return 1;
            }

            case "check":
            {
                // Simuliert eine Entscheidung, damit eine Regel ohne
                // laufenden Agenten geprueft werden kann.
                if (rest.Length < 3)
                {
                    Console.Error.WriteLine("Verwendung: cordon scope check <agentId> <host> <port> [--http METHOD PATH]");
                    return 2;
                }

                return ScopeCheck(rest);
            }

            default:
                Console.Error.WriteLine($"Unbekanntes 'scope'-Unterkommando: {subcommand}");
                return 2;
        }
    }

    private static int ScopeCheck(string[] args)
    {
        var agentId = args[0];
        var hostArgument = args[1];

        if (!int.TryParse(args[2], NumberStyles.Integer, CultureInfo.InvariantCulture, out var port))
        {
            Console.Error.WriteLine($"Port '{args[2]}' ist keine Zahl.");
            return 2;
        }

        var method = OptionParser.TakeValue(args, "--method", out _);
        var path = OptionParser.TakeValue(args, "--path", out _);

        using var store = new PolicyStore(CordonPaths.ScopesFile, watch: false);
        if (!store.Load())
        {
            Console.Error.WriteLine("Policy nicht ladbar.");
            return 1;
        }

        var policy = store.Current!;
        var host = HostNormalizer.Normalize(hostArgument);

        // Eine synthetische Identitaet: diese Pruefung beantwortet die Frage
        // "greift der Scope?", nicht "ist dieser Prozess echt?". Die
        // Identitaetspruefung findet nur am lebenden Objekt statt.
        var identity = new ClientIdentity
        {
            Pid = 0,
            ImagePath = policy.Scopes
                .SelectMany(s => s.Grant.Principals.ImageRoots)
                .FirstOrDefault() ?? string.Empty,
            PackageSid = "S-1-15-2-0-0-0-0-0-0-0",
            IsAppContainer = true,
            Integrity = IntegrityLevel.Low,
            Capabilities = [],
            AgentId = agentId,
            ExpectedPackageSid = "S-1-15-2-0-0-0-0-0-0-0",
            ExpectedImagePath = string.Empty,
        };

        var decision = PolicyEngine.Evaluate(
            policy,
            identity,
            host,
            port,
            method is null ? TargetKind.Connect : TargetKind.Http,
            method,
            path);

        Console.WriteLine($"Agent : {agentId}");
        Console.WriteLine($"Ziel  : {(host.IsValid ? host.Value : hostArgument)}:{port}");
        Console.WriteLine($"Host  : {(host.IsValid ? "gueltig" : $"UNGUELTIG - {host.Error}")}");
        Console.WriteLine($"Urteil: {decision.Verdict}");

        if (decision.Verdict == Verdict.Allow)
        {
            Console.WriteLine($"Scope : {decision.ScopeId}");
            Console.WriteLine($"TLS   : {decision.Tls}");
        }
        else
        {
            Console.WriteLine($"Code  : {decision.Code}");
            Console.WriteLine($"Grund : {decision.Reason}");
        }

        Console.WriteLine();
        Console.WriteLine(
            "Hinweis: Dies ist eine reine Regelpruefung mit synthetischer Identitaet. "
            + "Sie ersetzt nicht die Identitaetspruefung am lebenden Prozess.");

        return decision.Verdict == Verdict.Allow ? 0 : 1;
    }

    // =====================================================================
    // audit
    // =====================================================================

    private static int AuditCommand(string[] args)
    {
        var subcommand = args.Length > 0 ? args[0] : "tail";
        var rest = args.Skip(1).ToArray();

        switch (subcommand)
        {
            case "tail":
            {
                var count = (int)OptionParser.TakeLong(rest, "--lines", 50);
                var directory = OptionParser.TakeValue(rest, "--dir", out _) ?? CordonPaths.AuditDirectory;

                if (!Directory.Exists(directory))
                {
                    Console.Error.WriteLine($"Audit-Verzeichnis existiert nicht: {directory}");
                    return 1;
                }

                var file = Directory.GetFiles(directory, "cordon-*.jsonl")
                    .OrderByDescending(f => f, StringComparer.Ordinal)
                    .FirstOrDefault();

                if (file is null)
                {
                    Console.Error.WriteLine("Keine Audit-Dateien gefunden.");
                    return 1;
                }

                if (count < 1)
                {
                    count = 1;
                }

                Console.WriteLine($"# {file}");

                // Ringpuffer statt TakeLast: eine Audit-Datei kann gross
                // werden, und TakeLast wuerde die gesamte Datei puffern.
                var buffer = new Queue<string>(count);

                foreach (var line in File.ReadLines(file))
                {
                    if (line.Length == 0)
                    {
                        continue;
                    }

                    if (buffer.Count == count)
                    {
                        buffer.Dequeue();
                    }

                    buffer.Enqueue(line);
                }

                foreach (var line in buffer)
                {
                    Console.WriteLine(line);
                }

                return 0;
            }

            case "verify":
            {
                var directory = OptionParser.TakeValue(rest, "--dir", out _) ?? CordonPaths.AuditDirectory;
                return AuditVerifier.Verify(directory);
            }

            default:
                Console.Error.WriteLine($"Unbekanntes 'audit'-Unterkommando: {subcommand}");
                return 2;
        }
    }

    // =====================================================================
    // profile
    // =====================================================================

    private static int ProfileCommand(string[] args)
    {
        var subcommand = args.Length > 0 ? args[0] : "list";
        var rest = args.Skip(1).ToArray();

        switch (subcommand)
        {
            case "list":
            case "show":
            {
                var agentId = rest.Length > 0 ? rest[0] : null;

                if (agentId is null)
                {
                    Console.Error.WriteLine("Verwendung: cordon profile show <agentId>");
                    return 2;
                }

                var sid = AppContainerProfile.TryResolve(agentId);
                if (sid is null)
                {
                    Console.Error.WriteLine($"Kein AppContainer-Profil fuer Agent '{agentId}'.");
                    return 1;
                }

                Console.WriteLine($"Agent       : {agentId}");
                Console.WriteLine($"Profil      : {AppContainerProfile.NameForAgent(agentId)}");
                Console.WriteLine($"Package-SID : {sid.Value}");
                return 0;
            }

            case "delete":
            {
                if (rest.Length == 0)
                {
                    Console.Error.WriteLine("Verwendung: cordon profile delete <agentId>");
                    return 2;
                }

                var deleted = AppContainerProfile.Delete(rest[0]);
                Console.WriteLine(deleted
                    ? $"Profil fuer '{rest[0]}' geloescht."
                    : $"Profil fuer '{rest[0]}' konnte nicht geloescht werden.");
                return deleted ? 0 : 1;
            }

            case "create":
            {
                if (rest.Length == 0)
                {
                    Console.Error.WriteLine("Verwendung: cordon profile create <agentId>");
                    return 2;
                }

                var profile = AppContainerProfile.Ensure(rest[0]);
                Console.WriteLine($"Profil      : {profile.Name}");
                Console.WriteLine($"Package-SID : {profile.SidString}");
                Console.WriteLine("Capabilities: keine (Netzwerk ist im Kernel gesperrt)");
                return 0;
            }

            default:
                Console.Error.WriteLine($"Unbekanntes 'profile'-Unterkommando: {subcommand}");
                return 2;
        }
    }

    // =====================================================================
    // doctor
    // =====================================================================

    private static int Doctor(string[] args)
    {
        var options = CommandLine.Parse(args);
        var agentId = options.Get("--agent");
        var failures = 0;

        Console.WriteLine("[cordon] doctor - Umgebungsdiagnose");
        Console.WriteLine();

        // --- Windows-Version ---------------------------------------------
        var version = Environment.OSVersion.Version;
        var supportsAppContainer = version.Build >= 9200;
        Report(ref failures, supportsAppContainer, "Windows-Version",
            $"{version} (Build {version.Build}) - AppContainer verfuegbar: {supportsAppContainer}");

        // --- Bitness ------------------------------------------------------
        Report(ref failures, Environment.Is64BitProcess, "Prozess-Bitness",
            Environment.Is64BitProcess ? "x64" : "x86 (WFP-Anbindung nicht unterstuetzt)");

        // --- Rechte -------------------------------------------------------
        var elevated = FileAcl.IsElevated();
        Console.WriteLine($"[    ] Erhoehung  : {elevated} ({FileAcl.CurrentUserName()})");
        if (!elevated)
        {
            Console.WriteLine("       Ohne Erhoehung sind WFP-Regeln und die Dienstinstallation nicht moeglich.");
            Console.WriteLine("       Die AppContainer-Grenze wirkt davon unabhaengig.");
        }

        // --- Verzeichnisse ------------------------------------------------
        foreach (var directory in CordonPaths.AllDirectories)
        {
            Console.WriteLine($"[    ] Verzeichnis: {directory} -> {(Directory.Exists(directory) ? "vorhanden" : "FEHLT")}");
        }

        // --- Policy -------------------------------------------------------
        using (var store = new PolicyStore(CordonPaths.ScopesFile, watch: false))
        {
            var ok = store.Load();
            Report(ref failures, ok, "Policy",
                ok
                    ? $"{store.Current?.ScopeCount ?? 0} Scope(s) geladen"
                    : string.Join(" | ", store.LastErrors));
        }

        // --- Audit-Schluessel --------------------------------------------
        try
        {
            var key = AuditKeyStore.LoadOrCreate();
            Console.WriteLine($"[ ok ] Audit-Key : {key.Description}");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            Report(ref failures, false, "Audit-Key", ex.Message);
        }

        // --- AppContainer-Profil + Job Object -----------------------------
        if (agentId is not null)
        {
            try
            {
                var profile = AppContainerProfile.Ensure(agentId);
                Console.WriteLine($"[ ok ] Profil    : {profile.Name} = {profile.SidString}");
            }
            catch (Exception ex) when (ex is Win32Exception or UnauthorizedAccessException)
            {
                Report(ref failures, false, "AppContainer-Profil", ex.Message);
            }

            try
            {
                using var job = JobObject.Create(new SandboxLimits { ActiveProcessLimit = 8 });
                var limit = job.QueryActiveProcessLimit();
                Report(ref failures, limit == 8, "Job Object",
                    $"ActiveProcessLimit zurueckgelesen = {limit}");
            }
            catch (Exception ex) when (ex is Win32Exception or UnauthorizedAccessException)
            {
                Report(ref failures, false, "Job Object", ex.Message);
            }

            // --- Kernbeweis: Netzwerkgrenze ---------------------------------
            Console.WriteLine();
            Console.WriteLine("[cordon] Kernbeweis der Netzwerkgrenze:");
            Console.WriteLine(
                "  Fuer einen echten Nachweis muss ein Prozess im AppContainer einen Socket "
                + "zu oeffnen versuchen. Das kann dieser Prozess nicht stellvertretend tun.");
            Console.WriteLine(
                "  Verwenden Sie: cordon run --agent <id> -- Cordon.TestAgent --prove-boundary");
        }

        Console.WriteLine();
        Console.WriteLine(failures == 0
            ? "[cordon] doctor: keine blockierenden Probleme gefunden."
            : $"[cordon] doctor: {failures} Problem(e) gefunden.");

        return failures == 0 ? 0 : 1;
    }

    private static void Report(ref int failures, bool ok, string label, string detail)
    {
        Console.WriteLine(ok
            ? $"[ ok ] {label,-12}: {detail}"
            : $"[FAIL] {label,-12}: {detail}");

        if (!ok)
        {
            failures++;
        }
    }

    // =====================================================================
    // Dienst
    // =====================================================================

    private static int InstallService(string[] args)
    {
        var options = CommandLine.Parse(args);
        var binaryPath = options.Get("--bin") ?? Environment.ProcessPath;

        if (string.IsNullOrWhiteSpace(binaryPath))
        {
            Console.Error.WriteLine("Fehler: Pfad zum Cordon-Binary nicht ermittelbar. --bin setzen.");
            return 2;
        }

        if (!FileAcl.IsElevated())
        {
            Console.Error.WriteLine("Fehler: Die Dienstinstallation erfordert erhoehte Rechte.");
            return 1;
        }

        var binPath = $"\"{binaryPath}\" serve";
        var exitCode = RunSc(new[] { "create", CordonPaths.ServiceName, $"binPath= {binPath}", "start= auto" });

        if (exitCode != 0)
        {
            return exitCode;
        }

        _ = RunSc(new[] { "description", CordonPaths.ServiceName, "Cordon Control - Capability Gateway fuer KI-Agenten" });
        _ = RunSc(new[]
        {
            "failure", CordonPaths.ServiceName, "reset=", "86400", "actions=", "restart/5000/restart/5000/none",
        });

        Console.WriteLine($"[cordon] Dienst '{CordonPaths.ServiceName}' installiert.");
        Console.WriteLine("[cordon] Starten mit: sc.exe start CordonControl");
        return 0;
    }

    private static int UninstallService(string[] args)
    {
        if (!FileAcl.IsElevated())
        {
            Console.Error.WriteLine("Fehler: erfordert erhoehte Rechte.");
            return 1;
        }

        return RunSc(new[] { "delete", CordonPaths.ServiceName });
    }

    private static int RunSc(string[] arguments)
    {
        var startInfo = new ProcessStartInfo("sc.exe")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };

        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo);
        if (process is null)
        {
            Console.Error.WriteLine("sc.exe konnte nicht gestartet werden.");
            return 1;
        }

        var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        process.WaitForExit();

        Console.WriteLine(output.Trim());
        return process.ExitCode;
    }

    // =====================================================================
    // Hilfe
    // =====================================================================

    private static int PrintVersion()
    {
        Console.WriteLine("Cordon 0.1.0 (Iteration 1)");
        Console.WriteLine($"Protokollversion: {ProtocolVersion.Current}");
        Console.WriteLine($"Laufzeit        : {Environment.Version}");
        return 0;
    }

    private static int UnknownCommand(string command)
    {
        Console.Error.WriteLine($"Unbekanntes Kommando: {command}");
        Console.WriteLine();
        PrintUsage();
        return 2;
    }

    private static void PrintUsage()
    {
        Console.WriteLine("""
            Cordon - Capability-basiertes Agent Gateway fuer Windows

            VERWENDUNG
              cordon <kommando> [optionen]

            KERNKOMMANDOS
              init [--force] [--harden] [--with-interception-ca]
                  Legt Verzeichnisse, Audit-Schluessel und Beispiel-Policy an.
                  Ohne --harden werden keine ACLs gesetzt (nur fuer Entwicklung).

              serve [--policy <datei>] [--audit-dir <dir>] [--no-watch]
                    [--enable-interception] [--ca-dir <dir>]
                    [--connect-timeout <sekunden>] [--expected-image-root <pfad>]
                  Startet das Gateway. Laeuft als LocalSystem, wenn als Dienst
                  installiert. Ohne ladbare Policy wird NICHT gelauscht.

              run --agent <id> [--no-wfp] [--wfp-persistent] [--workdir <dir>]
                  [--max-processes <n>] [--max-process-memory-mb <n>]
                  [--max-job-memory-mb <n>] [--max-cpu-seconds <n>]
                  [--no-wait] -- <befehl> [argumente...]
                  Startet einen Agenten in AppContainer + Job Object.

            DIAGNOSE
              doctor [--agent <id>]        Umgebungs- und Grenzdiagnose
              scope show                   Aktive Policy im Klartext
              scope validate [datei]       Policy pruefen, ohne sie zu aktivieren
              scope check <agentId> <host> <port> [--method M --path P]
                                           Eine Regelentscheidung simulieren
              audit tail [--lines <n>]     Letzte Audit-Eintraege
              audit verify [--dir <dir>]   HMAC-Kette des Audits pruefen
              profile show|create|delete <agentId>
                                           AppContainer-Profile verwalten

            DIENST
              install-service [--bin <pfad>]
              uninstall-service

            SICHERHEITSKONZEPT (Kurzfassung)
              * Identitaet kommt aus dem Kernel (GetNamedPipeClientProcessId),
                nicht aus einem Header oder Token.
              * Der Agent laeuft in einem AppContainer OHNE Netzwerk-Capabilities.
                Der Kernel verweigert socket()/connect() - nicht der Proxy.
              * Alle Kindprozesse erben AppContainer und Job Object.
              * Standard ist TLS-Passthrough: Cordon sieht keinen Klartext.
                Interception ist Opt-In pro Ziel und nutzt eine lokale CA, die
                NICHT in den Windows-Trust-Store geschrieben wird.
              * Es gibt keinen 'permit all'-Fallback. Faellt die Policy aus,
                wird der Dienst beendet bzw. nicht gestartet.

            Siehe docs/ARCHITECTURE.md fuer Bedrohungsmodell und Grenzen.
            """);
    }
}
