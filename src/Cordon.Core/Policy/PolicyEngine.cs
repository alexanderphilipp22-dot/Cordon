using Cordon.Core.Model;

namespace Cordon.Core.Policy;

/// <summary>Ergebnis des Policy-Ladens. Fehler sind immer fatal.</summary>
public sealed record PolicyLoadResult(CompiledPolicy? Policy, IReadOnlyList<string> Errors)
{
    public bool Success => Policy is not null && Errors.Count == 0;
}

/// <summary>Ein kompilierter, unveraenderlicher Regelsatz.</summary>
public sealed class CompiledPolicy
{
    internal CompiledPolicy(ScopeConfiguration configuration, IReadOnlyList<CompiledScope> scopes)
    {
        Configuration = configuration;
        Scopes = scopes;
    }

    public ScopeConfiguration Configuration { get; }

    public IReadOnlyList<CompiledScope> Scopes { get; }

    public int ScopeCount => Scopes.Count;
}

/// <summary>Ein Scope mit vorkompilierten Matchern.</summary>
public sealed class CompiledScope
{
    internal CompiledScope(ScopeGrant grant, HostRuleSet targets, HostRuleSet intercept)
    {
        Grant = grant;
        Targets = targets;
        Intercept = intercept;
    }

    public ScopeGrant Grant { get; }

    public HostRuleSet Targets { get; }

    /// <summary>Ziele, fuer die TLS-Interception erlaubt ist (leer = keine).</summary>
    public HostRuleSet Intercept { get; }
}

/// <summary>Der Policy Decision Point.</summary>
public static class PolicyEngine
{
    /// <summary>
    /// Kompiliert und validiert eine Konfiguration. Schluckt keine Fehler:
    /// ein einziger ungueltiger Scope verhindert das Laden der ganzen Datei.
    /// Ein Teil-Load waere ein Sicherheitsproblem, weil er Regeln still
    /// verschwinden liesse.
    /// </summary>
    public static PolicyLoadResult Compile(ScopeConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        var errors = new List<string>();

        if (!PolicyValidator.TryValidate(configuration, out var validationErrors))
        {
            errors.AddRange(validationErrors);
        }

        if (errors.Count > 0)
        {
            return new PolicyLoadResult(null, errors);
        }

        var compiled = new List<CompiledScope>(configuration.Scopes.Count);

        foreach (var scope in configuration.Scopes)
        {
            if (!HostRuleSet.TryCompile(scope.Targets.Select(t => t.Host), out var targetSet, out var targetError)
                || targetSet is null)
            {
                errors.Add($"Scope '{scope.Id}': {targetError}");
                continue;
            }

            if (!HostRuleSet.TryCompile(
                    scope.Inspection.InterceptAllowlist,
                    out var interceptSet,
                    out var interceptError)
                || interceptSet is null)
            {
                errors.Add($"Scope '{scope.Id}': interceptAllowlist - {interceptError}");
                continue;
            }

            compiled.Add(new CompiledScope(scope, targetSet, interceptSet));
        }

        return errors.Count > 0
            ? new PolicyLoadResult(null, errors)
            : new PolicyLoadResult(new CompiledPolicy(configuration, compiled), errors);
    }

    /// <summary>
    /// Wertet eine Anfrage aus. Der Zielhost muss bereits normalisiert sein -
    /// die Normalisierung ist Teil des Entscheidungswegs und darf nicht
    /// umgangen werden (siehe <see cref="NormalizeTarget"/>).
    /// </summary>
    public static PolicyDecision Evaluate(
        CompiledPolicy policy,
        ClientIdentity identity,
        NormalizedHost host,
        int port,
        TargetKind kind,
        string? method = null,
        string? path = null)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(host);

        var portCheck = TargetGate.CheckPort(port);
        if (!portCheck.Allowed)
        {
            return PolicyDecision.Deny(portCheck.Code, portCheck.Reason);
        }

        var hostCheck = TargetGate.CheckHost(host, policy.Configuration);
        if (!hostCheck.Allowed)
        {
            return PolicyDecision.Deny(hostCheck.Code, hostCheck.Reason);
        }

        foreach (var scope in policy.Scopes)
        {
            if (!PrincipalMatches(scope.Grant.Principals, identity))
            {
                continue;
            }

            if (!PortAllowed(scope.Grant, port))
            {
                continue;
            }

            if (!scope.Targets.Matches(host))
            {
                continue;
            }

            var tls = ResolveTlsMode(scope, host);
            var decision = new PolicyDecision
            {
                Verdict = Verdict.Allow,
                ScopeId = scope.Grant.Id,
                Tls = tls,
                Limits = scope.Grant.Limits,
                HttpRules = scope.Grant.Rules,
            };

            if (kind == TargetKind.Http)
            {
                var httpCheck = CheckHttpRules(scope.Grant.Rules, method, path);
                if (!httpCheck.Allowed)
                {
                    return PolicyDecision.Deny(httpCheck.Code, httpCheck.Reason) with
                    {
                        ScopeId = scope.Grant.Id,
                    };
                }
            }

            return decision with { Reason = $"Grant '{scope.Grant.Id}'." };
        }

        // Kein Grant. Die Begruendung wird bewusst angereichert, weil ein
        // reines "no_scope" im Audit nicht diagnostizierbar ist.
        return PolicyDecision.Deny(
            DenyCodes.NoScope,
            $"Kein Scope erlaubt agent='{identity.AgentId}' image='{identity.ImagePath}' "
            + $"auf {host.Value}:{port} ({kind}).");
    }

    /// <summary>
    /// Interception ist niemals implizit: sie greift nur, wenn der Scope
    /// sie aktiviert <b>und</b> der Zielhost explizit in der
    /// interceptAllowlist steht. Sonst faellt Cordon auf Passthrough zurueck.
    /// </summary>
    public static TlsMode ResolveTlsMode(CompiledScope scope, NormalizedHost host)
    {
        ArgumentNullException.ThrowIfNull(scope);

        if (scope.Grant.Inspection.Tls != TlsMode.Intercept)
        {
            return TlsMode.Passthrough;
        }

        return scope.Intercept.Matches(host) ? TlsMode.Intercept : TlsMode.Passthrough;
    }

    private static bool PortAllowed(ScopeGrant grant, int port)
    {
        foreach (var target in grant.Targets)
        {
            foreach (var candidate in target.Ports)
            {
                if (candidate == port)
                {
                    return true;
                }
            }
        }

        return false;
    }

    /// <summary>
    /// Prueft, ob ein Principal zu einer Identitaet passt. Jede gesetzte
    /// Bedingung muss erfuellt sein (UND-Verknuepfung). Eine leere
    /// Bedingungsliste wird hier nicht als Wildcard behandelt; dass sie
    /// insgesamt leer ist, hat der Validator bereits abgelehnt.
    /// </summary>
    public static bool PrincipalMatches(ScopePrincipal principals, ClientIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(principals);
        ArgumentNullException.ThrowIfNull(identity);

        if (principals.AgentIds.Count > 0)
        {
            var matched = false;
            foreach (var agentId in principals.AgentIds)
            {
                if (string.Equals(agentId, identity.AgentId, StringComparison.OrdinalIgnoreCase))
                {
                    matched = true;
                    break;
                }
            }

            if (!matched)
            {
                return false;
            }
        }

        if (principals.PackageSids.Count > 0)
        {
            var matched = false;
            foreach (var sid in principals.PackageSids)
            {
                if (string.Equals(sid, identity.PackageSid, StringComparison.OrdinalIgnoreCase))
                {
                    matched = true;
                    break;
                }
            }

            if (!matched)
            {
                return false;
            }
        }

        if (principals.ImageRoots.Count > 0)
        {
            var matched = false;
            foreach (var root in principals.ImageRoots)
            {
                if (PathStartsWith(identity.ImagePath, root))
                {
                    matched = true;
                    break;
                }
            }

            if (!matched)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Praefix-Vergleich auf Pfaden mit erzwungener Verzeichnisgrenze.
    /// <para>
    /// Ohne die Grenze wuerde <c>C:\Agents\res</c> auch
    /// <c>C:\Agents\research-evil\agent.exe</c> erfassen - ein klassischer
    /// Praefix-Bug, der einen Grant auf einen fremden Agenten ausdehnt.
    /// </para>
    /// </summary>
    public static bool PathStartsWith(string? path, string root)
    {
        if (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(root))
        {
            return false;
        }

        var normalizedPath = path.Replace('/', '\\').TrimEnd('\\');
        var normalizedRoot = root.Replace('/', '\\').TrimEnd('\\');

        if (!normalizedPath.StartsWith(normalizedRoot, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (normalizedPath.Length == normalizedRoot.Length)
        {
            return true;
        }

        return normalizedPath[normalizedRoot.Length] == '\\';
    }

    private static GateResult CheckHttpRules(ScopeHttpRules rules, string? method, string? path)
    {
        ArgumentNullException.ThrowIfNull(rules);

        if (rules.HttpMethods.Count > 0)
        {
            if (string.IsNullOrEmpty(method))
            {
                return GateResult.Deny(DenyCodes.MethodNotAllowed, "Keine HTTP-Methode im Request.");
            }

            var matched = false;
            foreach (var candidate in rules.HttpMethods)
            {
                if (string.Equals(candidate, method, StringComparison.OrdinalIgnoreCase))
                {
                    matched = true;
                    break;
                }
            }

            if (!matched)
            {
                return GateResult.Deny(
                    DenyCodes.MethodNotAllowed,
                    $"Methode '{method}' ist nicht erlaubt.");
            }
        }

        if (rules.PathPrefixes.Count > 0)
        {
            if (string.IsNullOrEmpty(path))
            {
                return GateResult.Deny(DenyCodes.PathNotAllowed, "Kein Pfad im Request.");
            }

            var matched = false;
            foreach (var prefix in rules.PathPrefixes)
            {
                // Pfade sind case-sensitiv (RFC 3986) - ordinal vergleichen.
                if (path.StartsWith(prefix, StringComparison.Ordinal))
                {
                    matched = true;
                    break;
                }
            }

            if (!matched)
            {
                return GateResult.Deny(
                    DenyCodes.PathNotAllowed,
                    $"Pfad '{path}' liegt in keinem erlaubten Praefix.");
            }
        }

        return GateResult.Allow();
    }

    /// <summary>
    /// Normalisiert einen Rohhost aus einem Frame. Bündelt die Schritte,
    /// damit kein Aufrufer die Normalisierung versehentlich ueberspringt.
    /// </summary>
    public static NormalizedHost NormalizeTarget(string? rawHost) => HostNormalizer.Normalize(rawHost);
}
