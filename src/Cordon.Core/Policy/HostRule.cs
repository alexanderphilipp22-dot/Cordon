using Cordon.Core.Model;

namespace Cordon.Core.Policy;

/// <summary>
/// Ein kompiliertes Zielhost-Muster.
/// <para>Unterstuetzte Formen:</para>
/// <list type="bullet">
/// <item><c>api.example.com</c> — exakter DNS-Name</item>
/// <item><c>*.example.com</c> — Subdomain, <b>nicht</b> der Apex</item>
/// <item><c>203.0.113.7</c> — exaktes IP-Literal</item>
/// <item><c>10.0.4.0/24</c> — CIDR-Bereich</item>
/// </list>
/// <para>
/// <c>*</c> allein ist verboten. Ein Muster, das den Apex mitmeint, muss
/// ausgeschrieben werden (<c>example.com</c> <i>und</i> <c>*.example.com</c>).
/// Diese Strenge ist Absicht: die klassische Wildcard-Verwechslung ist eine
/// der haeufigsten Ursachen fuer zu weite Netzwerk-Grants.
/// </para>
/// </summary>
public sealed class HostRule
{
    private readonly string? _exact;
    private readonly string? _wildcardSuffix;
    private readonly Cidr? _cidr;

    private HostRule(string source, RuleKind kind, string? exact, string? wildcardSuffix, Cidr? cidr)
    {
        Source = source;
        Kind = kind;
        _exact = exact;
        _wildcardSuffix = wildcardSuffix;
        _cidr = cidr;
    }

    public string Source { get; }

    public RuleKind Kind { get; }

    /// <summary>
    /// Die normalisierte Vergleichsform: ASCII/lowercase DNS-Name,
    /// kanonisiertes IP-Literal bzw. der CIDR-Text. <c>null</c> nur bei
    /// Wildcards, die ueber <see cref="WildcardSuffix"/> verglichen werden.
    /// </summary>
    public string? NormalizedValue { get; private init; }

    /// <summary>
    /// Suffix inklusive fuehrendem Punkt (z. B. <c>.example.com</c>).
    /// Nur bei <see cref="RuleKind.WildcardSubdomain"/> gesetzt.
    /// </summary>
    public string? WildcardSuffix { get; private init; }

    /// <summary>
    /// Kompiliert ein Muster. Gibt bei ungueltigem Muster <c>false</c> zurueck;
    /// der Aufrufer lehnt die Konfiguration dann ab (fail closed).
    /// </summary>
    public static bool TryCompile(string? pattern, out HostRule? rule, out string? error)
    {
        rule = null;
        error = null;

        if (string.IsNullOrWhiteSpace(pattern))
        {
            error = "Hostmuster ist leer.";
            return false;
        }

        var value = pattern.Trim();

        if (value == "*")
        {
            error = "'*' als alleiniges Hostmuster ist verboten. Ziele muessen explizit sein.";
            return false;
        }

        // CIDR?
        if (value.Contains('/', StringComparison.Ordinal))
        {
            if (!Cidr.TryParse(value, out var cidr) || cidr is null)
            {
                error = $"'{pattern}' ist kein gueltiger CIDR-Bereich.";
                return false;
            }

            rule = new HostRule(value, RuleKind.Cidr, null, null, cidr)
            {
                NormalizedValue = cidr.Text,
            };
            return true;
        }

        // Wildcard?
        if (value.StartsWith("*.", StringComparison.Ordinal))
        {
            var suffix = value[2..];
            if (suffix.Length == 0 || suffix.Contains('*', StringComparison.Ordinal))
            {
                error = $"'{pattern}' ist ein ungueltiges Wildcard-Muster.";
                return false;
            }

            var normalizedSuffix = HostNormalizer.Normalize(suffix);
            if (!normalizedSuffix.IsValid)
            {
                error = $"'{pattern}': Suffix ungueltig - {normalizedSuffix.Error}";
                return false;
            }

            if (normalizedSuffix.Form != HostForm.DnsName)
            {
                error = $"'{pattern}': Wildcards auf IP-Literalen sind nicht zulaessig. Nutzen Sie CIDR.";
                return false;
            }

            var suffixPattern = "." + normalizedSuffix.Value;
            rule = new HostRule(value, RuleKind.WildcardSubdomain, null, suffixPattern, null)
            {
                WildcardSuffix = suffixPattern,
            };
            return true;
        }

        if (value.Contains('*', StringComparison.Ordinal))
        {
            error = $"'{pattern}': '*' ist nur als fuehrendes '*.' zulaessig.";
            return false;
        }

        var normalized = HostNormalizer.Normalize(value);
        if (!normalized.IsValid)
        {
            error = $"'{pattern}': {normalized.Error}";
            return false;
        }

        // Vergleichsform: bei DNS der normalisierte Name, bei IP das
        // kanonisierte Literal (damit "::1" und "0:0:0:0:0:0:0:1" gleich sind).
        var comparison = normalized.Form == HostForm.IpLiteral
            ? normalized.Address!.ToString()
            : normalized.Value;

        rule = new HostRule(
            value,
            normalized.Form == HostForm.IpLiteral ? RuleKind.ExactIp : RuleKind.ExactDns,
            comparison,
            null,
            null)
        {
            NormalizedValue = comparison,
        };

        return true;
    }

    /// <summary>Prueft einen bereits normalisierten Host.</summary>
    public bool Matches(NormalizedHost host)
    {
        ArgumentNullException.ThrowIfNull(host);
        if (!host.IsValid)
        {
            return false;
        }

        return Kind switch
        {
            RuleKind.ExactDns => host.Form == HostForm.DnsName
                && string.Equals(host.Value, _exact, StringComparison.Ordinal),

            // Bewusst NICHT der Apex: "*.example.com" matcht
            // "a.example.com", aber nicht "example.com".
            RuleKind.WildcardSubdomain => host.Form == HostForm.DnsName
                && host.Value.Length > _wildcardSuffix!.Length
                && host.Value.EndsWith(_wildcardSuffix, StringComparison.Ordinal),

            RuleKind.ExactIp => host.Form == HostForm.IpLiteral
                && host.Address is not null
                && _exact is not null
                && NormalizeIp(host.Address) == _exact,

            RuleKind.Cidr => host.Form == HostForm.IpLiteral
                && host.Address is not null
                && _cidr!.Contains(host.Address),

            _ => false,
        };
    }

    /// <summary>
    /// Normalisiert ein IP-Literal zur Vergleichsform. Wichtig, weil
    /// <c>::1</c> und <c>0:0:0:0:0:0:0:1</c> dieselbe Adresse sind, aber
    /// als String verschieden.
    /// </summary>
    private static string NormalizeIp(System.Net.IPAddress address) => address.ToString();

    public enum RuleKind
    {
        ExactDns = 0,
        WildcardSubdomain = 1,
        ExactIp = 2,
        Cidr = 3,
    }
}

/// <summary>
/// Eine kompilierte, unveraenderliche Menge von Hostmustern.
/// <para>
/// Die Muster werden nach Form indiziert, damit ein Match in der Regel ein
/// Hash-Lookup ist und nicht ein Durchlauf ueber alle Regeln. Das ist nicht
/// nur Performance: eine indizierte Struktur macht es schwerer, versehentlich
/// eine Regel zu uebersehen.
/// </para>
/// </summary>
public sealed class HostRuleSet
{
    private readonly Dictionary<string, HostRule> _exactDns = new(StringComparer.Ordinal);
    private readonly Dictionary<string, HostRule> _wildcardSuffix = new(StringComparer.Ordinal);
    private readonly Dictionary<string, HostRule> _exactIp = new(StringComparer.Ordinal);
    private readonly List<HostRule> _cidrs = [];

    private HostRuleSet()
    {
    }

    public int Count => _exactDns.Count + _wildcardSuffix.Count + _exactIp.Count + _cidrs.Count;

    /// <summary>
    /// Kompiliert Muster. Bei einem ungueltigen Muster gibt es <c>false</c> -
    /// die Konfiguration wird dann als Ganzes abgelehnt.
    /// </summary>
    public static bool TryCompile(
        IEnumerable<string> patterns,
        out HostRuleSet? set,
        out string? error)
    {
        ArgumentNullException.ThrowIfNull(patterns);
        set = null;
        error = null;

        var result = new HostRuleSet();

        foreach (var pattern in patterns)
        {
            if (!HostRule.TryCompile(pattern, out var rule, out var ruleError) || rule is null)
            {
                error = ruleError;
                return false;
            }

            switch (rule.Kind)
            {
                case HostRule.RuleKind.ExactDns:
                    result._exactDns[ExtractExact(rule)] = rule;
                    break;

                case HostRule.RuleKind.WildcardSubdomain:
                    result._wildcardSuffix[ExtractSuffix(rule)] = rule;
                    break;

                case HostRule.RuleKind.ExactIp:
                    result._exactIp[ExtractExact(rule)] = rule;
                    break;

                case HostRule.RuleKind.Cidr:
                    result._cidrs.Add(rule);
                    break;

                default:
                    error = $"Unbekannte Regelart fuer '{pattern}'.";
                    return false;
            }
        }

        set = result;
        return true;
    }

    /// <summary>Wahr, wenn irgendein Muster passt. Der Aufrufer unterscheidet
    /// nicht, welches - fuer Audit wird das konkrete Muster mitgegeben.</summary>
    public bool Matches(NormalizedHost host, out string? matchedPattern)
    {
        matchedPattern = null;
        if (!host.IsValid)
        {
            return false;
        }

        if (host.Form == HostForm.DnsName)
        {
            if (_exactDns.TryGetValue(host.Value, out var exact))
            {
                matchedPattern = exact.Source;
                return true;
            }

            // Wildcard von rechts: fuer "a.b.example.com" werden
            // ".b.example.com" und ".example.com" geprueft. Der fuehrende
            // Punkt erzwingt eine Label-Grenze, sodass "notexample.com"
            // niemals gegen ".example.com" matcht. Der Apex selbst hat kein
            // Label davor und passt daher bewusst nicht.
            var dot = host.Value.LastIndexOf('.');
            while (dot > 0)
            {
                var suffix = host.Value[dot..];
                if (_wildcardSuffix.TryGetValue(suffix, out var wildcard))
                {
                    matchedPattern = wildcard.Source;
                    return true;
                }

                dot = host.Value.LastIndexOf('.', dot - 1);
            }

            return false;
        }

        if (host.Address is null)
        {
            return false;
        }

        var ipText = host.Address.ToString();
        if (_exactIp.TryGetValue(ipText, out var exactIp))
        {
            matchedPattern = exactIp.Source;
            return true;
        }

        foreach (var cidr in _cidrs)
        {
            if (cidr.Matches(host))
            {
                matchedPattern = cidr.Source;
                return true;
            }
        }

        return false;
    }

    public bool Matches(NormalizedHost host) => Matches(host, out _);

    private static string ExtractExact(HostRule rule)
    {
        // Vergleichsform stammt aus der Normalisierung im HostRule selbst -
        // hier wird nichts neu abgeleitet, damit Index und Matcher nicht
        // auseinanderlaufen koennen.
        return rule.NormalizedValue
            ?? throw new InvalidOperationException($"Regel '{rule.Source}' hat keinen normalisierten Wert.");
    }

    private static string ExtractSuffix(HostRule rule) =>
        rule.WildcardSuffix
        ?? throw new InvalidOperationException($"Wildcard-Regel '{rule.Source}' hat kein Suffix.");
}

/// <summary>
/// Validiert eine gesamte Policy-Datei. Jede Unsicherheit fuehrt dazu, dass
/// die Konfiguration <b>nicht</b> geladen wird - es gibt keinen Teil-Load und
/// keinen "permit all"-Fallback.
/// </summary>
public static class PolicyValidator
{
    public static bool TryValidate(ScopeConfiguration configuration, out IReadOnlyList<string> errors)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        var problems = new List<string>();

        if (configuration.Version != 1)
        {
            problems.Add($"Unbekannte Policy-Version {configuration.Version}; erwartet wird 1.");
        }

        if (configuration.DefaultVerdict != Verdict.Deny)
        {
            problems.Add("defaultVerdict muss 'deny' sein. Ein Default-Allow ist nicht zulaessig.");
        }

        if (configuration.RequireSignature && configuration.AllowedSigners.Count == 0)
        {
            problems.Add(
                "requireSignature=true erzwingt mindestens einen Eintrag in allowedSigners. "
                + "Eine leere Whitelist wuerde jede Signatur ablehnen und ist als "
                + "Konfigurationsfehler zu behandeln (fail closed beim Laden).");
        }

        var seenIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var scope in configuration.Scopes)
        {
            var label = string.IsNullOrWhiteSpace(scope.Id) ? "<ohne id>" : scope.Id;

            if (string.IsNullOrWhiteSpace(scope.Id))
            {
                problems.Add("Ein Scope hat keine Id.");
            }
            else if (!seenIds.Add(scope.Id))
            {
                problems.Add($"Doppelte Scope-Id '{scope.Id}'.");
            }

            if (scope.Principals.AgentIds.Count == 0
                && scope.Principals.ImageRoots.Count == 0
                && scope.Principals.PackageSids.Count == 0)
            {
                problems.Add($"Scope '{label}': principals ist leer. Ein Grant ohne Principal waere ein Wildcard.");
            }

            foreach (var agentId in scope.Principals.AgentIds)
            {
                try
                {
                    _ = Protocol.ProtocolVersion.Sanitize(agentId);
                }
                catch (ArgumentException ex)
                {
                    problems.Add($"Scope '{label}': unzulaessige agentId '{agentId}' - {ex.Message}");
                }
            }

            foreach (var root in scope.Principals.ImageRoots)
            {
                if (string.IsNullOrWhiteSpace(root) || !Path.IsPathFullyQualified(root))
                {
                    problems.Add($"Scope '{label}': imageRoot '{root}' muss ein absoluter Pfad sein.");
                }
            }

            if (scope.Targets.Count == 0)
            {
                problems.Add($"Scope '{label}': targets ist leer.");
            }

            foreach (var target in scope.Targets)
            {
                if (!HostRule.TryCompile(target.Host, out _, out var hostError))
                {
                    problems.Add($"Scope '{label}': {hostError}");
                }

                if (target.Ports.Count == 0)
                {
                    problems.Add($"Scope '{label}': Ziel '{target.Host}' hat keine Ports.");
                }

                foreach (var port in target.Ports)
                {
                    if (port is < 1 or > 65535)
                    {
                        problems.Add($"Scope '{label}': Port {port} ist ausserhalb 1..65535.");
                    }
                }
            }

            if (scope.Inspection.Tls == TlsMode.Intercept)
            {
                if (scope.Inspection.InterceptAllowlist.Count == 0)
                {
                    problems.Add(
                        $"Scope '{label}': tls=intercept ohne interceptAllowlist. "
                        + "Interception muss explizit auf Ziele begrenzt werden.");
                }

                foreach (var allowed in scope.Inspection.InterceptAllowlist)
                {
                    if (!HostRule.TryCompile(allowed, out _, out var interceptError))
                    {
                        problems.Add($"Scope '{label}': interceptAllowlist - {interceptError}");
                    }
                }
            }

            if (scope.Limits.MaxConcurrentConnections < 1)
            {
                problems.Add($"Scope '{label}': maxConcurrentConnections muss >= 1 sein.");
            }

            if (scope.Limits.MaxBytesUp < 0 || scope.Limits.MaxBytesDown < 0)
            {
                problems.Add($"Scope '{label}': Byte-Limits duerfen nicht negativ sein.");
            }

            if (scope.Limits.SessionTtlSeconds < 1)
            {
                problems.Add($"Scope '{label}': sessionTtlSeconds muss >= 1 sein.");
            }

            foreach (var tool in scope.AllowedTools)
            {
                if (string.IsNullOrWhiteSpace(tool))
                {
                    problems.Add($"Scope '{label}': allowedTools enthaelt einen leeren Toolnamen.");
                }
            }
        }

        errors = problems;
        return problems.Count == 0;
    }
}
