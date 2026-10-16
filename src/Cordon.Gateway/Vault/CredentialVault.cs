using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;

namespace Cordon.Gateway.Vault;

/// <summary>Ein im Speicher gehaltenes Geheimnis für genau eine Ziel-Domäne.</summary>
public sealed record VaultSecret(string Domain, string HeaderName, string HeaderValue)
{
    /// <summary>Der Klartext darf niemals in Logs oder Audits erscheinen.</summary>
    public override string ToString() => $"VaultSecret({Domain}, {HeaderName}, ***)";
}

/// <summary>
/// In-Memory Credential Vault.
/// <para>
/// Hält API-Secrets (GitHub, OpenAI, …) ausserhalb des AppContainer-Prozesses,
/// damit ein kompromittierter Agent sie weder aus seiner <c>.env</c> noch aus
/// seinem Speicher lesen kann. Die Injektion erfolgt ausschliesslich im
/// Gateway-Prozess und nur bei exakt passender Ziel-Domäne.
/// </para>
/// </summary>
public sealed class CredentialVault
{
    private readonly ConcurrentDictionary<string, VaultSecret> _secrets = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Registriert ein Geheimnis für eine Ziel-Domäne.</summary>
    public void Register(string domain, string headerName, string headerValue)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        ArgumentException.ThrowIfNullOrWhiteSpace(headerName);
        ArgumentException.ThrowIfNullOrWhiteSpace(headerValue);

        var normalized = NormalizeDomain(domain);
        if (normalized.Length == 0)
        {
            throw new ArgumentException("Domäne besteht nur aus Punkten.", nameof(domain));
        }

        // CRLF-/Header-Injection verhindern: der Header-Name muss ein gueltiger
        // RFC-7230-Token sein, der Wert darf keine Zeilenumbrueche oder
        // Steuerzeichen enthalten.
        var trimmedHeaderName = headerName.Trim();
        ValidateHeaderName(trimmedHeaderName);
        ValidateHeaderValue(headerValue);

        _secrets[normalized] = new VaultSecret(normalized, trimmedHeaderName, headerValue);
    }

    /// <summary>
    /// Löst ein Geheimnis für einen Ziel-Host auf. Der Vergleich ist exakt und
    /// case-insensitiv; es gibt bewusst keine Wildcard-Auflösung, damit ein
    /// Secret nicht versehentlich an eine verwandte Domäne fliesst.
    /// </summary>
    public bool TryResolve(string host, [NotNullWhen(true)] out VaultSecret? secret)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            secret = null;
            return false;
        }

        return _secrets.TryGetValue(NormalizeDomain(host), out secret);
    }

    /// <summary>Anzahl der verwalteten Geheimnisse.</summary>
    public int Count => _secrets.Count;

    /// <summary>Die verwalteten Domänen (normalisiert, klein geschrieben).</summary>
    public IReadOnlyCollection<string> Domains => _secrets.Keys.ToArray();

    private static void ValidateHeaderName(string headerName)
    {
        if (headerName.Length == 0 || headerName.Any(c => !IsTokenChar(c)))
        {
            throw new ArgumentException($"Ungueltiger Header-Name '{headerName}'.", nameof(headerName));
        }
    }

    private static void ValidateHeaderValue(string headerValue)
    {
        foreach (var c in headerValue)
        {
            if (c == '\r' || c == '\n' || (c < ' ' && c != '\t') || c == '\u007f')
            {
                throw new ArgumentException(
                    "Header-Wert enthaelt unzulaessige Steuerzeichen.",
                    nameof(headerValue));
            }
        }
    }

    private static bool IsTokenChar(char c) =>
        char.IsAsciiLetterOrDigit(c)
        || c is '!' or '#' or '$' or '%' or '&' or '\'' or '*' or '+'
            or '-' or '.' or '^' or '_' or '`' or '|' or '~';

    private static string NormalizeDomain(string domain) =>
        domain.Trim().TrimEnd('.').ToLowerInvariant();
}

/// <summary>
/// Injiziert Vault-Header in ausgehende Requests. Wird ausschliesslich im
/// Gateway-Proxy-Layer (Interception-Pfad) aufgerufen, wo Cordon den
/// HTTP-Request sieht.
/// </summary>
public static class VaultHeaderInjector
{
    /// <summary>
    /// Injiziert den passenden Auth-Header, wenn für den Host ein Geheimnis
    /// registriert ist. Gibt <c>true</c> zurück, wenn injiziert wurde.
    /// </summary>
    public static bool TryInject(IDictionary<string, string> headers, string host, CredentialVault vault)
    {
        ArgumentNullException.ThrowIfNull(headers);
        ArgumentNullException.ThrowIfNull(vault);

        if (!vault.TryResolve(host, out var secret) || secret is null)
        {
            return false;
        }

        // Bewusst überschreiben: der Agent darf keinen eigenen, selbst
        // gewählten Authorization-Header für eine verwaltete Domäne durchsetzen.
        headers[secret.HeaderName] = secret.HeaderValue;
        return true;
    }
}
