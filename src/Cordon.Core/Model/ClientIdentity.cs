using System.Text.Json.Serialization;

namespace Cordon.Core.Model;

/// <summary>
/// Der Identitaetsvektor des Aufrufers. Alle Felder stammen aus
/// Kernel-Abfragen (Pipe-Claim + Token-Inspektion) und <b>niemals</b> aus
/// der Nutzlast des Agenten.
/// </summary>
public sealed record ClientIdentity
{
    /// <summary>PID aus <c>GetNamedPipeClientProcessId</c>.</summary>
    public required uint Pid { get; init; }

    /// <summary>Normalisierter Image-Pfad aus <c>QueryFullProcessImageNameW</c>.</summary>
    public required string ImagePath { get; init; }

    /// <summary>
    /// Erzeugungszeit des Prozesses als roher <c>FILETIME</c>-Wert.
    /// <para>
    /// Wird beim Verbindungsaufbau erfasst und bei der Aufloesung erneut
    /// geprueft. Weicht der Wert ab, wurde die PID zwischenzeitlich neu
    /// vergeben - die Aufloesung wird dann verworfen. Siehe
    /// <c>PipeClientSignature</c>.
    /// </para>
    /// </summary>
    public long ProcessCreationTime { get; init; }

    /// <summary>SHA-256 des Images, falls berechnet (optional, gecacht).</summary>
    public string? ImageSha256 { get; init; }

    /// <summary>Package-SID des AppContainers, z. B. <c>S-1-15-2-...</c>.</summary>
    public required string PackageSid { get; init; }

    public required bool IsAppContainer { get; init; }

    public required IntegrityLevel Integrity { get; init; }

    /// <summary>
    /// Capability-SIDs des Tokens. Muss fuer einen Agenten <b>leer</b> sein:
    /// jede Netzwerk-Capability hebt die primaere Grenze auf.
    /// </summary>
    public required IReadOnlyList<string> Capabilities { get; init; }

    /// <summary>Subject des Authenticode-Signierers, falls geprueft und vorhanden.</summary>
    public string? SignerSubject { get; init; }

    /// <summary>Der Agent-Id, der diese Pipe-Instanz exklusiv zugeordnet ist.</summary>
    public required string AgentId { get; init; }

    /// <summary>Erwartete Package-SID der Pipe-Instanz (zweite, unabhaengige Bindung).</summary>
    public required string ExpectedPackageSid { get; init; }

    /// <summary>Erwarteter Image-Pfad der Pipe-Instanz.</summary>
    public required string ExpectedImagePath { get; init; }

    /// <summary>Kurzform fuer Audit und Logging.</summary>
    public string Describe() =>
        $"pid={Pid} agent={AgentId} sid={PackageSid} integrity={Integrity} image={ImagePath}";
}

/// <summary>Das angeforderte Ziel, nach Normalisierung.</summary>
public sealed record ResourceTarget
{
    public required TargetKind Kind { get; init; }

    /// <summary>Normalisierter Host: IDN-ASCII, kleingeschrieben, ohne Trailing-Dot.</summary>
    public required string Host { get; init; }

    /// <summary>Der Original-String aus dem Frame. Nur fuer Audit.</summary>
    public required string RawHost { get; init; }

    public required int Port { get; init; }

    public string? Method { get; init; }

    public string? Path { get; init; }

    public string Describe() => $"{Host}:{Port}";
}

/// <summary>Ergebnis der Policy-Auswertung.</summary>
public sealed record PolicyDecision
{
    public required Verdict Verdict { get; init; }

    /// <summary>Gesetzt bei <see cref="Verdict.Allow"/>.</summary>
    public string? ScopeId { get; init; }

    /// <summary>Gesetzt bei <see cref="Verdict.Deny"/>.</summary>
    public string? Code { get; init; }

    public string? Reason { get; init; }

    public TlsMode Tls { get; init; } = TlsMode.Passthrough;

    /// <summary>Effektive Limits des matched Scope (bzw. konservative Defaults).</summary>
    public required ScopeLimits Limits { get; init; }

    /// <summary>Effektive HTTP-Regeln (nur bei Interception wirksam).</summary>
    public ScopeHttpRules? HttpRules { get; init; }

    public static PolicyDecision Deny(string code, string reason) => new()
    {
        Verdict = Verdict.Deny,
        Code = code,
        Reason = reason,
        Limits = ScopeLimits.ConservativeDefault,
    };
}

/// <summary>Ressourcenlimits eines Scopes. Job-Object-Limits kommen separat dazu.</summary>
public sealed record ScopeLimits
{
    public int MaxConcurrentConnections { get; init; } = 16;

    public long MaxBytesUp { get; init; } = 64L * 1024 * 1024;

    public long MaxBytesDown { get; init; } = 256L * 1024 * 1024;

    public int SessionTtlSeconds { get; init; } = 3600;

    /// <summary>Wird verwendet, wenn kein Scope greift (z. B. fuer Audit-Metadaten).</summary>
    public static ScopeLimits ConservativeDefault { get; } = new()
    {
        MaxConcurrentConnections = 0,
        MaxBytesUp = 0,
        MaxBytesDown = 0,
        SessionTtlSeconds = 0,
    };
}

/// <summary>HTTP-Regeln, nur nach Opt-In-TLS-Interception auswertbar.</summary>
public sealed record ScopeHttpRules
{
    // Wie in ScopeConfiguration.cs: die Liste darf auch nach dem
    // Deserialisieren nie null sein (siehe Kommentar dort).
    private readonly IReadOnlyList<string> _httpMethods = [];
    private readonly IReadOnlyList<string> _pathPrefixes = [];

    /// <summary>Leer = alle Methoden. Sonst exakter, case-insensitiver Vergleich.</summary>
    public IReadOnlyList<string> HttpMethods
    {
        get => _httpMethods;
        init => _httpMethods = value ?? [];
    }

    /// <summary>
    /// Präfixe auf dem Request-Pfad. Länge 0 = alle Pfade.
    /// Vergleich ist ordinal und case-sensitiv (Pfade sind case-sensitiv).
    /// </summary>
    public IReadOnlyList<string> PathPrefixes
    {
        get => _pathPrefixes;
        init => _pathPrefixes = value ?? [];
    }
}
