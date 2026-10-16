using System.Text.Json.Serialization;

namespace Cordon.Core.Model;

// ---------------------------------------------------------------------------
// Zusicherung dieser Datei: Sammlungen und eingebettete Objekte sind niemals
// null - auch nicht nach dem Deserialisieren einer unvollstaendigen oder
// manipulierten JSON-Datei.
//
// Grund: Der System.Text.Json-Source-Generator erzeugt fuer `init`-only
// Properties keinen Objekt-Creator, sondern einen parameterisierten Creator
// (ObjectCreator = null). Fehlt ein Schluessel im JSON, uebergibt er fuer
// diesen Parameter `default` - bei einem Referenztyp also `null` - und
// ueberschreibt damit den Initialisierer `= []`. Ein weggelassenes
// "allowedTools" brachte so eine null-Liste in den Entscheidungsweg
// (NullReferenceException statt "leere Liste = fail closed").
//
// Ein `init`-Accessor mit Rueckfallwert haelt die Zusicherung dort, wo sie
// deklariert ist - also fuer jeden JSON-Konsumenten, nicht nur fuer den
// Policy-Loader.
// ---------------------------------------------------------------------------

/// <summary>
/// Wurzel der Policy-Datei (<c>%ProgramData%\Cordon\config\scopes.json</c>).
/// </summary>
public sealed record ScopeConfiguration
{
    private readonly IReadOnlyList<string> _allowedCapabilities = [];
    private readonly IReadOnlyList<string> _allowedSigners = [];
    private readonly IReadOnlyList<ScopeGrant> _scopes = [];

    public int Version { get; init; } = 1;

    /// <summary>
    /// Immer <see cref="Verdict.Deny"/>. Das Feld existiert nur, damit ein
    /// versehentlich auf "allow" gesetzter Default beim Laden abgelehnt wird.
    /// </summary>
    public Verdict DefaultVerdict { get; init; } = Verdict.Deny;

    /// <summary>
    /// Erlaubt Zielen im Loopback-/Link-Local-Bereich. Global abschaltbar
    /// gelassen, weil das der wahrscheinlichste SSRF-Eskalationspfad ist.
    /// </summary>
    public bool AllowLoopback { get; init; }

    public bool AllowLinkLocal { get; init; }

    /// <summary>Erzwingt eine gueltige Authenticode-Signatur des Agent-Images.</summary>
    public bool RequireSignature { get; init; }

    /// <summary>Capabilities, die im Agent-Token erlaubt sind. Default: keine.</summary>
    public IReadOnlyList<string> AllowedCapabilities
    {
        get => _allowedCapabilities;
        init => _allowedCapabilities = value ?? [];
    }

    /// <summary>
    /// Wenn <see cref="RequireSignature"/> aktiv ist, muss der aus dem
    /// Zertifikat gelesene Signer-Subject in dieser Liste stehen. Leer =
    /// es wird <b>nichts</b> zugelassen (fail closed). Das Laden der Policy
    /// erzwingt bei <c>requireSignature=true</c> mindestens einen Eintrag.
    /// </summary>
    public IReadOnlyList<string> AllowedSigners
    {
        get => _allowedSigners;
        init => _allowedSigners = value ?? [];
    }

    public IReadOnlyList<ScopeGrant> Scopes
    {
        get => _scopes;
        init => _scopes = value ?? [];
    }
}

/// <summary>Ein Capability-Grant: Principal ∧ Ziel ⇒ Erlaubnis.</summary>
public sealed record ScopeGrant
{
    private readonly ScopePrincipal _principals = new();
    private readonly IReadOnlyList<ScopeTarget> _targets = [];
    private readonly ScopeInspection _inspection = new();
    private readonly ScopeLimits _limits = new();
    private readonly ScopeHttpRules _rules = new();
    private readonly IReadOnlyList<string> _allowedTools = [];

    public required string Id { get; init; }

    public string? Description { get; init; }

    public required ScopePrincipal Principals
    {
        get => _principals;
        init => _principals = value ?? new();
    }

    public required IReadOnlyList<ScopeTarget> Targets
    {
        get => _targets;
        init => _targets = value ?? [];
    }

    public ScopeInspection Inspection
    {
        get => _inspection;
        init => _inspection = value ?? new();
    }

    public ScopeLimits Limits
    {
        get => _limits;
        init => _limits = value ?? new();
    }

    public ScopeHttpRules Rules
    {
        get => _rules;
        init => _rules = value ?? new();
    }

    /// <summary>
    /// Erlaubte MCP-/JSON-Toolnamen (z. B. "read_file", "search_code").
    /// Leer = keine Toolaufrufe erlaubt (fail closed).
    /// </summary>
    public IReadOnlyList<string> AllowedTools
    {
        get => _allowedTools;
        init => _allowedTools = value ?? [];
    }
}

/// <summary>
/// Wer darf den Grant nutzen. <b>Alle</b> gesetzten Bedingungen muessen
/// erfuellt sein; eine leere Bedingung ist kein Wildcard, sondern wird beim
/// Laden als Konfigurationsfehler behandelt.
/// </summary>
public sealed record ScopePrincipal
{
    private readonly IReadOnlyList<string> _agentIds = [];
    private readonly IReadOnlyList<string> _imageRoots = [];
    private readonly IReadOnlyList<string> _packageSids = [];

    /// <summary>Agent-Ids (Pipe-Instanzen), fuer die der Grant gilt.</summary>
    public IReadOnlyList<string> AgentIds
    {
        get => _agentIds;
        init => _agentIds = value ?? [];
    }

    /// <summary>Zulaessige Image-Praefixe (case-insensitiver Pfadvergleich).</summary>
    public IReadOnlyList<string> ImageRoots
    {
        get => _imageRoots;
        init => _imageRoots = value ?? [];
    }

    /// <summary>Optionale Bindung an eine konkrete Package-SID.</summary>
    public IReadOnlyList<string> PackageSids
    {
        get => _packageSids;
        init => _packageSids = value ?? [];
    }
}

/// <summary>Ein erlaubtes Ziel: Hostmuster plus Portliste.</summary>
public sealed record ScopeTarget
{
    private readonly IReadOnlyList<int> _ports = [];

    /// <summary>
    /// Exakter Host, <c>*.example.com</c> (matcht Subdomains, NICHT den Apex),
    /// IP-Literal oder CIDR. <c>*</c> allein ist verboten.
    /// </summary>
    public required string Host { get; init; }

    public required IReadOnlyList<int> Ports
    {
        get => _ports;
        init => _ports = value ?? [];
    }
}

/// <summary>TLS-Verhalten eines Scopes.</summary>
public sealed record ScopeInspection
{
    private readonly IReadOnlyList<string> _interceptAllowlist = [];

    public TlsMode Tls { get; init; } = TlsMode.Passthrough;

    /// <summary>
    /// Ziele, fuer die Interception ueberhaupt erlaubt ist. Muss den
    /// angeforderten Host enthalten, sonst faellt Cordon auf Passthrough
    /// zurueck - Interception ist niemals implizit.
    /// </summary>
    public IReadOnlyList<string> InterceptAllowlist
    {
        get => _interceptAllowlist;
        init => _interceptAllowlist = value ?? [];
    }
}

/// <summary>Aufteilung der Job-Object-Limits fuer den Agenten.</summary>
public sealed record SandboxLimits
{
    public int ActiveProcessLimit { get; init; } = 64;

    public long ProcessMemoryLimitBytes { get; init; } = 4L * 1024 * 1024 * 1024;

    public long JobMemoryLimitBytes { get; init; } = 8L * 1024 * 1024 * 1024;

    /// <summary>Gesamt-CPU-Zeit des Jobs in Sekunden. 0 = unbegrenzt.</summary>
    public long JobCpuTimeSeconds { get; init; }
}
