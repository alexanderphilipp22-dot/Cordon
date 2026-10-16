using System.Text.Json.Serialization;

namespace Cordon.Core;

/// <summary>
/// Ergebnis einer Policy-Entscheidung. <see cref="Deny"/> ist der einzige
/// sichere Default; ein "unbekannt" existiert bewusst nicht.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<Verdict>))]
public enum Verdict
{
    Deny = 0,
    Allow = 1,
}

/// <summary>Art des angeforderten Ziels.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<TargetKind>))]
public enum TargetKind
{
    /// <summary>Opaker TLS-Tunnel (CONNECT). Cordon sieht keinen Klartext.</summary>
    Connect = 0,

    /// <summary>Klartext-HTTP nach Opt-In-TLS-Interception.</summary>
    Http = 1,
}

/// <summary>TLS-Behandlung fuer einen Scope.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<TlsMode>))]
public enum TlsMode
{
    /// <summary>Default: Cordon relayt opak. Keine CA, kein Schluessel, kein Klartext.</summary>
    Passthrough = 0,

    /// <summary>
    /// Opt-In fuer explizit gelistete Debugging-Ziele. Cordon terminiert TLS
    /// mit einer prozesslokalen CA (NICHT im Windows-Trust-Store installiert).
    /// </summary>
    Intercept = 1,
}

/// <summary>Integritaetslevel des Aufrufer-Tokens, auf das Wesentliche reduziert.</summary>
public enum IntegrityLevel
{
    Unknown = 0,
    Untrusted = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    System = 5,
    Protected = 6,
}

/// <summary>Stabile Ablehnungsgruende. Werden auditiert und sind Teil der API.</summary>
public static class DenyCodes
{
    public const string NoScope = "no_scope";
    public const string NoPrincipal = "no_principal";
    public const string MalformedTarget = "malformed_target";
    public const string DeniedLiteral = "denied_literal";
    public const string PortNotAllowed = "port_not_allowed";
    public const string MethodNotAllowed = "method_not_allowed";
    public const string PathNotAllowed = "path_not_allowed";
    public const string ToolNotAllowed = "tool_not_allowed";
    public const string IdentityUnresolvable = "identity_unresolvable";
    public const string IdentityMismatch = "identity_mismatch";
    public const string NotAppContainer = "not_app_container";
    public const string HasNetworkCapability = "has_network_capability";
    public const string IntegrityTooHigh = "integrity_too_high";
    public const string LimitExceeded = "limit_exceeded";
    public const string UpstreamFailure = "upstream_failure";
    public const string UpstreamBlockedLiteral = "upstream_blocked_literal";
    public const string ProtocolError = "protocol_error";
    public const string NotAuthorizedForPipe = "not_authorized_for_pipe";
}
