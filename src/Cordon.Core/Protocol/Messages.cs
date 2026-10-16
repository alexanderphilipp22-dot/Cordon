namespace Cordon.Core.Protocol;

/// <summary>Aktuelle Protokollversion. Wird im Hello ausgehandelt.</summary>
public static class ProtocolVersion
{
    public const int Current = 1;

    public const string PipePrefix = "CordonGateway";

    /// <summary>Vollstaendiger Pipe-Name fuer einen Agenten.</summary>
    public static string PipeNameFor(string agentId) => $"{PipePrefix}.{Sanitize(agentId)}";

    /// <summary>
    /// Agent-Ids landen in einem Pipe-Namen und muessen daher auf eine
    /// sichere Zeichenmenge begrenzt werden. Ein '\\' oder '..' koennte
    /// sonst einen anderen Pipe-Namensraum adressieren.
    /// </summary>
    public static string Sanitize(string agentId)
    {
        if (string.IsNullOrWhiteSpace(agentId))
        {
            throw new ArgumentException("Agent-Id darf nicht leer sein.", nameof(agentId));
        }

        Span<char> buffer = stackalloc char[agentId.Length];
        var length = 0;
        foreach (var c in agentId)
        {
            if (char.IsAsciiLetterOrDigit(c) || c is '-' or '_')
            {
                buffer[length++] = c;
            }
            else if (c == '.' && length > 0 && buffer[length - 1] != '.')
            {
                buffer[length++] = '.';
            }
        }

        var sanitized = new string(buffer[..length]).Trim('.');
        if (sanitized.Length == 0 || sanitized.Length > 64)
        {
            throw new ArgumentException(
                $"Agent-Id '{agentId}' ergibt nach Bereinigung eine unbrauchbare Laenge ({sanitized.Length}).",
                nameof(agentId));
        }

        return sanitized;
    }
}

public sealed record HelloRequest
{
    public int ProtocolVersion { get; init; } = Cordon.Core.Protocol.ProtocolVersion.Current;

    /// <summary>Vom Agenten behauptet. Wird gegen die Pipe-Instanz geprueft.</summary>
    public string AgentId { get; init; } = string.Empty;

    /// <summary>Zufaelliges Nonce, nur zur Korrelation im Audit.</summary>
    public string? Nonce { get; init; }
}

public sealed record HelloAck
{
    public int ProtocolVersion { get; init; } = Cordon.Core.Protocol.ProtocolVersion.Current;

    public PeerIdentityDto? Peer { get; init; }

    /// <summary>Der vom Gateway ermittelte Agent-Id (nicht der behauptete).</summary>
    public string? EffectiveAgentId { get; init; }
}

/// <summary>Identitaet, wie sie das Gateway aus dem Kernel gelesen hat.</summary>
public sealed record PeerIdentityDto
{
    public uint Pid { get; init; }

    public string? ImagePath { get; init; }

    public string? PackageSid { get; init; }

    public bool IsAppContainer { get; init; }

    public string? Integrity { get; init; }

    // Wie in ScopeConfiguration.cs: die Liste darf auch nach dem
    // Deserialisieren nie null sein. Der Source-Generator uebergibt fuer einen
    // fehlenden Schluessel `default` und wuerde den Initialisierer sonst
    // ueberschreiben - und dieses Dto kommt aus einem eingehenden Frame.
    private readonly IReadOnlyList<string> _capabilities = [];

    /// <summary>Capability-SIDs des Tokens, wie der Kernel sie geliefert hat.</summary>
    public IReadOnlyList<string> Capabilities
    {
        get => _capabilities;
        init => _capabilities = value ?? [];
    }
}

public sealed record ConnectRequest
{
    /// <summary>Zielhost. Darf ein Name, IP-Literal oder [IPv6] sein.</summary>
    public string Host { get; init; } = string.Empty;

    public int Port { get; init; }
}

public sealed record ConnectOk
{
    public string? ScopeId { get; init; }

    public bool TlsPassthrough { get; init; } = true;

    public string? ServerCertificateSubject { get; init; }
}

public sealed record ConnectDeny
{
    public string? Code { get; init; }

    public string? Reason { get; init; }
}

public sealed record CloseNotice
{
    public string? Reason { get; init; }
}

public sealed record ErrorMessage
{
    public string? Code { get; init; }

    public string? Reason { get; init; }
}

/// <summary>
/// Leerer JSON-Header. Wird fuer Frames verwendet, die formal einen
/// JSON-Header besitzen sollen, aber keine Daten tragen.
/// </summary>
public sealed record EmptyHeader;
