using System.Text.Json;
using System.Text.Json.Serialization;
using Cordon.Core.Audit;
using Cordon.Core.Model;
using Cordon.Core.Protocol;

namespace Cordon.Core;

/// <summary>
/// Source-generated JSON-Kontext. Vermeidet Reflektion zur Laufzeit
/// (trim-/AOT-sicher) und haelt die Serialisierung an einer Stelle.
/// </summary>
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    WriteIndented = false)]
[JsonSerializable(typeof(ScopeConfiguration))]
[JsonSerializable(typeof(ClientIdentity))]
[JsonSerializable(typeof(ResourceTarget))]
[JsonSerializable(typeof(PolicyDecision))]
[JsonSerializable(typeof(ScopeLimits))]
[JsonSerializable(typeof(ScopeHttpRules))]
[JsonSerializable(typeof(FrameHeader))]
[JsonSerializable(typeof(HelloRequest))]
[JsonSerializable(typeof(HelloAck))]
[JsonSerializable(typeof(ConnectRequest))]
[JsonSerializable(typeof(ConnectOk))]
[JsonSerializable(typeof(ConnectDeny))]
[JsonSerializable(typeof(CloseNotice))]
[JsonSerializable(typeof(ErrorMessage))]
[JsonSerializable(typeof(PeerIdentityDto))]
[JsonSerializable(typeof(AuditEvent))]
[JsonSerializable(typeof(AuditIdentityDto))]
[JsonSerializable(typeof(AuditTargetDto))]
[JsonSerializable(typeof(EmptyHeader))]
[JsonSerializable(typeof(SandboxLimits))]
[JsonSerializable(typeof(System.Collections.Generic.Dictionary<string, string>))]
public sealed partial class CordonJsonContext : JsonSerializerContext
{
}

/// <summary>Zentrale JSON-Optionen fuer Faelle, in denen ein Options-Objekt
/// gebraucht wird (z. B. <c>JsonDocument</c>).</summary>
public static class CordonJson
{
    public static JsonSerializerOptions Options { get; } = new(CordonJsonContext.Default.Options)
    {
        WriteIndented = false,
    };

    /// <summary>Fuer Konfigurationsdateien: lesbar und kommentarfreundlich.</summary>
    public static JsonSerializerOptions WriteIndentedOptions { get; } = new(CordonJsonContext.Default.Options)
    {
        WriteIndented = true,
    };

    public static readonly JsonDocumentOptions DocumentOptions = new()
    {
        AllowTrailingCommas = true,
        CommentHandling = JsonCommentHandling.Skip,
        MaxDepth = 32,
    };
}
