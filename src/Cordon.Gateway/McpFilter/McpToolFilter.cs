using System.Text.Json;
using Cordon.Core;
using Cordon.Core.Model;
using Cordon.Core.Protocol;

namespace Cordon.Gateway.McpFilter;

/// <summary>Entscheidung über einen MCP-/JSON-Toolaufruf.</summary>
public sealed record McpToolDecision(bool Allowed, string ToolName, string? Code, string? Reason)
{
    public static McpToolDecision Allow(string toolName) => new(true, toolName, null, null);

    public static McpToolDecision Deny(string toolName, string code, string reason) =>
        new(false, toolName, code, reason);
}

/// <summary>
/// Deklarative Tool-Whitelist eines Scopes.
/// <para>
/// Der Vergleich ist exakt und case-sensitiv (Toolnamen sind Bezeichner, keine
/// Dateipfade). Eine leere Whitelist bedeutet: <b>kein</b> Toolaufruf ist
/// erlaubt (fail closed).
/// </para>
/// </summary>
public sealed class McpToolPolicy
{
    private readonly HashSet<string> _allowed;

    public McpToolPolicy(IEnumerable<string> allowedTools)
    {
        ArgumentNullException.ThrowIfNull(allowedTools);
        _allowed = new HashSet<string>(allowedTools, StringComparer.Ordinal);
    }

    /// <summary>Die erlaubten Toolnamen (unverändert).</summary>
    public IReadOnlyCollection<string> AllowedTools => _allowed;

    /// <summary>Erzeugt die Whitelist aus den <c>allowedTools</c> eines Scopes.</summary>
    public static McpToolPolicy FromScope(ScopeGrant scope)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return new McpToolPolicy(scope.AllowedTools);
    }

    public bool Allows(string toolName) => _allowed.Contains(toolName);
}

/// <summary>
/// Parst und autorisiert MCP-/JSON-Toolaufrufe am Named-Pipe-Choke-Point.
/// <para>
/// Unterstützt sowohl die JSON-RPC-Form
/// (<c>{"method":"tools/call","params":{"name":"read_file"}}</c>) als auch die
/// direkten Formen <c>{"name":"read_file"}</c> und <c>{"tool":"read_file"}</c>.
/// Jeder Parsefehler oder fehlende Toolname führt zur Ablehnung (fail closed).
/// </para>
/// </summary>
public static class McpToolFilter
{
    /// <summary>
    /// Inspiziert einen JSON-Payload und prüft den Toolnamen gegen die Policy.
    /// Wirft nicht; für eine harte Ablehnung siehe <see cref="Authorize"/>.
    /// </summary>
    public static McpToolDecision Inspect(ReadOnlySpan<byte> jsonPayload, McpToolPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);

        string? toolName;
        bool ambiguous;
        try
        {
            // Harte Tiefengrenze: tief verschachteltes, boeswilliges JSON wird
            // als Protokollverletzung abgelehnt, bevor es Speicher oder Stack
            // belastet (fail closed, kein Absturz des Gateway-Prozesses).
            var state = new JsonReaderState(new JsonReaderOptions { MaxDepth = 32 });
            var reader = new Utf8JsonReader(jsonPayload, isFinalBlock: true, state);
            using var document = JsonDocument.ParseValue(ref reader);
            (toolName, ambiguous) = ExtractToolName(document.RootElement);
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or ArgumentException)
        {
            return McpToolDecision.Deny(
                "<unparseable>",
                DenyCodes.ProtocolError,
                $"MCP-Payload ist kein gueltiges JSON: {ex.Message}");
        }

        if (ambiguous)
        {
            return McpToolDecision.Deny(
                "<ambiguous>",
                DenyCodes.ProtocolError,
                "MCP-Payload enthaelt widerspruechliche Toolnamen.");
        }

        if (string.IsNullOrEmpty(toolName))
        {
            return McpToolDecision.Deny(
                "<missing>",
                DenyCodes.MalformedTarget,
                "MCP-Payload enthaelt keinen Tool-Namen.");
        }

        return policy.Allows(toolName)
            ? McpToolDecision.Allow(toolName)
            : McpToolDecision.Deny(
                toolName,
                DenyCodes.ToolNotAllowed,
                $"Tool '{toolName}' ist in diesem Scope nicht erlaubt.");
    }

    /// <summary>
    /// Wie <see cref="Inspect"/>, wirft aber bei Ablehnung eine strukturierte
    /// <see cref="CordonProtocolException"/> mit stabilem Code.
    /// </summary>
    public static void Authorize(ReadOnlySpan<byte> jsonPayload, McpToolPolicy policy)
    {
        var decision = Inspect(jsonPayload, policy);
        if (!decision.Allowed)
        {
            throw new CordonProtocolException(
                decision.Code ?? DenyCodes.ToolNotAllowed,
                decision.Reason ?? "Toolaufruf ist nicht erlaubt.");
        }
    }

    private static (string? Name, bool Ambiguous) ExtractToolName(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object)
        {
            return (null, false);
        }

        var candidates = new List<string>();

        // JSON-RPC MCP: {"method":"tools/call","params":{"name":"..."}}
        if (root.TryGetProperty("params", out var parameters)
            && parameters.ValueKind == JsonValueKind.Object
            && parameters.TryGetProperty("name", out var rpcName)
            && rpcName.ValueKind == JsonValueKind.String
            && rpcName.GetString() is { } rpcTool)
        {
            candidates.Add(rpcTool);
        }

        // Direkte Formen.
        if (root.TryGetProperty("name", out var name)
            && name.ValueKind == JsonValueKind.String
            && name.GetString() is { } directName)
        {
            candidates.Add(directName);
        }

        if (root.TryGetProperty("tool", out var tool)
            && tool.ValueKind == JsonValueKind.String
            && tool.GetString() is { } directTool)
        {
            candidates.Add(directTool);
        }

        if (candidates.Count == 0)
        {
            return (null, false);
        }

        // Parser-Differential-Schutz: widerspruechliche Toolnamen deuten auf
        // einen Versuch hin, Filter und ausfuehrendes System gegeneinander
        // auszuspielen. In dem Fall wird der Aufruf abgelehnt.
        var first = candidates[0];
        foreach (var candidate in candidates)
        {
            if (!string.Equals(candidate, first, StringComparison.Ordinal))
            {
                return (null, true);
            }
        }

        return (first, false);
    }
}
