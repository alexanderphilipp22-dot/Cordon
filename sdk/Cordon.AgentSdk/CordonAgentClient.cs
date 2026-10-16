using System.IO.Pipes;
using Cordon.Core;
using Cordon.Core.Model;
using Cordon.Core.Protocol;

namespace Cordon.AgentSdk;

/// <summary>
/// Der Client, mit dem ein Agent mit dem Cordon-Gateway spricht.
/// <para>
/// <b>Es gibt keinen Token und keinen Header.</b> Die Autorisierung haengt
/// allein daran, dass dieser Prozess in einem AppContainer mit einer
/// Package-SID laeuft, die in der DACL der Ziel-Pipe steht. Das Gateway
/// liest die PID aus dem Pipe-Kernelobjekt und leitet daraus alles Weitere
/// ab. Ein kompromittierter Agent kann sich daher <b>nicht</b> als ein
/// anderer Agent ausgeben - er kann nur seine echte Identitaet verwenden,
/// und die ist an seine Scopes gebunden.
/// </para>
/// </summary>
public sealed class CordonAgentClient : IAsyncDisposable
{
    private readonly string _agentId;
    private readonly string _pipeName;
    private readonly TimeSpan _connectTimeout;

    private NamedPipeClientStream? _pipe;
    private ushort _sequence;
    private ClientIdentitySnapshot? _identity;

    public CordonAgentClient(string agentId, TimeSpan? connectTimeout = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(agentId);

        _agentId = agentId;
        _pipeName = ProtocolVersion.PipeNameFor(agentId);
        _connectTimeout = connectTimeout ?? TimeSpan.FromSeconds(10);
    }

    /// <summary>Die vom Gateway bestaetigte Identitaet dieses Prozesses.</summary>
    public ClientIdentitySnapshot? Identity => _identity;

    public bool IsConnected => _pipe?.IsConnected ?? false;

    /// <summary>
    /// Verbindet und fuehrt den Handshake aus. Wirft
    /// <see cref="CordonDeniedException"/>, wenn das Gateway die Identitaet
    /// ablehnt - der Aufrufer darf in diesem Fall <b>nicht</b> auf einen
    /// direkten Netzwerkpfad ausweichen.
    /// </summary>
    public async Task ConnectAsync(CancellationToken cancellationToken = default)
    {
        if (_pipe is not null)
        {
            throw new InvalidOperationException("Bereits verbunden.");
        }

        var pipe = new NamedPipeClientStream(
            serverName: ".",
            pipeName: _pipeName,
            direction: PipeDirection.InOut,
            options: PipeOptions.Asynchronous,
            impersonationLevel: System.Security.Principal.TokenImpersonationLevel.Identification);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_connectTimeout);

        try
        {
            await pipe.ConnectAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
            throw new CordonDeniedException(
                "connect_timeout",
                $"Pipe '{_pipeName}' war nicht innerhalb von {_connectTimeout.TotalSeconds:0} s erreichbar. "
                + "Laeuft das Cordon-Gateway und ist der Agent ueber 'cordon run' gestartet worden?");
        }
        catch (UnauthorizedAccessException)
        {
            // Die DACL der Pipe enthaelt diese Package-SID nicht.
            await pipe.DisposeAsync().ConfigureAwait(false);
            throw new CordonDeniedException(
                "pipe_access_denied",
                $"Zugriff auf Pipe '{_pipeName}' verweigert. Der Agent laeuft nicht in dem "
                + "AppContainer, dem diese Pipe gehoert.");
        }

        _pipe = pipe;

        await SendHelloAsync(cancellationToken).ConfigureAwait(false);

        var response = await FrameCodec.ReadAsync(pipe, cancellationToken).ConfigureAwait(false);
        if (response is null)
        {
            await DisposeAsync().ConfigureAwait(false);
            throw new CordonDeniedException("gateway_closed", "Gateway schloss die Pipe waehrend des Handshakes.");
        }

        switch (response.Kind)
        {
            case FrameKind.HelloAck:
            {
                var ack = response.Parse(CordonJsonContext.Default.HelloAck);
                var peer = ack?.Peer;

                _identity = new ClientIdentitySnapshot
                {
                    Pid = peer?.Pid ?? 0,
                    ImagePath = peer?.ImagePath ?? string.Empty,
                    PackageSid = peer?.PackageSid ?? string.Empty,
                    IsAppContainer = peer?.IsAppContainer ?? false,
                    Integrity = peer?.Integrity ?? "Unknown",
                    Capabilities = peer?.Capabilities ?? [],
                    EffectiveAgentId = ack?.EffectiveAgentId ?? _agentId,
                };

                if (!_identity.IsAppContainer)
                {
                    await DisposeAsync().ConfigureAwait(false);
                    throw new CordonDeniedException(
                        "not_app_container",
                        "Das Gateway meldet, dass dieser Prozess kein AppContainer ist. "
                        + "Ohne AppContainer gibt es keine Netzwerkgrenze - der Start wurde "
                        + "vermutlich nicht ueber 'cordon run' durchgefuehrt.");
                }

                break;
            }

            case FrameKind.Error:
            {
                var error = response.Parse(CordonJsonContext.Default.ErrorMessage);
                await DisposeAsync().ConfigureAwait(false);
                throw new CordonDeniedException(
                    error?.Code ?? "unknown",
                    error?.Reason ?? "Gateway lehnte die Verbindung ab.");
            }

            default:
                await DisposeAsync().ConfigureAwait(false);
                throw new CordonDeniedException(
                    "unexpected_frame",
                    $"Unerwarteter Frame '{response.KindName}' im Handshake.");
        }
    }

    /// <summary>
    /// Oeffnet einen TCP-Tunnel zu einem Ziel. Der Host wird <b>vor</b> dem
    /// Tunnelaufbau gegen die Scopes geprueft.
    /// </summary>
    public async Task<CordonTunnelStream> OpenTunnelAsync(
        string host,
        int port,
        CancellationToken cancellationToken = default)
    {
        if (_pipe is null)
        {
            throw new InvalidOperationException("Nicht verbunden. Zuerst ConnectAsync aufrufen.");
        }

        if (string.IsNullOrWhiteSpace(host))
        {
            throw new ArgumentException("Host darf nicht leer sein.", nameof(host));
        }

        if (port is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(port), port, "Port muss in 1..65535 liegen.");
        }

        var request = new ConnectRequest { Host = host, Port = port };

        await FrameCodec.WriteAsync(
                _pipe,
                FrameKind.Connect,
                FrameFlags.None,
                NextSequence(),
                request,
                CordonJsonContext.Default.ConnectRequest,
                ReadOnlyMemory<byte>.Empty,
                cancellationToken)
            .ConfigureAwait(false);

        // Solange die Antwort aussteht, darf kein anderer Connect gesendet
        // werden: die Antwort ist nicht mit einer Request-Id versehen.
        var response = await FrameCodec.ReadAsync(_pipe, cancellationToken).ConfigureAwait(false);
        if (response is null)
        {
            throw new CordonDeniedException("gateway_closed", "Gateway schloss die Pipe.");
        }

        switch (response.Kind)
        {
            case FrameKind.ConnectOk:
            {
                var ok = response.Parse(CordonJsonContext.Default.ConnectOk);
                if (ok?.TlsPassthrough == false)
                {
                    throw new CordonDeniedException(
                        "interception_not_supported",
                        "Das Gateway verlangt TLS-Interception fuer dieses Ziel, aber dieser Client "
                        + "unterstuetzt sie nicht. Passthrough-Ziele im Scope konfigurieren.");
                }

                return new CordonTunnelStream(this);
            }

            case FrameKind.ConnectDeny:
            {
                var deny = response.Parse(CordonJsonContext.Default.ConnectDeny);
                throw new CordonDeniedException(
                    deny?.Code ?? "denied",
                    deny?.Reason ?? $"Ziel {host}:{port} wurde abgelehnt.");
            }

            case FrameKind.Error:
            {
                var error = response.Parse(CordonJsonContext.Default.ErrorMessage);
                throw new CordonDeniedException(
                    error?.Code ?? "error",
                    error?.Reason ?? "Gateway meldete einen Fehler.");
            }

            default:
                throw new CordonDeniedException(
                    "unexpected_frame",
                    $"Unerwarteter Frame '{response.KindName}' nach Connect.");
        }
    }

    /// <summary>
    /// Liest einen Frame als reine Nutzdaten. Wird vom
    /// <see cref="CordonTunnelStream"/> verwendet.
    /// </summary>
    internal async ValueTask<TunnelReadResult> ReadTunnelDataAsync(CancellationToken cancellationToken)
    {
        var pipe = _pipe ?? throw new InvalidOperationException("Nicht verbunden.");

        while (true)
        {
            var message = await FrameCodec.ReadAsync(pipe, cancellationToken).ConfigureAwait(false);
            if (message is null)
            {
                return new TunnelReadResult(0, true, null);
            }

            switch (message.Kind)
            {
                case FrameKind.Data:
                {
                    var payload = message.Payload;
                    if (payload.Length == 0 && message.HasFlag(FrameFlags.Fin))
                    {
                        return new TunnelReadResult(0, true, null);
                    }

                    return new TunnelReadResult(payload.Length, false, null)
                    {
                        Payload = payload.ToArray(),
                    };
                }

                case FrameKind.Ping:
                    await FrameCodec.WriteControlAsync(pipe, FrameKind.Pong, NextSequence(), cancellationToken)
                        .ConfigureAwait(false);
                    continue;

                case FrameKind.Close:
                    return new TunnelReadResult(0, true, null);

                case FrameKind.Error:
                {
                    var error = message.Parse(CordonJsonContext.Default.ErrorMessage);
                    return new TunnelReadResult(0, true, $"{error?.Code}: {error?.Reason}");
                }

                default:
                    return new TunnelReadResult(
                        0,
                        true,
                        $"Unerwarteter Frame '{message.KindName}' im Tunnel.");
            }
        }
    }

    internal async ValueTask WriteTunnelDataAsync(
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        var pipe = _pipe ?? throw new InvalidOperationException("Nicht verbunden.");

        if (payload.Length == 0)
        {
            return;
        }

        await FrameCodec.WriteDataAsync(pipe, NextSequence(), payload, fin: false, cancellationToken)
            .ConfigureAwait(false);
    }

    internal async ValueTask CloseTunnelAsync(CancellationToken cancellationToken)
    {
        var pipe = _pipe;
        if (pipe is null)
        {
            return;
        }

        try
        {
            await FrameCodec.WriteDataAsync(
                    pipe,
                    NextSequence(),
                    ReadOnlyMemory<byte>.Empty,
                    fin: true,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (IOException)
        {
            // Peer bereits weg.
        }
    }

    public async ValueTask DisposeAsync()
    {
        var pipe = _pipe;
        _pipe = null;

        if (pipe is not null)
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
        }
    }

    internal ushort NextSequence() => unchecked(_sequence++);

    private async Task SendHelloAsync(CancellationToken cancellationToken)
    {
        var hello = new HelloRequest
        {
            ProtocolVersion = ProtocolVersion.Current,
            AgentId = _agentId,

            // Nur zur Korrelation im Audit. Ausdruecklich KEIN Token: es wird
            // nicht zur Autorisierung verwendet und das Gateway wertet es
            // nicht aus.
            Nonce = Guid.NewGuid().ToString("N"),
        };

        await FrameCodec.WriteAsync(
                _pipe!,
                FrameKind.Hello,
                FrameFlags.None,
                NextSequence(),
                hello,
                CordonJsonContext.Default.HelloRequest,
                ReadOnlyMemory<byte>.Empty,
                cancellationToken)
            .ConfigureAwait(false);
    }
}

/// <summary>Ergebnis eines Tunnel-Lesevorgangs.</summary>
internal readonly record struct TunnelReadResult(int Length, bool EndOfStream, string? Error)
{
    /// <summary>Nutzdaten. Leer, wenn <see cref="EndOfStream"/> gesetzt ist.</summary>
    public byte[] Payload { get; init; } = [];
}

/// <summary>Die vom Gateway bestaetigte Identitaet des Agenten.</summary>
public sealed record ClientIdentitySnapshot
{
    public required uint Pid { get; init; }

    public required string ImagePath { get; init; }

    public required string PackageSid { get; init; }

    public required bool IsAppContainer { get; init; }

    public required string Integrity { get; init; }

    public required IReadOnlyList<string> Capabilities { get; init; }

    public required string EffectiveAgentId { get; init; }
}

/// <summary>
/// Wird geworfen, wenn Cordon eine Anfrage ablehnt.
/// <para>
/// Der Aufrufer darf diesen Fehler <b>nicht</b> als Aufforderung verstehen,
/// einen anderen Weg zu suchen. Es gibt keinen anderen Weg - das ist der
/// Sinn der Architektur.
/// </para>
/// </summary>
public sealed class CordonDeniedException : Exception
{
    public CordonDeniedException(string code, string message)
        : base(message)
    {
        Code = code;
    }

    public CordonDeniedException(string code, string message, Exception inner)
        : base(message, inner)
    {
        Code = code;
    }

    /// <summary>Stabiler Ablehnungscode (z. B. <c>no_scope</c>).</summary>
    public string Code { get; }
}
