using System.IO.Pipes;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using Cordon.Core;
using Cordon.Core.Audit;
using Cordon.Core.Configuration;
using Cordon.Core.Model;
using Cordon.Core.Policy;
using Cordon.Core.Protocol;
using Cordon.Gateway.Tls;
using Cordon.Windows;

namespace Cordon.Gateway;

/// <summary>Eine etablierte, autorisierte Sitzung zu einem Ziel.</summary>
internal sealed class SessionTarget
{
    public required Socket Socket { get; init; }

    public required IPAddress RemoteAddress { get; init; }

    public required string Host { get; init; }

    public required int Port { get; init; }

    public required string ScopeId { get; init; }

    public required ScopeLimits Limits { get; init; }

    public required string CorrelationId { get; init; }
}

/// <summary>
/// Behandelt genau eine Agent-Verbindung: Handshake, Identitaetspruefung,
/// Autorisierung pro Ziel und anschliessend opaker Byte-Relay.
/// <para>
/// Cordon parst hier <b>kein</b> HTTP und <b>kein</b> TLS. Es liest nur den
/// Zielhost aus einem JSON-Frame. Das ist Absicht: jede Parsing-Logik auf dem
/// Pfad eines kompromittierten Agenten ist zusaetzliche Angriffsflaeche.
/// </para>
/// </summary>
public sealed class ProxyConnection : IDisposable
{
    /// <summary>Zeit, die der Agent fuer den Handshake bekommt.</summary>
    private static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(10);

    /// <summary>Maximale Groesse eines per Interception gelesenen HTTP-Requests.</summary>
    private const int MaxInterceptedRequestBytes = 4 * 1024 * 1024;

    private readonly NamedPipeServerStream _pipe;
    private readonly string _agentId;
    private readonly string _expectedPackageSid;
    private readonly string? _expectedImagePath;
    private readonly PipeClientSignature _clientSignature;
    private readonly PolicyStore _policyStore;
    private readonly AuditLog _audit;
    private readonly UpstreamConnector _connector;
    private readonly CertificateAuthority? _authority;
    private readonly ScopeConnectionLimiter _limiter;
    private readonly string _correlationId = Guid.NewGuid().ToString("N");

    private ushort _sequence;
    private ClientIdentity? _identity;
    private bool _disposed;

    /// <summary>
    /// Serialisiert alle Schreibzugriffe auf die Pipe. Der Byte-Modus einer
    /// Named Pipe garantiert keine Atomaritaet ueber die Pipe-Puffergroesse
    /// hinaus; ohne diese Sperre koennten parallele Frames (z. B. Daten- und
    /// Kontroll-Frames im Relay) verschraenkt werden und den Frame-Strom des
    /// Agenten korrumpieren.
    /// </summary>
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    internal ProxyConnection(
        NamedPipeServerStream pipe,
        string agentId,
        string expectedPackageSid,
        string? expectedImagePath,
        PipeClientSignature clientSignature,
        PolicyStore policyStore,
        AuditLog audit,
        UpstreamConnector connector,
        CertificateAuthority? authority,
        ScopeConnectionLimiter limiter)
    {
        _pipe = pipe;
        _agentId = agentId;
        _expectedPackageSid = expectedPackageSid;
        _expectedImagePath = expectedImagePath;
        _clientSignature = clientSignature;
        _policyStore = policyStore;
        _audit = audit;
        _connector = connector;
        _authority = authority;
        _limiter = limiter;
    }

    /// <summary>
    /// Gibt die von dieser Verbindung gehaltene Schreibsperre frei.
    /// <para>
    /// Die Pipe wird bewusst <b>nicht</b> entsorgt: sie gehoert dem
    /// <see cref="AgentListener"/> und wird dort geschlossen. Ein Dispose der
    /// Pipe an dieser Stelle waere ein doppeltes Dispose auf einem Handle, das
    /// der Aufrufer noch besitzt (vgl. <c>leaveInnerStreamOpen</c> beim
    /// SslStream).
    /// </para>
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _writeLock.Dispose();
        GC.SuppressFinalize(this);
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        try
        {
            if (!await HandshakeAsync(cancellationToken).ConfigureAwait(false))
            {
                return;
            }

            await ServeAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (CordonProtocolException ex)
        {
            WriteProtocolViolation(ex.Message);
        }
        catch (IOException)
        {
            // Verbindungsabbruch durch den Agenten ist der Normalfall.
        }
        catch (ObjectDisposedException)
        {
            // Pipe wurde bereits freigegeben (z. B. beim Herunterfahren).
        }
        catch (OperationCanceledException)
        {
            // Herunterfahren.
        }
        finally
        {
            _audit.Write(AuditLog.Event(AuditEvents.ClientDisconnected) with
            {
                AgentId = _agentId,
                CorrelationId = _correlationId,
                Identity = ToAuditIdentity(_identity),
            });
        }
    }

    /// <summary>
    /// Handshake: der Agent behauptet eine Agent-Id, Cordon prueft die
    /// tatsaechliche Identitaet. Die Behauptung wird nur protokolliert,
    /// <b>nie</b> verwendet.
    /// </summary>
    private async Task<bool> HandshakeAsync(CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(HandshakeTimeout);

        ReceivedMessage? message;
        try
        {
            message = await FrameCodec.ReadAsync(_pipe, timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            await SendErrorAsync(DenyCodes.ProtocolError, "Handshake-Timeout.", cancellationToken)
                .ConfigureAwait(false);
            return false;
        }

        if (message is null)
        {
            return false;
        }

        if (message.Kind != FrameKind.Hello)
        {
            await SendErrorAsync(
                    DenyCodes.ProtocolError,
                    $"Erwartet wurde hello, empfangen wurde {message.KindName}.",
                    cancellationToken)
                .ConfigureAwait(false);
            return false;
        }

        var hello = message.Parse(CordonJsonContext.Default.HelloRequest);
        if (hello is null)
        {
            await SendErrorAsync(DenyCodes.ProtocolError, "Hello ohne Header.", cancellationToken)
                .ConfigureAwait(false);
            return false;
        }

        if (hello.ProtocolVersion != ProtocolVersion.Current)
        {
            await SendErrorAsync(
                    DenyCodes.ProtocolError,
                    $"Protokollversion {hello.ProtocolVersion} wird nicht unterstuetzt "
                    + $"(erwartet {ProtocolVersion.Current}).",
                    cancellationToken)
                .ConfigureAwait(false);
            return false;
        }

        // ------------------------------------------------------------------
        // Identitaet aufloesen
        // ------------------------------------------------------------------
        // Die Aufloesung prueft erneut am Pipe-Handle UND vergleicht die
        // Erzeugungszeit des Prozesses. Damit ist ausgeschlossen, dass die
        // PID seit dem Verbindungsaufbau neu vergeben wurde - ohne diese
        // Pruefung koennte hier das Token eines fremden Prozesses landen.
        var resolution = PipeClientResolver.Resolve(
            _pipe.SafePipeHandle,
            _clientSignature,
            _agentId,
            _expectedPackageSid,
            _expectedImagePath);

        if (!resolution.Success || resolution.Identity is null)
        {
            var code = resolution.ErrorCode ?? DenyCodes.IdentityUnresolvable;
            var reason = $"{code}: {resolution.Error}";

            WriteRejected(reason, null);
            await SendErrorAsync(code, resolution.Error ?? "Identitaet nicht aufloesbar.", cancellationToken)
                .ConfigureAwait(false);
            return false;
        }

        var identity = resolution.Identity;

        if (resolution.Warnings.Count > 0)
        {
            // Unbestaetigte Teilwerte werden protokolliert, nicht verschwiegen.
            // Sie fuehren nicht zum Abbruch - der Validator entscheidet, ob
            // eine fehlende Aussage die Anforderung verletzt.
            _audit.Write(AuditLog.Event(AuditEvents.ClientWarning) with
            {
                AgentId = _agentId,
                CorrelationId = _correlationId,
                Verdict = "deny",
                Reason = "Unbestaetigte Identitaetswerte: " + string.Join(" | ", resolution.Warnings),
                Identity = ToAuditIdentity(identity),
            });
        }

        var policy = _policyStore.Current;
        if (policy is null)
        {
            WriteRejected("Keine aktive Policy. Der Dienst verweigert den Dienst (fail closed).", identity);
            await SendErrorAsync(
                    DenyCodes.NotAuthorizedForPipe,
                    "Keine aktive Policy.",
                    cancellationToken)
                .ConfigureAwait(false);
            return false;
        }

        var validation = IdentityValidator.Validate(
            identity,
            requireAppContainer: true,
            requireLowIntegrity: true,
            allowedCapabilities: policy.Configuration.AllowedCapabilities);

        if (validation.Warnings.Count > 0)
        {
            // Reduzierter Schutz wird protokolliert, nicht verschwiegen. Das
            // ist ausdruecklich KEIN "rejected"-Event - der Agent wird
            // zugelassen, nur mit einer Bindung weniger.
            _audit.Write(AuditLog.Event(AuditEvents.ClientWarning) with
            {
                AgentId = _agentId,
                CorrelationId = _correlationId,
                Verdict = "allow",
                Reason = string.Join(" | ", validation.Warnings),
                Identity = ToAuditIdentity(identity),
            });
        }

        // Die behauptete Agent-Id wird gegen die Pipe-Instanz geprueft. Sie
        // ist nicht die Autorisierungsgrundlage - nur ein Konsistenzsignal.
        if (!string.Equals(hello.AgentId, _agentId, StringComparison.OrdinalIgnoreCase))
        {
            WriteRejected(
                $"Behauptete Agent-Id '{hello.AgentId}' passt nicht zur Pipe-Instanz '{_agentId}'.",
                identity);
            await SendErrorAsync(
                    DenyCodes.IdentityMismatch,
                    "Agent-Id passt nicht zur Pipe-Instanz.",
                    cancellationToken)
                .ConfigureAwait(false);
            return false;
        }

        if (!validation.IsAuthorized)
        {
            WriteRejected(validation.Summary, identity);
            await SendErrorAsync(DenyCodes.IdentityMismatch, validation.Summary, cancellationToken)
                .ConfigureAwait(false);
            return false;
        }

        if (policy.Configuration.RequireSignature)
        {
            var signature = ImageSignature.Verify(identity.ImagePath);
            if (!signature.IsTrusted)
            {
                WriteRejected($"Signaturpruefung fehlgeschlagen: {signature.Error}", identity);
                await SendErrorAsync(
                        DenyCodes.IdentityMismatch,
                        $"Signaturpruefung fehlgeschlagen: {signature.Error}",
                        cancellationToken)
                    .ConfigureAwait(false);
                return false;
            }

            // Signer-Subject zwingend gegen die Whitelist pruefen. Fehlt das
            // Subject oder ist es nicht gelistet, wird fail-closed abgelehnt.
            if (!IsSignerAllowed(signature.SignerSubject, policy.Configuration.AllowedSigners))
            {
                WriteRejected(
                    $"Signer-Subject '{signature.SignerSubject ?? "<leer>"}' ist nicht in der Whitelist erlaubt.",
                    identity);
                await SendErrorAsync(
                        DenyCodes.IdentityMismatch,
                        "Signer-Subject ist nicht in der Whitelist erlaubt.",
                        cancellationToken)
                    .ConfigureAwait(false);
                return false;
            }
        }

        _identity = identity;

        _audit.Write(AuditLog.Event(AuditEvents.ClientConnected) with
        {
            AgentId = _agentId,
            CorrelationId = _correlationId,
            Verdict = "allow",
            Identity = ToAuditIdentity(identity),
            Detail = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["claimedAgentId"] = hello.AgentId,
                ["nonce"] = hello.Nonce ?? string.Empty,
            },
        });

        await SendAsync(
                FrameKind.HelloAck,
                new HelloAck
                {
                    ProtocolVersion = ProtocolVersion.Current,
                    EffectiveAgentId = _agentId,
                    Peer = new PeerIdentityDto
                    {
                        Pid = identity.Pid,
                        ImagePath = identity.ImagePath,
                        PackageSid = identity.PackageSid,
                        IsAppContainer = identity.IsAppContainer,
                        Integrity = identity.Integrity.ToString(),
                        Capabilities = identity.Capabilities,
                    },
                },
                cancellationToken)
            .ConfigureAwait(false);

        return true;
    }

    /// <summary>
    /// Schleife ueber alle Zielanforderungen dieser Pipe-Verbindung. Die
    /// Verbindung kann mehrere Ziele nacheinander autorisieren (wie ein
    /// Proxy), jedes einzeln geprueft.
    /// </summary>
    private async Task ServeAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            ReceivedMessage? message;
            try
            {
                message = await FrameCodec.ReadAsync(_pipe, cancellationToken).ConfigureAwait(false);
            }
            catch (CordonProtocolException ex)
            {
                await SendErrorAsync(DenyCodes.ProtocolError, ex.Message, cancellationToken)
                    .ConfigureAwait(false);
                return;
            }

            if (message is null)
            {
                return;
            }

            switch (message.Kind)
            {
                case FrameKind.Ping:
                    await WriteControlLockedAsync(FrameKind.Pong, NextSequence(), cancellationToken)
                        .ConfigureAwait(false);
                    break;

                case FrameKind.Connect:
                    await HandleConnectAsync(message, cancellationToken).ConfigureAwait(false);
                    break;

                case FrameKind.Close:
                    return;

                case FrameKind.Data:
                    // Daten ohne vorherigen Connect sind ein Protokollfehler.
                    await SendErrorAsync(
                            DenyCodes.ProtocolError,
                            "Data-Frame ohne vorherigen Connect.",
                            cancellationToken)
                        .ConfigureAwait(false);
                    return;

                default:
                    await SendErrorAsync(
                            DenyCodes.ProtocolError,
                            $"Frame {message.KindName} ist hier nicht zulaessig.",
                            cancellationToken)
                        .ConfigureAwait(false);
                    return;
            }
        }
    }

    private async Task HandleConnectAsync(ReceivedMessage message, CancellationToken cancellationToken)
    {
        var request = message.Parse(CordonJsonContext.Default.ConnectRequest);
        if (request is null)
        {
            await DenyConnectAsync(DenyCodes.ProtocolError, "Connect ohne Header.", cancellationToken)
                .ConfigureAwait(false);
            return;
        }

        var identity = _identity
            ?? throw new InvalidOperationException("Connect ohne vorherigen Handshake.");

        var policy = _policyStore.Current;
        if (policy is null)
        {
            await DenyConnectAsync(
                    DenyCodes.NotAuthorizedForPipe,
                    "Keine aktive Policy.",
                    cancellationToken)
                .ConfigureAwait(false);
            return;
        }

        var host = HostNormalizer.Normalize(request.Host);
        if (!host.IsValid)
        {
            await DenyConnectAsync(
                    DenyCodes.MalformedTarget,
                    host.Error ?? "Host ungueltig.",
                    cancellationToken)
                .ConfigureAwait(false);
            WriteConnectDeny(identity, request.Host, request.Port, DenyCodes.MalformedTarget, host.Error);
            return;
        }

        var decision = PolicyEngine.Evaluate(
            policy,
            identity,
            host,
            request.Port,
            TargetKind.Connect);

        if (decision.Verdict != Verdict.Allow)
        {
            WriteConnectDeny(identity, request.Host, request.Port, decision.Code, decision.Reason);
            await DenyConnectAsync(
                    decision.Code ?? DenyCodes.NoScope,
                    decision.Reason ?? "Kein Grant.",
                    cancellationToken)
                .ConfigureAwait(false);
            return;
        }

        // MaxConcurrentConnections: harte Grenze pro Scope, geprueft VOR dem
        // Upstream-Connect. Wird sie erreicht, wird die Verbindung abgelehnt
        // (fail closed) statt einen Socket zu oeffnen.
        var scopeId = decision.ScopeId ?? string.Empty;
        if (!_limiter.TryAcquire(scopeId, decision.Limits.MaxConcurrentConnections))
        {
            WriteConnectDeny(
                identity,
                request.Host,
                request.Port,
                DenyCodes.LimitExceeded,
                $"Scope '{scopeId}' hat das Verbindungslimit "
                + $"{decision.Limits.MaxConcurrentConnections} erreicht.");
            await DenyConnectAsync(
                    DenyCodes.LimitExceeded,
                    $"MaxConcurrentConnections ({decision.Limits.MaxConcurrentConnections}) erreicht.",
                    cancellationToken)
                .ConfigureAwait(false);
            return;
        }

        try
        {
        var connect = await _connector
            .ConnectAsync(host, request.Port, policy.Configuration, cancellationToken)
            .ConfigureAwait(false);

        if (!connect.IsSuccess)
        {
            WriteConnectDeny(identity, request.Host, request.Port, connect.DenyCode, connect.DenyReason);
            await DenyConnectAsync(
                    connect.DenyCode ?? DenyCodes.UpstreamFailure,
                    connect.DenyReason ?? "Upstream nicht erreichbar.",
                    cancellationToken)
                .ConfigureAwait(false);
            return;
        }

        var intercept = decision.Tls == TlsMode.Intercept && _authority is not null;

        var target = new SessionTarget
        {
            Socket = connect.Socket!,
            RemoteAddress = connect.RemoteAddress!,
            Host = host.Value,
            Port = request.Port,
            ScopeId = decision.ScopeId ?? string.Empty,
            Limits = decision.Limits,
            CorrelationId = _correlationId,
        };

        _audit.Write(AuditLog.Event(AuditEvents.ConnectAllow) with
        {
            AgentId = _agentId,
            CorrelationId = _correlationId,
            Verdict = "allow",
            ScopeId = target.ScopeId,
            Reason = decision.Reason,
            Identity = ToAuditIdentity(identity),
            Target = ToAuditTarget(TargetKind.Connect, host, request.Port, null, null),
            Detail = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["remoteAddress"] = target.RemoteAddress.ToString(),
                ["addressClass"] = AddressClassifier.Describe(target.RemoteAddress),
                ["tls"] = intercept ? "intercept" : "passthrough",
                ["requestedHost"] = request.Host,
            },
        });

        await SendAsync(
                FrameKind.ConnectOk,
                new ConnectOk
                {
                    ScopeId = target.ScopeId,
                    TlsPassthrough = !intercept,
                    ServerCertificateSubject = intercept ? _authority!.Subject : null,
                },
                cancellationToken)
            .ConfigureAwait(false);

        var started = DateTimeOffset.UtcNow;
        long bytesUp = 0;
        long bytesDown = 0;

        // SessionTtlSeconds: harte Obergrenze fuer die Lebensdauer eines
        // autorisierten Tunnels. Ein Agent kann einen Tunnel nicht unbegrenzt
        // offen halten; nach Ablauf wird die Sitzung abgebrochen.
        using var sessionCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (target.Limits.SessionTtlSeconds > 0)
        {
            sessionCts.CancelAfter(TimeSpan.FromSeconds(target.Limits.SessionTtlSeconds));
        }

        var sessionToken = sessionCts.Token;

        try
        {
            if (intercept)
            {
                var counters = await RunInterceptedHttpAsync(target, sessionToken).ConfigureAwait(false);
                bytesUp = counters.BytesUp;
                bytesDown = counters.BytesDown;
            }
            else
            {
                var counters = await RelayAsync(_pipe, target, sessionToken).ConfigureAwait(false);
                bytesUp = counters.BytesUp;
                bytesDown = counters.BytesDown;
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
        {
            // Abbruch ist normal und wird unten auditiert.
        }
        finally
        {
            try
            {
                target.Socket.Shutdown(SocketShutdown.Both);
            }
            catch (SocketException)
            {
                // Bereits geschlossen.
            }
            catch (ObjectDisposedException)
            {
                // dito
            }

            target.Socket.Dispose();

            _audit.Write(AuditLog.Event(AuditEvents.ConnectEnd) with
            {
                AgentId = _agentId,
                CorrelationId = _correlationId,
                ScopeId = target.ScopeId,
                Verdict = "allow",
                Identity = ToAuditIdentity(identity),
                Target = ToAuditTarget(TargetKind.Connect, host, request.Port, null, null),
                BytesUp = bytesUp,
                BytesDown = bytesDown,
                DurationMs = (DateTimeOffset.UtcNow - started).TotalMilliseconds,
            });
        }
        }
        finally
        {
            _limiter.Release(scopeId);
        }
    }

    /// <summary>
    /// Opaker Byte-Relay zwischen Pipe und Ziel-Socket.
    /// <para>
    /// Es wird kein Byte interpretiert. Backpressure entsteht dadurch, dass
    /// Schreiben und Lesen im selben Task passieren: kann der Peer nicht
    /// schnell genug lesen, blockiert der Schreibvorgang und damit auch das
    /// Nachziehen des naechsten Frames.
    /// </para>
    /// </summary>
    private async Task<(long BytesUp, long BytesDown)> RelayAsync(
        Stream clientStream,
        SessionTarget target,
        CancellationToken cancellationToken)
    {
        long bytesUp = 0;
        long bytesDown = 0;

        var buffer = new byte[FrameHeader.MaxPayloadLength];
        var sendSequence = NextSequence();

        // Eigener Abbruch fuer die Gegenrichtung. Ohne ihn wuerde ein Agent,
        // der halb schliesst (FIN/Close), den Relay dauerhaft blockieren,
        // solange der Upstream die Verbindung offen haelt - ein Socket- und
        // Task-Leck bis zum Prozessende. Sobald eine Richtung fertig ist,
        // wird die andere ueber das Token beendet.
        using var relayCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var relayToken = relayCts.Token;

        // Richtung 1: Ziel-Socket -> Pipe (immer aktiv).
        var downTask = Task.Run(
            async () =>
            {
                while (true)
                {
                    var read = await target.Socket
                        .ReceiveAsync(buffer.AsMemory(), SocketFlags.None, relayToken)
                        .ConfigureAwait(false);

                    if (read == 0)
                    {
                        await WriteDataLockedAsync(
                                sendSequence++,
                                ReadOnlyMemory<byte>.Empty,
                                fin: true,
                                relayToken)
                            .ConfigureAwait(false);
                        return;
                    }

                    var total = Interlocked.Add(ref bytesDown, read);
                    if (total > target.Limits.MaxBytesDown)
                    {
                        await SendErrorAsync(
                                DenyCodes.LimitExceeded,
                                $"Download-Limit ({target.Limits.MaxBytesDown} Byte) ueberschritten.",
                                relayToken)
                            .ConfigureAwait(false);
                        return;
                    }

                    await WriteDataLockedAsync(
                            sendSequence++,
                            buffer.AsMemory(0, read),
                            fin: false,
                            relayToken)
                        .ConfigureAwait(false);
                }
            },
            CancellationToken.None);

        // Richtung 2: Pipe -> Ziel-Socket.
        var upTask = Task.Run(
            async () =>
            {
                while (true)
                {
                    var message = await FrameCodec.ReadAsync(clientStream, relayToken).ConfigureAwait(false);
                    if (message is null)
                    {
                        return;
                    }

                    if (message.Kind == FrameKind.Close)
                    {
                        return;
                    }

                    if (message.Kind == FrameKind.Ping)
                    {
                        await WriteControlLockedAsync(
                                FrameKind.Pong,
                                sendSequence++,
                                relayToken)
                            .ConfigureAwait(false);
                        continue;
                    }

                    if (message.Kind != FrameKind.Data)
                    {
                        await SendErrorAsync(
                                DenyCodes.ProtocolError,
                                $"Frame {message.KindName} waehrend eines Relays.",
                                relayToken)
                            .ConfigureAwait(false);
                        return;
                    }

                    var payload = message.Payload;
                    if (payload.Length == 0)
                    {
                        if (message.HasFlag(FrameFlags.Fin))
                        {
                            return;
                        }

                        continue;
                    }

                    var total = Interlocked.Add(ref bytesUp, payload.Length);
                    if (total > target.Limits.MaxBytesUp)
                    {
                        await SendErrorAsync(
                                DenyCodes.LimitExceeded,
                                $"Upload-Limit ({target.Limits.MaxBytesUp} Byte) ueberschritten.",
                                relayToken)
                            .ConfigureAwait(false);
                        return;
                    }

                    await target.Socket
                        .SendAsync(payload, SocketFlags.None, relayToken)
                        .ConfigureAwait(false);
                }
            },
            CancellationToken.None);

        await Task.WhenAny(upTask, downTask).ConfigureAwait(false);

        // Gegenrichtung abbrechen, damit kein Lesevorgang auf dem Socket
        // haengen bleibt. Anschliessend beide Tasks sauber auslaufen lassen;
        // der Socket wird im finally des Aufrufers geschlossen.
        relayCts.Cancel();

        try
        {
            await Task.WhenAll(upTask, downTask).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException
            or SocketException
            or OperationCanceledException
            or ObjectDisposedException)
        {
            // Erwartet beim Abbau.
        }

        return (Interlocked.Read(ref bytesUp), Interlocked.Read(ref bytesDown));
    }

    /// <summary>
    /// Interception-Pfad: TLS wird von Cordon terminiert, dann wird ein
    /// einzelner HTTP-Request gelesen, gegen die Scope-Regeln geprueft und
    /// weitergereicht. Die Antwort wird opak zurueckkopiert.
    /// <para>
    /// Bewusst auf <b>einen</b> Request pro Connect beschraenkt. Ein
    /// vollstaendiger HTTP-Proxy mit Keep-Alive, Chunked-Encoding und
    /// Trailer-Handling waere erheblich mehr Parsing-Code auf dem Pfad eines
    /// kompromittierten Agenten - also mehr Angriffsflaeche fuer wenig Gewinn.
    /// </para>
    /// </summary>
    private async Task<(long BytesUp, long BytesDown)> RunInterceptedHttpAsync(
        SessionTarget target,
        CancellationToken cancellationToken)
    {
        var authority = _authority
            ?? throw new InvalidOperationException("Interception ohne CA.");

        // leaveInnerStreamOpen: true - die Pipe gehoert dem AgentListener und
        // wird dort geschlossen. Wuerde der SslStream sie mitentsorgen, waere
        // das ein doppeltes Dispose auf einem Handle, das der Aufrufer noch
        // besitzt.
        var sslStream = new SslStream(_pipe, leaveInnerStreamOpen: true);

        try
        {
            await sslStream.AuthenticateAsServerAsync(
                    TlsInterception.CreateServerOptions(authority, target.Host),
                    cancellationToken)
                .ConfigureAwait(false);

            var request = await HttpRequestReader
                .ReadAsync(sslStream, MaxInterceptedRequestBytes, cancellationToken)
                .ConfigureAwait(false);

            if (request is null)
            {
                return (0, 0);
            }

            var policy = _policyStore.Current;
            var identity = _identity!;

            if (policy is null)
            {
                await HttpRequestReader
                    .WriteErrorAsync(sslStream, 503, "Cordon: keine aktive Policy.", cancellationToken)
                    .ConfigureAwait(false);
                return (request.TotalBytes, 0);
            }

            var host = HostNormalizer.Normalize(target.Host);
            var decision = PolicyEngine.Evaluate(
                policy,
                identity,
                host,
                target.Port,
                TargetKind.Http,
                request.Method,
                request.Path);

            _audit.Write(AuditLog.Event(
                    decision.Verdict == Verdict.Allow ? AuditEvents.ConnectAllow : AuditEvents.ConnectDeny) with
            {
                AgentId = _agentId,
                CorrelationId = _correlationId,
                ScopeId = decision.ScopeId,
                Verdict = decision.Verdict == Verdict.Allow ? "allow" : "deny",
                Reason = decision.Reason,
                Code = decision.Code,
                Identity = ToAuditIdentity(identity),
                Target = ToAuditTarget(TargetKind.Http, host, target.Port, request.Method, request.Path),
                Detail = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["inspected"] = "true",
                    ["contentLength"] = request.ContentLength.ToString(System.Globalization.CultureInfo.InvariantCulture),
                },
            });

            if (decision.Verdict != Verdict.Allow)
            {
                await HttpRequestReader
                    .WriteErrorAsync(
                        sslStream,
                        403,
                        $"Cordon: {decision.Code} - {decision.Reason}",
                        cancellationToken)
                    .ConfigureAwait(false);
                return (request.TotalBytes, 0);
            }

            // Request in Ursprungsform an den Upstream schicken: die
            // absolute Form ("GET https://host/path") ist nur zwischen
            // Proxy und Client gueltig.
            var forwardedHeader = request.ToUpstreamHeaderBytes();
            await target.Socket.SendAsync(forwardedHeader, SocketFlags.None, cancellationToken)
                .ConfigureAwait(false);

            // Body gestreamt nachreichen. Gepuffert wuerde ein grosser
            // Upload einen entsprechend grossen Block in Cordon erzeugen.
            await HttpRequestReader.CopyBodyAsync(
                    sslStream,
                    target.Socket,
                    request.ContentLength,
                    cancellationToken)
                .ConfigureAwait(false);

            var bytesDown = await HttpRequestReader.CopyResponseAsync(
                    target.Socket,
                    sslStream,
                    target.Limits.MaxBytesDown,
                    cancellationToken)
                .ConfigureAwait(false);

            return (forwardedHeader.Length + request.ContentLength, bytesDown);
        }
        finally
        {
            // Entsorgt nur die TLS-Schicht, nicht die darunterliegende Pipe
            // (leaveInnerStreamOpen). Ein Dispose-Fehler darf das Ergebnis
            // nicht verdraengen - die Uebertragung ist bereits erfolgt.
            await sslStream.DisposeAsync().ConfigureAwait(false);
        }
    }

    private Task DenyConnectAsync(string code, string reason, CancellationToken cancellationToken) =>
        SendAsync(
            FrameKind.ConnectDeny,
            new ConnectDeny { Code = code, Reason = reason },
            cancellationToken);

    private async Task SendAsync<T>(byte kind, T header, CancellationToken cancellationToken)
        where T : class
    {
        // Die Zuordnung Typ -> JsonTypeInfo muss explizit sein, damit die
        // source-generierte Serialisierung greift (kein Reflektionspfad, der
        // beim Trimmen verschwinden koennte). Ein unbekannter Typ ist ein
        // Programmierfehler und wirft - besser als stillschweigend etwas
        // anderes zu serialisieren.
        var typeInfo = ResolveTypeInfo<T>();

        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await FrameCodec.WriteAsync(
                    _pipe,
                    kind,
                    FrameFlags.None,
                    NextSequence(),
                    header,
                    typeInfo,
                    ReadOnlyMemory<byte>.Empty,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    /// <summary>Schreibt einen Kontrollframe unter der Pipe-Schreibsperre.</summary>
    private async Task WriteControlLockedAsync(byte kind, ushort seq, CancellationToken cancellationToken)
    {
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await FrameCodec.WriteControlAsync(_pipe, kind, seq, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    /// <summary>Schreibt einen Datenframe unter der Pipe-Schreibsperre.</summary>
    private async Task WriteDataLockedAsync(
        ushort seq,
        ReadOnlyMemory<byte> payload,
        bool fin,
        CancellationToken cancellationToken)
    {
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await FrameCodec.WriteDataAsync(_pipe, seq, payload, fin, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private static System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> ResolveTypeInfo<T>()
        where T : class
    {
        var context = CordonJsonContext.Default;

        if (typeof(T) == typeof(HelloAck))
        {
            return (System.Text.Json.Serialization.Metadata.JsonTypeInfo<T>)(object)context.HelloAck;
        }

        if (typeof(T) == typeof(ConnectOk))
        {
            return (System.Text.Json.Serialization.Metadata.JsonTypeInfo<T>)(object)context.ConnectOk;
        }

        if (typeof(T) == typeof(ConnectDeny))
        {
            return (System.Text.Json.Serialization.Metadata.JsonTypeInfo<T>)(object)context.ConnectDeny;
        }

        if (typeof(T) == typeof(ErrorMessage))
        {
            return (System.Text.Json.Serialization.Metadata.JsonTypeInfo<T>)(object)context.ErrorMessage;
        }

        if (typeof(T) == typeof(CloseNotice))
        {
            return (System.Text.Json.Serialization.Metadata.JsonTypeInfo<T>)(object)context.CloseNotice;
        }

        throw new NotSupportedException($"Kein JsonTypeInfo fuer {typeof(T).Name} registriert.");
    }

    /// <summary>Prueft einen Signer-Subject case-insensitiv gegen eine Whitelist.</summary>
    private static bool IsSignerAllowed(string? signerSubject, IReadOnlyList<string> allowedSigners)
    {
        // Fehlendes oder leeres Subject ist niemals erlaubt (fail closed).
        if (string.IsNullOrWhiteSpace(signerSubject))
        {
            return false;
        }

        foreach (var allowed in allowedSigners)
        {
            if (string.Equals(allowed, signerSubject, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private Task SendErrorAsync(string code, string reason, CancellationToken cancellationToken) =>
        SendAsync(FrameKind.Error, new ErrorMessage { Code = code, Reason = reason }, cancellationToken);

    private ushort NextSequence() => unchecked(_sequence++);

    private void WriteRejected(string reason, ClientIdentity? identity) =>
        _audit.Write(AuditLog.Event(AuditEvents.ClientRejected) with
        {
            AgentId = _agentId,
            CorrelationId = _correlationId,
            Verdict = "deny",
            Reason = reason,
            Identity = ToAuditIdentity(identity),
        });

    private void WriteProtocolViolation(string reason) =>
        _audit.Write(AuditLog.Event(AuditEvents.ProtocolViolation) with
        {
            AgentId = _agentId,
            CorrelationId = _correlationId,
            Verdict = "deny",
            Reason = reason,
            Identity = ToAuditIdentity(_identity),
        });

    private void WriteConnectDeny(
        ClientIdentity identity,
        string rawHost,
        int port,
        string? code,
        string? reason)
    {
        var host = HostNormalizer.Normalize(rawHost);

        _audit.Write(AuditLog.Event(AuditEvents.ConnectDeny) with
        {
            AgentId = _agentId,
            CorrelationId = _correlationId,
            Verdict = "deny",
            Code = code,
            Reason = reason,
            Identity = ToAuditIdentity(identity),
            Target = new AuditTargetDto
            {
                Kind = TargetKind.Connect.ToString(),
                Host = host.IsValid ? host.Value : null,
                RawHost = rawHost,
                Port = port,
            },
        });
    }

    private static AuditIdentityDto ToAuditIdentity(ClientIdentity? identity) => identity is null
        ? new AuditIdentityDto()
        : new AuditIdentityDto
        {
            Pid = identity.Pid,
            ImagePath = identity.ImagePath,
            ImageSha256 = identity.ImageSha256,
            PackageSid = identity.PackageSid,
            Integrity = identity.Integrity.ToString(),
            IsAppContainer = identity.IsAppContainer,
            Capabilities = identity.Capabilities,
            SignerSubject = identity.SignerSubject,
        };

    private static AuditTargetDto ToAuditTarget(
        TargetKind kind,
        NormalizedHost host,
        int port,
        string? method,
        string? path) => new()
        {
            Kind = kind.ToString(),
            Host = host.Value,
            RawHost = host.Value,
            Port = port,
            Method = method,
            Path = path,
        };
}
