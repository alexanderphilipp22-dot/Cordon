using System.IO.Pipes;
using System.Security.Principal;
using Cordon.Core.Audit;
using Cordon.Core.Configuration;

namespace Cordon.Gateway;

/// <summary>
/// Ein Pipe-Listener fuer genau einen Agenten.
/// <para>
/// Der Listener haelt dauerhaft <see cref="GatewayOptions.PipeInstancesPerAgent"/>
/// Instanzen offen, damit ein Agent mehrere gleichzeitige Ziele bedienen
/// kann. Jede Instanz wird nach dem Verbindungsende sofort ersetzt.
/// </para>
/// </summary>
internal sealed class AgentListener : IAsyncDisposable
{
    private readonly string _agentId;
    private readonly SecurityIdentifier _packageSid;
    private readonly string? _expectedImageRoot;
    private readonly GatewayOptions _options;
    private readonly PolicyStore _policyStore;
    private readonly AuditLog _audit;
    private readonly CancellationTokenSource _shutdown;
    private readonly UpstreamConnector _connector;
    private readonly ScopeConnectionLimiter _limiter;
    private readonly List<Task> _acceptLoops = [];
    private readonly object _stateLock = new();

    private long _totalConnections;
    private int _activeConnections;
    private bool _disposed;

    public AgentListener(
        string agentId,
        SecurityIdentifier packageSid,
        string? expectedImageRoot,
        GatewayOptions options,
        PolicyStore policyStore,
        AuditLog audit,
        ScopeConnectionLimiter limiter,
        CancellationToken shutdownToken)
    {
        _agentId = agentId;
        _packageSid = packageSid;
        _expectedImageRoot = expectedImageRoot;
        _options = options;
        _policyStore = policyStore;
        _audit = audit;
        _limiter = limiter;
        _connector = new UpstreamConnector(options.ConnectTimeout);
        _shutdown = CancellationTokenSource.CreateLinkedTokenSource(shutdownToken);
    }

    /// <summary>
    /// Image-Root, gegen den die Identitaet dieses Agenten gebunden wird.
    /// <c>null</c> bedeutet: keine Image-Bindung, nur Pipe-DACL + Package-SID.
    /// Der Gateway-Host vergleicht diesen Wert, um den Listener neu
    /// aufzubauen, wenn sich die Policy aendert.
    /// </summary>
    public string? ExpectedImageRoot => _expectedImageRoot;

    public AgentListenerStatus GetStatus() => new(
        _agentId,
        _packageSid.Value,
        Volatile.Read(ref _activeConnections),
        Interlocked.Read(ref _totalConnections));

    public void Start()
    {
        for (var i = 0; i < _options.PipeInstancesPerAgent; i++)
        {
            _acceptLoops.Add(Task.Run(() => AcceptLoopAsync(_shutdown.Token)));
        }
    }

    public async ValueTask DisposeAsync()
    {
        lock (_stateLock)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
        }

        await _shutdown.CancelAsync().ConfigureAwait(false);

        try
        {
            await Task.WhenAll(_acceptLoops).WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is TimeoutException or OperationCanceledException)
        {
            // Beim Herunterfahren akzeptabel: die Pipe-Instanzen werden
            // spaetestens mit dem Prozessende freigegeben.
        }

        _acceptLoops.Clear();
        _shutdown.Dispose();
    }

    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;

            try
            {
                pipe = PipeSecurityFactory.CreateInstance(
                    _agentId,
                    _packageSid,
                    maxInstances: _options.PipeInstancesPerAgent);

                await pipe.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                pipe?.Dispose();
                return;
            }
            catch (IOException)
            {
                // Pipe konnte nicht erzeugt werden (Name belegt, Rechte).
                // Kurz warten und erneut versuchen, statt die Schleife zu
                // beenden - ein voruebergehender Fehler darf den Agenten
                // nicht dauerhaft aussperren.
                pipe?.Dispose();
                await DelayAsync(TimeSpan.FromSeconds(1), cancellationToken).ConfigureAwait(false);
                continue;
            }

            Interlocked.Increment(ref _totalConnections);

            // Die Verbindung wird in einem eigenen Task behandelt, damit die
            // Annahmeschleife sofort die naechste Instanz bereitstellen kann.
            _ = Task.Run(() => HandleConnectionAsync(pipe, cancellationToken), CancellationToken.None);
        }
    }

    private async Task HandleConnectionAsync(NamedPipeServerStream pipe, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _activeConnections);

        try
        {
            // ------------------------------------------------------------------
            // Identitaet erfassen - VOR dem ersten interpretierten Byte
            // ------------------------------------------------------------------
            // Die Erfassung passiert unmittelbar nach dem Verbindungsaufbau
            // und liefert PID plus Erzeugungszeit. Beides wird an die
            // Verbindung gebunden; die spaetere Aufloesung prueft, dass die PID
            // in der Zwischenzeit nicht neu vergeben wurde.
            var capture = Windows.PipeClientCaptureReader.Capture(pipe.SafePipeHandle);

            if (!capture.Success)
            {
                _audit.Write(AuditLog.Event(AuditEvents.ClientRejected) with
                {
                    AgentId = _agentId,
                    Verdict = "deny",
                    Reason = $"Identitaet nicht erfassbar: {capture.Error}",
                    Code = capture.Win32Error == 0
                        ? Windows.IdentityResolutionErrors.PipeNotConnected
                        : Windows.IdentityResolutionErrors.AccessDenied,
                });

                return;
            }

            // `using`: gibt nach dem Ende der Verbindung die Schreibsperre des
            // ProxyConnection frei. Die Pipe selbst wird weiter unten im
            // finally geschlossen - sie gehoert diesem Listener, nicht der
            // Verbindung.
            using var connection = new ProxyConnection(
                pipe,
                _agentId,
                _packageSid.Value,
                _expectedImageRoot,
                capture.Signature,
                _policyStore,
                _audit,
                _connector,
                _options.Authority,
                _limiter);

            await connection.RunAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // Eine unbehandelte Exception darf den Fire-and-Forget-Task nicht
            // unbeobachtet fehlschlagen lassen. RunAsync hat bereits einen
            // ClientDisconnected-Datensatz geschrieben; hier wird der Fehler
            // zusaetzlich als Anomalie auditiert, statt still zu verschwinden.
            _audit.Write(AuditLog.Event(AuditEvents.ProtocolViolation) with
            {
                AgentId = _agentId,
                Verdict = "deny",
                Reason = $"Unbehandelter Fehler in der Verbindungsbehandlung: "
                    + $"{ex.GetType().Name}: {ex.Message}",
            });
        }
        finally
        {
            Interlocked.Decrement(ref _activeConnections);

            try
            {
                if (pipe.IsConnected)
                {
                    pipe.Disconnect();
                }
            }
            catch (InvalidOperationException)
            {
                // Bereits getrennt.
            }

            await pipe.DisposeAsync().ConfigureAwait(false);
        }
    }

    private static async Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Herunterfahren.
        }
    }
}
