using System.Collections.Concurrent;
using Cordon.Core.Configuration;
using Cordon.Core.Policy;

namespace Cordon.Gateway;

/// <summary>Konfiguration des Gateways.</summary>
public sealed record GatewayOptions
{
    /// <summary>Optionale CA fuer TLS-Interception. <c>null</c> = nur Passthrough.</summary>
    public Tls.CertificateAuthority? Authority { get; init; }

    /// <summary>Verbindungs-Timeout zum Ziel.</summary>
    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(15);

    /// <summary>
    /// Optionaler globaler Override fuer den erwarteten Image-Pfad.
    /// <para>
    /// <c>null</c> (Default) bedeutet: der Root wird <b>pro Agent</b> aus den
    /// <c>imageRoots</c> des passenden Scopes abgeleitet. Das ist die
    /// richtige Granularitaet - ein einzelner globaler Root wuerde bei
    /// mehreren Agenten entweder zu weit oder zu eng greifen.
    /// </para>
    /// </summary>
    public string? ExpectedImagePathOverride { get; init; }

    /// <summary>Anzahl gleichzeitiger Pipe-Instanzen pro Agent.</summary>
    public int PipeInstancesPerAgent { get; init; } = 4;
}

/// <summary>Status eines Agent-Listeners.</summary>
public sealed record AgentListenerStatus(
    string AgentId,
    string PackageSid,
    int ActiveConnections,
    long TotalConnections);

/// <summary>
/// Der Gateway-Host: haelt pro Agent eine Pipe-Instanz offen und passt den
/// Satz der Listener an die aktive Policy an.
/// <para>
/// Ein Listener pro Agent ist Absicht: der Pipe-Name ist damit an die
/// Agent-Id gebunden, und die DACL kann exakt die Package-SID dieses einen
/// Agenten enthalten. Ein gemeinsamer Listener muesste alle Agenten
/// zulassen und die Unterscheidung allein der Token-Pruefung ueberlassen -
/// also eine Bindung statt zwei.
/// </para>
/// </summary>
public sealed class GatewayServer : IAsyncDisposable
{
    private readonly GatewayOptions _options;
    private readonly PolicyStore _policyStore;
    private readonly Core.Audit.AuditLog _audit;
    private readonly ConcurrentDictionary<string, AgentListener> _listeners = new(StringComparer.OrdinalIgnoreCase);
    private readonly ScopeConnectionLimiter _limiter = new();
    private readonly CancellationTokenSource _shutdown = new();

    public GatewayServer(GatewayOptions options, PolicyStore policyStore, Core.Audit.AuditLog audit)
    {
        _options = options;
        _policyStore = policyStore;
        _audit = audit;
        _policyStore.Reloaded += OnPolicyReloaded;
    }

    /// <summary>Aktuell lauschende Agenten mit Zaehlern.</summary>
    public IReadOnlyList<AgentListenerStatus> Status =>
        _listeners.Values.Select(l => l.GetStatus()).OrderBy(s => s.AgentId, StringComparer.Ordinal).ToList();

    /// <summary>
    /// Startet die Listener fuer alle Agenten der aktiven Policy und laeuft,
    /// bis <paramref name="cancellationToken"/> ausgeloest wird.
    /// </summary>
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _shutdown.Token);

        // Erster Sync: ohne aktive Policy gibt es nichts zu lauschen.
        SyncListeners();

        if (_listeners.IsEmpty)
        {
            _audit.Write(Core.Audit.AuditLog.Event(Core.Audit.AuditEvents.GatewayStart) with
            {
                Verdict = "deny",
                Reason = "Keine Policy mit Agenten geladen. Es wird nicht gelauscht (fail closed).",
            });
        }
        else
        {
            _audit.Write(Core.Audit.AuditLog.Event(Core.Audit.AuditEvents.GatewayStart) with
            {
                Verdict = "allow",
                Detail = _listeners.Values
                    .Select(l => l.GetStatus())
                    .ToDictionary(s => s.AgentId, s => s.PackageSid, StringComparer.Ordinal),
            });
        }

        try
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, linked.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Herunterfahren.
        }
    }

    public async ValueTask DisposeAsync()
    {
        _policyStore.Reloaded -= OnPolicyReloaded;

        await _shutdown.CancelAsync().ConfigureAwait(false);

        foreach (var listener in _listeners.Values)
        {
            await listener.DisposeAsync().ConfigureAwait(false);
        }

        _listeners.Clear();
        _shutdown.Dispose();
    }

    private void OnPolicyReloaded(bool success, IReadOnlyList<string> errors)
    {
        if (!success)
        {
            // Policy kaputt: bestehende Listener bleiben unveraendert. Die
            // zuletzt gueltige Policy gilt weiter, statt in einen
            // ungeschuetzten Zustand zu fallen.
            _audit.Write(Core.Audit.AuditLog.Event(Core.Audit.AuditEvents.PolicyLoadFailed) with
            {
                Verdict = "deny",
                Reason = string.Join(" | ", errors),
            });
            return;
        }

        _audit.Write(Core.Audit.AuditLog.Event(Core.Audit.AuditEvents.PolicyReloaded) with
        {
            Verdict = "allow",
        });

        SyncListeners();
    }

    private void SyncListeners()
    {
        var policy = _policyStore.Current;
        var desired = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);

        if (policy is not null)
        {
            foreach (var scope in policy.Scopes)
            {
                foreach (var agentId in scope.Grant.Principals.AgentIds)
                {
                    // Der Image-Root wird PRO AGENT aufgeloest. Ein Agent kann
                    // in mehreren Scopes stehen; der erste konfigurierte Root
                    // gewinnt. Widerspruechliche Roots fuer denselben Agenten
                    // sind ein Konfigurationsfehler, den 'cordon scope show'
                    // sichtbar macht.
                    var root = ResolveImageRoot(scope) ?? _options.ExpectedImagePathOverride;

                    if (desired.TryGetValue(agentId, out var existing))
                    {
                        if (existing is null && root is not null)
                        {
                            desired[agentId] = root;
                        }
                    }
                    else
                    {
                        desired[agentId] = root;
                    }
                }
            }
        }

        // Entfernte Agenten: Listener beenden.
        foreach (var existing in _listeners.Keys.ToList())
        {
            if (!desired.ContainsKey(existing))
            {
                if (_listeners.TryRemove(existing, out var listener))
                {
                    _ = listener.DisposeAsync().AsTask();
                }
            }
        }

        // Agenten, deren Image-Root sich geaendert hat: Listener neu
        // aufbauen. Sonst wuerde die zweite Bindung mit einem veralteten
        // Erwartungswert weiterlaufen.
        foreach (var agentId in desired.Keys.ToList())
        {
            if (_listeners.TryGetValue(agentId, out var existing)
                && !string.Equals(existing.ExpectedImageRoot, desired[agentId], StringComparison.OrdinalIgnoreCase))
            {
                if (_listeners.TryRemove(agentId, out var stale))
                {
                    _ = stale.DisposeAsync().AsTask();
                }
            }
        }

        // Neue Agenten: Listener starten. Die Package-SID wird aus dem
        // AppContainer-Profil abgeleitet - existiert kein Profil, kann der
        // Agent gar nicht gestartet worden sein, und es wird nicht gelauscht.
        foreach (var pair in desired)
        {
            var agentId = pair.Key;

            if (_listeners.ContainsKey(agentId))
            {
                continue;
            }

            var sid = TryResolvePackageSid(agentId);
            if (sid is null)
            {
                _audit.Write(Core.Audit.AuditLog.Event(Core.Audit.AuditEvents.ClientRejected) with
                {
                    AgentId = agentId,
                    Verdict = "deny",
                    Reason = "Kein AppContainer-Profil vorhanden. Listener wird nicht gestartet. "
                        + "Agent zuerst mit 'cordon run' starten.",
                });
                continue;
            }

            var listener = new AgentListener(
                agentId,
                sid,
                pair.Value,
                _options,
                _policyStore,
                _audit,
                _limiter,
                _shutdown.Token);

            if (_listeners.TryAdd(agentId, listener))
            {
                listener.Start();
            }
            else
            {
                _ = listener.DisposeAsync().AsTask();
            }
        }
    }

    /// <summary>
    /// Ermittelt den Image-Root, der aus diesem Scope fuer den Agenten gilt.
    /// Gibt <c>null</c> zurueck, wenn der Scope keinen nennt.
    /// <para>
    /// <c>imageRoots</c> steht auf der Ebene des Principals, gilt also fuer
    /// alle Agent-Ids dieses Scopes. Der erste nicht-leere Eintrag gewinnt.
    /// </para>
    /// </summary>
    private static string? ResolveImageRoot(CompiledScope scope)
    {
        ArgumentNullException.ThrowIfNull(scope);

        foreach (var root in scope.Grant.Principals.ImageRoots)
        {
            if (!string.IsNullOrWhiteSpace(root))
            {
                return root;
            }
        }

        return null;
    }

    private static System.Security.Principal.SecurityIdentifier? TryResolvePackageSid(string agentId)
    {
        try
        {
            return Windows.AppContainerProfile.TryResolve(agentId);
        }
        catch (Exception ex) when (ex is PlatformNotSupportedException or DllNotFoundException)
        {
            return null;
        }
    }
}
