using System.Net;
using System.Net.Sockets;
using Cordon.Core;
using Cordon.Core.Model;
using Cordon.Core.Policy;

namespace Cordon.Gateway;

/// <summary>Ergebnis eines Upstream-Verbindungsaufbaus.</summary>
public sealed record UpstreamConnectResult
{
    public Socket? Socket { get; init; }

    public IPAddress? RemoteAddress { get; init; }

    public string? DenyCode { get; init; }

    public string? DenyReason { get; init; }

    public bool IsSuccess => Socket is not null;

    public static UpstreamConnectResult Deny(string code, string reason) => new()
    {
        DenyCode = code,
        DenyReason = reason,
    };
}

/// <summary>
/// Baut die ausgehende Verbindung fuer ein erlaubtes Ziel auf - und prueft
/// dabei die <b>aufgeloeste IP</b> gegen die Adressgrenzen.
/// <para>
/// Diese Pruefung ist der Grund, warum DNS-Rebinding hier nicht funktioniert:
/// Ein Angreifer kontrolliert den DNS-Namen und kann dafuer sorgen, dass der
/// erste Lookup auf eine oeffentliche IP zeigt und ein spaeterer auf
/// <c>127.0.0.1</c> oder <c>169.254.169.254</c>. Geprueft wird deshalb nicht
/// der Name, sondern jede Adresse, mit der tatsaechlich verbunden wird.
/// </para>
/// </summary>
public sealed class UpstreamConnector
{
    private readonly TimeSpan _connectTimeout;

    public UpstreamConnector(TimeSpan? connectTimeout = null)
    {
        _connectTimeout = connectTimeout ?? TimeSpan.FromSeconds(15);
    }

    /// <summary>
    /// Loest das Ziel auf und verbindet.
    /// <para>
    /// Es wird <b>kein</b> Retry auf eine bereits abgelehnte Adresse
    /// versucht, und es wird nicht auf eine andere Adresse ausgewichen, wenn
    /// die erste abgelehnt wurde. Ein Ausweichen waere genau der Pfad, den
    /// ein Angreifer mit gemischten A/AAAA-Records ausnutzen wuerde.
    /// </para>
    /// </summary>
    public async Task<UpstreamConnectResult> ConnectAsync(
        NormalizedHost host,
        int port,
        ScopeConfiguration configuration,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(host);
        ArgumentNullException.ThrowIfNull(configuration);

        var portCheck = TargetGate.CheckPort(port);
        if (!portCheck.Allowed)
        {
            return UpstreamConnectResult.Deny(portCheck.Code, portCheck.Reason);
        }

        IReadOnlyList<IPAddress> addresses;

        if (host.Form == HostForm.IpLiteral)
        {
            addresses = [host.Address!];
        }
        else
        {
            try
            {
                addresses = await Dns.GetHostAddressesAsync(host.Value, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (SocketException ex)
            {
                return UpstreamConnectResult.Deny(
                    DenyCodes.UpstreamFailure,
                    $"Namensaufloesung fuer '{host.Value}' fehlgeschlagen: {ex.SocketErrorCode}.");
            }
        }

        if (addresses.Count == 0)
        {
            return UpstreamConnectResult.Deny(
                DenyCodes.UpstreamFailure,
                $"Namensaufloesung fuer '{host.Value}' lieferte keine Adresse.");
        }

        SocketException? lastError = null;

        foreach (var address in addresses)
        {
            var gate = TargetGate.CheckAddress(address, configuration);
            if (!gate.Allowed)
            {
                // Fail closed fuer die gesamte Anfrage: eine gemischte
                // Antwort (eine oeffentliche, eine lokale Adresse) ist ein
                // Angriffsmuster, kein Konfigurationsdetail.
                return UpstreamConnectResult.Deny(
                    gate.Code,
                    $"{gate.Reason} (aufgeloest aus '{host.Value}', Kategorie: "
                    + $"{AddressClassifier.Describe(address)})");
            }

            var family = address.AddressFamily;
            var socket = new Socket(family, SocketType.Stream, ProtocolType.Tcp)
            {
                NoDelay = true,
            };

            try
            {
                using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeoutSource.CancelAfter(_connectTimeout);

                await socket.ConnectAsync(
                        new IPEndPoint(address, port),
                        timeoutSource.Token)
                    .ConfigureAwait(false);

                return new UpstreamConnectResult
                {
                    Socket = socket,
                    RemoteAddress = address,
                };
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                socket.Dispose();
                return UpstreamConnectResult.Deny(
                    DenyCodes.UpstreamFailure,
                    $"Verbindungsaufbau zu {address}:{port} lief in ein Timeout "
                    + $"({_connectTimeout.TotalSeconds:0} s).");
            }
            catch (SocketException ex)
            {
                socket.Dispose();
                lastError = ex;
            }
        }

        return UpstreamConnectResult.Deny(
            DenyCodes.UpstreamFailure,
            $"Verbindungsaufbau zu '{host.Value}:{port}' fehlgeschlagen: "
            + $"{(lastError is null ? "kein Ziel erreichbar" : lastError.SocketErrorCode.ToString())}.");
    }
}
