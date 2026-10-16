using System.Net;
using Cordon.Core.Model;

namespace Cordon.Core.Policy;

/// <summary>Ergebnis einer Einzelpruefung.</summary>
public readonly record struct GateResult(bool Allowed, string Code, string Reason)
{
    public static GateResult Allow() => new(true, string.Empty, string.Empty);

    public static GateResult Deny(string code, string reason) => new(false, code, reason);
}

/// <summary>
/// Die "harte" Zieltpruefung. Laeuft <b>vor</b> jeder Policy-Auswertung und
/// kann durch keinen Scope ausser Kraft gesetzt werden - mit Ausnahme der
/// beiden expliziten Schalter fuer Loopback und Link-Local.
/// <para>
/// Diese Klasse ist der zentrale Punkt gegen SSRF-artige Eskalation: ein
/// Agent, der den Gateway-Prozess (LocalSystem) dazu bringt,
/// <c>http://127.0.0.1:445/</c> oder <c>http://169.254.169.254/</c>
/// (Cloud-Metadata) zu kontaktieren, wuerde die Isolation vollstaendig
/// aushebeln. Deshalb ist die Pruefung hier und nicht im Scope.
/// </para>
/// </summary>
public static class TargetGate
{
    /// <summary>Prueft einen bereits normalisierten Zielhost.</summary>
    public static GateResult CheckHost(NormalizedHost host, ScopeConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(host);
        ArgumentNullException.ThrowIfNull(configuration);

        if (!host.IsValid)
        {
            return GateResult.Deny(DenyCodes.MalformedTarget, host.Error ?? "Host ist ungueltig.");
        }

        if (host.Form == HostForm.DnsName)
        {
            // Ein DNS-Name kann syntaktisch in Ordnung und trotzdem ein
            // bekannter lokaler Name sein. Die IP-Pruefung nach der
            // Aufloesung faengt das ab; hier wird nur die Syntax bewertet.
            return GateResult.Allow();
        }

        return CheckAddress(host.Address!, configuration);
    }

    /// <summary>
    /// Prueft eine aufgeloeste Zieladresse. <b>Muss</b> nach jeder
    /// Namensaufloesung aufgerufen werden - nur so ist DNS-Rebinding
    /// ausgeschlossen, weil die Pruefung auf der tatsaechlich verbundenen
    /// IP erfolgt.
    /// </summary>
    public static GateResult CheckAddress(IPAddress address, ScopeConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(address);
        ArgumentNullException.ThrowIfNull(configuration);

        if (AddressClassifier.IsNeverAllowed(address))
        {
            return GateResult.Deny(
                DenyCodes.DeniedLiteral,
                $"Adresse {address} liegt in einem reservierten oder nicht zulassungsfaehigen Bereich.");
        }

        if (!configuration.AllowLoopback && AddressClassifier.IsLoopback(address))
        {
            return GateResult.Deny(
                DenyCodes.DeniedLiteral,
                $"Adresse {address} ist Loopback. Loopback ist per Default gesperrt (allowLoopback=false).");
        }

        if (!configuration.AllowLinkLocal && AddressClassifier.IsLinkLocal(address))
        {
            return GateResult.Deny(
                DenyCodes.DeniedLiteral,
                $"Adresse {address} ist Link-Local. Link-Local ist per Default gesperrt (allowLinkLocal=false).");
        }

        return GateResult.Allow();
    }

    /// <summary>Prueft eine Liste aufgeloester Adressen. Alle muessen passen.</summary>
    public static GateResult CheckAddresses(IReadOnlyList<IPAddress> addresses, ScopeConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(addresses);

        if (addresses.Count == 0)
        {
            return GateResult.Deny(DenyCodes.UpstreamFailure, "Namensaufloesung lieferte keine Adresse.");
        }

        foreach (var address in addresses)
        {
            var result = CheckAddress(address, configuration);
            if (!result.Allowed)
            {
                return result;
            }
        }

        return GateResult.Allow();
    }

    /// <summary>Prueft einen TCP-Port auf Gueltigkeit.</summary>
    public static GateResult CheckPort(int port)
    {
        if (port is < 1 or > 65535)
        {
            return GateResult.Deny(DenyCodes.MalformedTarget, $"Port {port} liegt ausserhalb 1..65535.");
        }

        return GateResult.Allow();
    }
}
