using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Text;

namespace Cordon.Core.Policy;

/// <summary>
/// Normalisiert und validiert den Zielhost, bevor irgendeine Policy
/// ausgewertet wird.
/// <para>
/// Der Host stammt zwar aus einem JSON-Feld (also nicht aus rohem HTTP) und
/// ist damit nicht header-injizierbar. Er wird hier trotzdem als
/// <b>feindliche Eingabe</b> behandelt: jeder Normalisierungsschritt, der
/// fehlt, ist eine Umgehung von Wildcard-Regeln (z. B. <c>example.com.</c>
/// oder <c>EXAMPLE.com</c>).
/// </para>
/// </summary>
public static class HostNormalizer
{
    /// <summary>Maximale Laenge eines DNS-Namens inklusive Punkten (RFC 1035).</summary>
    public const int MaxHostLength = 253;

    /// <summary>Maximale Laenge eines einzelnen Labels.</summary>
    public const int MaxLabelLength = 63;

    public static NormalizedHost Normalize(string? rawHost)
    {
        if (string.IsNullOrWhiteSpace(rawHost))
        {
            return NormalizedHost.Failure("Host ist leer.");
        }

        var value = rawHost.Trim();

        // IPv6-Literal in Klammern: [::1]
        if (value.Length >= 2 && value[0] == '[' && value[^1] == ']')
        {
            value = value[1..^1];
        }

        if (value.Length == 0 || value.Length > MaxHostLength + 2)
        {
            return NormalizedHost.Failure($"Host-Laenge unzulaessig ({value.Length}).");
        }

        // Zeichen, die in einem Hostnamen nichts zu suchen haben. '@' ist der
        // klassische userinfo-Trick, '\\' und '/' koennten Pfadlogik stoeren,
        // Steuerzeichen koennten Logs faelschen.
        foreach (var c in value)
        {
            if (char.IsControl(c) || c is ' ' or '\t' or '@' or '/' or '\\' or '#' or '?' or '%' or '\0')
            {
                return NormalizedHost.Failure($"Host enthaelt unzulaessiges Zeichen (U+{(int)c:X4}).");
            }
        }

        // Ein abschliessender Punkt macht aus "example.com." formal einen
        // FQDN. Ohne Entfernen wuerde "* .example.com" nicht matchen.
        value = value.TrimEnd('.');
        if (value.Length == 0)
        {
            return NormalizedHost.Failure("Host besteht nur aus Punkten.");
        }

        // IP-Literal (v4 oder v6)?
        if (TryParseLiteral(value, out var address))
        {
            return NormalizedHost.FromLiteral(value, address);
        }

        // Nur Ziffern, Punkte und Doppelpunkte => sollte ein IP-Literal sein,
        // ist aber keines. Nicht als DNS-Name durchwinken.
        if (LooksLikeIpLiteral(value))
        {
            return NormalizedHost.Failure("Sieht wie ein IP-Literal aus, ist aber keines.");
        }

        return NormalizeDnsName(value);
    }

    private static NormalizedHost NormalizeDnsName(string value)
    {
        // IDN auf ASCII (Punycode) abbilden, damit "münchen.de" und
        // "xn--mnchen-3ya.de" identisch behandelt werden.
        string ascii;
        try
        {
            ascii = new IdnMapping().GetAscii(value);
        }
        catch (ArgumentException ex)
        {
            return NormalizedHost.Failure($"IDN-Konvertierung fehlgeschlagen: {ex.Message}");
        }

        ascii = ascii.ToLowerInvariant();

        if (ascii.Length > MaxHostLength)
        {
            return NormalizedHost.Failure($"DNS-Name zu lang ({ascii.Length} > {MaxHostLength}).");
        }

        var labels = ascii.Split('.');
        if (labels.Length < 2)
        {
            // Ein einzelnes Label ist kein aufloesbarer Zielhost. "localhost"
            // wird hier bewusst abgelehnt, bevor die Denylist greift.
            return NormalizedHost.Failure("DNS-Name hat kein Punkt-getrenntes Suffix.");
        }

        foreach (var label in labels)
        {
            if (label.Length == 0)
            {
                return NormalizedHost.Failure("DNS-Name enthaelt ein leeres Label.");
            }

            if (label.Length > MaxLabelLength)
            {
                return NormalizedHost.Failure($"Label zu lang ({label.Length}).");
            }

            if (label[0] == '-' || label[^1] == '-')
            {
                return NormalizedHost.Failure("Label beginnt oder endet mit '-'.");
            }

            foreach (var c in label)
            {
                if (!char.IsAsciiLetterOrDigit(c) && c != '-')
                {
                    return NormalizedHost.Failure($"Label enthaelt unzulaessiges Zeichen '{c}'.");
                }
            }
        }

        return NormalizedHost.Success(ascii, HostForm.DnsName, null);
    }

    private static bool TryParseLiteral(string value, out IPAddress address)
    {
        // IPAddress.TryParse akzeptiert auch "1" (=> 0.0.0.1) und "1.2"
        // (=> 1.0.0.2). Solche Kurzformen sind eine bekannte SSRF-Umgehung
        // und werden deshalb explizit abgelehnt.
        if (!IPAddress.TryParse(value, out var parsed))
        {
            address = IPAddress.None;
            return false;
        }

        if (parsed.AddressFamily == AddressFamily.InterNetwork)
        {
            var parts = value.Split('.');
            if (parts.Length != 4)
            {
                address = IPAddress.None;
                return false;
            }

            foreach (var part in parts)
            {
                if (part.Length == 0 || part.Length > 3 || !part.All(char.IsAsciiDigit))
                {
                    address = IPAddress.None;
                    return false;
                }
            }
        }
        else if (parsed.AddressFamily == AddressFamily.InterNetworkV6)
        {
            // Kein Zone-Index: "fe80::1%eth0" umgeht Adressvergleiche.
            if (value.Contains('%', StringComparison.Ordinal))
            {
                address = IPAddress.None;
                return false;
            }

            if (!value.Contains(':', StringComparison.Ordinal))
            {
                address = IPAddress.None;
                return false;
            }
        }
        else
        {
            address = IPAddress.None;
            return false;
        }

        address = parsed;
        return true;
    }

    private static bool LooksLikeIpLiteral(string value)
    {
        var hasDigit = false;
        foreach (var c in value)
        {
            if (char.IsAsciiDigit(c))
            {
                hasDigit = true;
                continue;
            }

            if (c is not ('.' or ':' or 'x' or 'X' or 'a' or 'b' or 'c' or 'd' or 'e' or 'f'
                or 'A' or 'B' or 'C' or 'D' or 'E' or 'F'))
            {
                return false;
            }
        }

        // Enthaelt nur Hex-Ziffern, Punkte und Doppelpunkte, und mindestens
        // eine Ziffer: das sollte ein IP-Literal sein.
        return hasDigit;
    }
}

public enum HostForm
{
    /// <summary>Aufloesbarer DNS-Name, ASCII/Punycode, kleingeschrieben.</summary>
    DnsName = 0,

    /// <summary>IP-Literal (v4 oder v6).</summary>
    IpLiteral = 1,
}

/// <summary>Ergebnis der Host-Normalisierung.</summary>
public sealed record NormalizedHost
{
    public required bool IsValid { get; init; }

    /// <summary>Normalisierter Host (ASCII, lowercase, ohne Trailing-Dot / Klammern).</summary>
    public string Value { get; init; } = string.Empty;

    public HostForm Form { get; init; }

    /// <summary>Adresse, falls <see cref="Form"/> = <see cref="HostForm.IpLiteral"/>.</summary>
    public IPAddress? Address { get; init; }

    /// <summary>Fehlertext, falls <see cref="IsValid"/> = <c>false</c>.</summary>
    public string? Error { get; init; }

    public static NormalizedHost Success(string value, HostForm form, IPAddress? address) => new()
    {
        IsValid = true,
        Value = value,
        Form = form,
        Address = address,
    };

    public static NormalizedHost FromLiteral(string value, IPAddress address) => new()
    {
        IsValid = true,
        Value = value,
        Form = HostForm.IpLiteral,
        Address = address,
    };

    public static NormalizedHost Failure(string error) => new()
    {
        IsValid = false,
        Error = error,
    };
}
