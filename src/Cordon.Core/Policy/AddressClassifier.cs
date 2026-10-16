using System.Net;
using System.Net.Sockets;
using System.Numerics;

namespace Cordon.Core.Policy;

/// <summary>
/// Ein Netzbereich in CIDR-Notation. Rechnet mit <see cref="BigInteger"/>,
/// damit IPv4 und IPv6 denselben Code nutzen.
/// </summary>
public sealed class Cidr
{
    private readonly BigInteger _network;
    private readonly BigInteger _mask;

    private Cidr(AddressFamily family, BigInteger network, BigInteger mask, int prefixLength, string text)
    {
        Family = family;
        _network = network;
        _mask = mask;
        PrefixLength = prefixLength;
        Text = text;
    }

    public AddressFamily Family { get; }

    public int PrefixLength { get; }

    public string Text { get; }

    public static bool TryParse(string text, out Cidr? cidr)
    {
        cidr = null;
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var value = text.Trim();
        var prefixLength = -1;
        var slash = value.IndexOf('/', StringComparison.Ordinal);
        if (slash >= 0)
        {
            var prefixText = value[(slash + 1)..];
            value = value[..slash];
            if (!int.TryParse(prefixText, out prefixLength) || prefixLength < 0)
            {
                return false;
            }
        }

        if (!IPAddress.TryParse(value, out var address))
        {
            return false;
        }

        var bits = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        prefixLength = prefixLength < 0 ? bits : prefixLength;
        if (prefixLength > bits)
        {
            return false;
        }

        var bytes = address.GetAddressBytes();
        if (bytes.Length != bits / 8)
        {
            return false;
        }

        var host = new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
        var mask = PrefixToMask(prefixLength, bits);
        var network = host & mask;

        cidr = new Cidr(address.AddressFamily, network, mask, prefixLength, text.Trim());
        return true;
    }

    /// <summary>
    /// Wie <see cref="TryParse"/>, wirft aber bei Fehlern. Ausschliesslich
    /// fuer die fest eingebauten Bereiche gedacht - dort ist ein Fehler ein
    /// Programmierfehler, kein Konfigurationsfehler.
    /// </summary>
    public static Cidr ParseStatic(string text)
    {
        if (!TryParse(text, out var cidr) || cidr is null)
        {
            throw new InvalidOperationException($"Interner Fehler: '{text}' ist kein gueltiges CIDR.");
        }

        return cidr;
    }

    public bool Contains(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.AddressFamily != Family)
        {
            // Kein implizites Mappen von IPv4 auf IPv6. Wer beides will,
            // schreibt beide Bereiche in die Konfiguration.
            return false;
        }

        var bytes = address.GetAddressBytes();
        var value = new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
        return (value & _mask) == _network;
    }

    private static BigInteger PrefixToMask(int prefixLength, int bits)
    {
        if (prefixLength == 0)
        {
            return BigInteger.Zero;
        }

        var ones = (BigInteger.One << prefixLength) - 1;
        return ones << (bits - prefixLength);
    }
}

/// <summary>
/// Kategorisiert Adressen und beantwortet die Default-Deny-Fragen
/// (Loopback, Link-Local, Multicast, ...).
/// <para>
/// Diese Pruefung laeuft <b>nach</b> der Namensaufloesung auf der konkreten
/// Ziel-IP. Nur so ist DNS-Rebinding ausgeschlossen: ein Name, der
/// zunaechst auf eine oeffentliche IP zeigt und beim zweiten Lookup auf
/// 127.0.0.1, wird hier anhand der tatsaechlich verbundenen Adresse
/// abgelehnt.
/// </para>
/// </summary>
public static class AddressClassifier
{
    private static readonly Cidr[] LoopbackRanges =
    [
        Cidr.ParseStatic("127.0.0.0/8"),
        Cidr.ParseStatic("::1/128"),
    ];

    private static readonly Cidr[] LinkLocalRanges =
    [
        Cidr.ParseStatic("169.254.0.0/16"),
        Cidr.ParseStatic("fe80::/10"),
    ];

    private static readonly Cidr[] NeverAllowedRanges =
    [
        Cidr.ParseStatic("0.0.0.0/8"),        // "this network"
        Cidr.ParseStatic("100.64.0.0/10"),    // CGNAT
        Cidr.ParseStatic("192.0.0.0/24"),     // IETF Protocol Assignments
        Cidr.ParseStatic("192.0.2.0/24"),     // TEST-NET-1
        Cidr.ParseStatic("198.18.0.0/15"),    // Benchmarking
        Cidr.ParseStatic("198.51.100.0/24"),  // TEST-NET-2
        Cidr.ParseStatic("203.0.113.0/24"),   // TEST-NET-3
        Cidr.ParseStatic("224.0.0.0/4"),      // Multicast
        Cidr.ParseStatic("240.0.0.0/4"),      // Reserved / Broadcast
        Cidr.ParseStatic("255.255.255.255/32"),
        Cidr.ParseStatic("::/128"),           // Unspecified
        Cidr.ParseStatic("::ffff:0:0/96"),    // IPv4-mapped: umgeht v4-Regeln
        Cidr.ParseStatic("64:ff9b::/96"),     // NAT64: umgeht v4-Regeln
        Cidr.ParseStatic("ff00::/8"),         // Multicast v6
    ];

    private static readonly Cidr[] PrivateRanges =
    [
        Cidr.ParseStatic("10.0.0.0/8"),
        Cidr.ParseStatic("172.16.0.0/12"),
        Cidr.ParseStatic("192.168.0.0/16"),
        Cidr.ParseStatic("fc00::/7"),
    ];

    /// <summary>Eine IP, die nie ein Ziel sein darf - unabhaengig von der Policy.</summary>
    public static bool IsNeverAllowed(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        return Matches(NeverAllowedRanges, address);
    }

    public static bool IsLoopback(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        return Matches(LoopbackRanges, address);
    }

    public static bool IsLinkLocal(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        return Matches(LinkLocalRanges, address);
    }

    public static bool IsPrivate(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        return Matches(PrivateRanges, address);
    }

    /// <summary>
    /// Vollstaendige Zulassungspruefung fuer eine aufgeloeste Zieladresse.
    /// </summary>
    public static bool IsPermitted(IPAddress address, bool allowLoopback, bool allowLinkLocal)
    {
        ArgumentNullException.ThrowIfNull(address);

        if (IsNeverAllowed(address))
        {
            return false;
        }

        if (!allowLoopback && IsLoopback(address))
        {
            return false;
        }

        if (!allowLinkLocal && IsLinkLocal(address))
        {
            return false;
        }

        return true;
    }

    private static bool Matches(Cidr[] ranges, IPAddress address)
    {
        foreach (var range in ranges)
        {
            if (range.Contains(address))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Kurzbeschreibung fuer Audit-Zwecke.</summary>
    public static string Describe(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (IsLoopback(address))
        {
            return "loopback";
        }

        if (IsLinkLocal(address))
        {
            return "link-local";
        }

        if (IsPrivate(address))
        {
            return "private";
        }

        if (IsNeverAllowed(address))
        {
            return "reserved";
        }

        return "public";
    }
}
