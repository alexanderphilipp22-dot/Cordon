using System.Buffers.Binary;

namespace Cordon.Core.Protocol;

/// <summary>Frame-Typen des Cordon-Pipe-Protokolls.</summary>
public static class FrameKind
{
    public const byte Hello = 0x01;
    public const byte HelloAck = 0x02;
    public const byte Connect = 0x10;
    public const byte ConnectOk = 0x11;
    public const byte ConnectDeny = 0x12;
    public const byte Data = 0x20;
    public const byte Close = 0x21;
    public const byte Ping = 0x30;
    public const byte Pong = 0x31;
    public const byte Error = 0x7F;

    public static bool IsKnown(byte kind) => kind is
        Hello or HelloAck or Connect or ConnectOk or ConnectDeny or
        Data or Close or Ping or Pong or Error;

    public static string Name(byte kind) => kind switch
    {
        Hello => "hello",
        HelloAck => "hello-ack",
        Connect => "connect",
        ConnectOk => "connect-ok",
        ConnectDeny => "connect-deny",
        Data => "data",
        Close => "close",
        Ping => "ping",
        Pong => "pong",
        Error => "error",
        _ => $"unknown(0x{kind:x2})",
    };
}

/// <summary>Frame-Flags.</summary>
public static class FrameFlags
{
    public const byte None = 0x00;

    /// <summary>Letzter Frame dieses Halbkanals (Half-Close).</summary>
    public const byte Fin = 0x01;
}

/// <summary>
/// Fester 8-Byte-Kopf. Alle Mehrbytefelder sind <b>big-endian</b>, damit das
/// Protokoll nicht von der Host-Endianness abhaengt.
/// <code>
/// Offset 0: Kind     u8
/// Offset 1: Flags    u8
/// Offset 2: Seq      u16 BE
/// Offset 4: BodyLen  u32 BE   (Gesamtlaenge von JSON-Header + Payload)
/// Offset 8: JSON-Header (JsonLen Bytes, UTF-8)
/// danach  : Payload
/// </code>
/// <para>
/// <b>Warum genau <i>ein</i> Laengenfeld:</b> Der Leser muss die Grenze des
/// Frames kennen, bevor er ihn interpretiert. Wuerde die Payload-Laenge nur
/// im JSON stehen, koennte ein Data-Frame ohne JSON-Parsing nicht gerahmt
/// werden. Die Trennung in JSON und Payload ergibt sich beim Schreiben aus
/// der Groesse des serialisierten JSON und beim Lesen aus dem geparsten
/// JSON der jeweiligen Nachricht.
/// </para>
/// </summary>
public readonly record struct FrameHeader(byte Kind, byte Flags, ushort Seq, uint BodyLength)
{
    public const int Size = 8;

    /// <summary>Obergrenze fuer den gesamten Frame-Body (JSON + Payload).</summary>
    public const int MaxBodyLength = 1024 * 1024;

    /// <summary>Obergrenze fuer eine einzelne Daten-Payload.</summary>
    public const int MaxPayloadLength = 256 * 1024;

    /// <summary>
    /// Obergrenze fuer den JSON-Header-Anteil eines Frames. Kontrollframes
    /// (hello/connect/ack/error) tragen nur kleine JSON-Header; ein Frame, der
    /// die gesamte Body-Obergrenze als JSON-Header nutzt, ist ein Anzeichen fuer
    /// einen korrupten oder boeswilligen Bytestrom und wird abgelehnt.
    /// </summary>
    public const int MaxJsonHeaderLength = 64 * 1024;

    public bool HasFlag(byte flag) => (Flags & flag) != 0;

    public void WriteTo(Span<byte> destination)
    {
        if (destination.Length < Size)
        {
            throw new ArgumentException($"Span zu klein: {destination.Length} < {Size}.", nameof(destination));
        }

        destination[0] = Kind;
        destination[1] = Flags;
        BinaryPrimitives.WriteUInt16BigEndian(destination[2..], Seq);
        BinaryPrimitives.WriteUInt32BigEndian(destination[4..], BodyLength);
    }

    public static FrameHeader ReadFrom(ReadOnlySpan<byte> source)
    {
        if (source.Length < Size)
        {
            throw new ArgumentException($"Span zu klein: {source.Length} < {Size}.", nameof(source));
        }

        return new FrameHeader(
            source[0],
            source[1],
            BinaryPrimitives.ReadUInt16BigEndian(source[2..]),
            BinaryPrimitives.ReadUInt32BigEndian(source[4..]));
    }

    public byte[] ToArray()
    {
        var buffer = new byte[Size];
        WriteTo(buffer);
        return buffer;
    }
}
