using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace Cordon.Core.Protocol;

/// <summary>
/// Ein gelesener Frame. <see cref="Body"/> ist die rohe Nutzlast des Frames;
/// die Grenze zwischen JSON-Header und Binaer-Payload wird beim Zugriff
/// ermittelt, nicht beim Lesen.
/// </summary>
public sealed class ReceivedMessage
{
    private int _payloadOffset = -1;
    private bool _headerResolved;

    internal ReceivedMessage(byte kind, byte flags, ushort seq, byte[] body)
    {
        Kind = kind;
        Flags = flags;
        Seq = seq;
        Body = body;
    }

    public byte Kind { get; }

    public byte Flags { get; }

    public ushort Seq { get; }

    public byte[] Body { get; }

    public bool IsData => Kind == FrameKind.Data;

    public string KindName => FrameKind.Name(Kind);

    public bool HasFlag(byte flag) => (Flags & flag) == flag;

    /// <summary>Binaer-Payload nach dem JSON-Header. Leer, wenn kein JSON vorhanden ist.</summary>
    public ReadOnlyMemory<byte> Payload
    {
        get
        {
            var offset = ResolvePayloadOffset();
            return offset >= Body.Length ? ReadOnlyMemory<byte>.Empty : Body.AsMemory(offset);
        }
    }

    /// <summary>Der JSON-Header als Rohbytes.</summary>
    public ReadOnlyMemory<byte> JsonHeader
    {
        get
        {
            var offset = ResolvePayloadOffset();
            return Body.AsMemory(0, offset);
        }
    }

    /// <summary>
    /// Deserialisiert den JSON-Header. Gibt <c>null</c> zurueck, wenn kein
    /// JSON vorhanden ist. Wirft <see cref="CordonProtocolException"/> bei
    /// kaputtem JSON - der Aufrufer bricht dann die Verbindung ab.
    /// </summary>
    public T? Parse<T>(JsonTypeInfo<T> typeInfo)
        where T : class
    {
        var offset = ResolvePayloadOffset();
        if (offset == 0)
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize(Body.AsSpan(0, offset), typeInfo);
        }
        catch (JsonException ex)
        {
            throw new CordonProtocolException($"JSON-Header von {KindName} ist ungueltig.", ex);
        }
    }

    /// <summary>Wie <see cref="Parse{T}"/>, aber ohne Exception bei Fehlern.</summary>
    public bool TryParse<T>(JsonTypeInfo<T> typeInfo, out T? value)
        where T : class
    {
        try
        {
            value = Parse(typeInfo);
            return true;
        }
        catch (CordonProtocolException)
        {
            value = null;
            return false;
        }
    }

    private int ResolvePayloadOffset()
    {
        if (_headerResolved)
        {
            return _payloadOffset;
        }

        _headerResolved = true;

        // Leerer Body (Ping/Pong/Close) und Data-Frames tragen grundsaetzlich
        // KEINEN JSON-Header. Insbesondere ein Data-Payload, das mit '{'
        // beginnt (z. B. eine JSON-Antwort), darf NICHT als Header
        // fehlinterpretiert werden - das wuerde die ersten Nutzdaten-Bytes
        // verschlucken.
        if (Body.Length == 0 || Kind == FrameKind.Data)
        {
            _payloadOffset = 0;
            return _payloadOffset;
        }

        // Kontrollframes mit Body muessen mit einem JSON-Objekt beginnen.
        if (Body[0] != (byte)'{')
        {
            throw new CordonProtocolException($"{KindName}-Frame hat keinen JSON-Header.");
        }

        try
        {
            var reader = new Utf8JsonReader(Body, isFinalBlock: true, state: default);
            using var document = JsonDocument.ParseValue(ref reader);
            _ = document.RootElement.ValueKind;

            var consumed = (int)reader.BytesConsumed;
            if (consumed <= 0 || consumed > Body.Length)
            {
                throw new CordonProtocolException(
                    $"{KindName}-Frame hat eine unplausible JSON-Header-Laenge ({consumed}).");
            }

            if (consumed > FrameHeader.MaxJsonHeaderLength)
            {
                throw new CordonProtocolException(
                    $"{KindName}-Frame: JSON-Header zu gross ({consumed} > {FrameHeader.MaxJsonHeaderLength}).");
            }

            _payloadOffset = consumed;
        }
        catch (JsonException ex)
        {
            throw new CordonProtocolException($"JSON-Header von {KindName} ist ungueltig.", ex);
        }

        return _payloadOffset;
    }
}

/// <summary>Lesen und Schreiben von Frames auf einem Bytestrom.</summary>
public static class FrameCodec
{
    /// <summary>
    /// Liest genau einen Frame. Gibt <c>null</c> zurueck, wenn der Peer die
    /// Pipe <b>sauber an einer Framegrenze</b> geschlossen hat.
    /// </summary>
    public static async ValueTask<ReceivedMessage?> ReadAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var headerBytes = new byte[FrameHeader.Size];
        if (!await TryReadExactlyAsync(stream, headerBytes, cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        var header = FrameHeader.ReadFrom(headerBytes);

        if (!FrameKind.IsKnown(header.Kind))
        {
            throw new CordonProtocolException($"Unbekannter Frame-Typ 0x{header.Kind:x2}.");
        }

        if (header.BodyLength > FrameHeader.MaxBodyLength)
        {
            throw new CordonProtocolException(
                $"Frame-Body zu gross: {header.BodyLength} > {FrameHeader.MaxBodyLength}.");
        }

        byte[] body;
        if (header.BodyLength == 0)
        {
            body = [];
        }
        else
        {
            body = new byte[header.BodyLength];
            if (!await TryReadExactlyAsync(stream, body, cancellationToken).ConfigureAwait(false))
            {
                throw new CordonProtocolException("Pipe endete mitten im Frame-Body.");
            }
        }

        return new ReceivedMessage(header.Kind, header.Flags, header.Seq, body);
    }

    /// <summary>Schreibt einen Kontrollframe mit JSON-Header und optionaler Payload.</summary>
    public static ValueTask WriteAsync<T>(
        Stream stream,
        byte kind,
        byte flags,
        ushort seq,
        T? header,
        JsonTypeInfo<T> typeInfo,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
        where T : class
    {
        var json = header is null ? [] : JsonSerializer.SerializeToUtf8Bytes(header, typeInfo);
        return WriteRawAsync(stream, kind, flags, seq, json, payload, cancellationToken);
    }

    /// <summary>Schreibt einen Datenframe: leerer JSON-Header plus Payload.</summary>
    public static ValueTask WriteDataAsync(
        Stream stream,
        ushort seq,
        ReadOnlyMemory<byte> payload,
        bool fin,
        CancellationToken cancellationToken)
    {
        if (payload.Length > FrameHeader.MaxPayloadLength)
        {
            throw new CordonProtocolException($"Payload zu gross: {payload.Length}.");
        }

        return WriteRawAsync(
            stream,
            FrameKind.Data,
            fin ? FrameFlags.Fin : FrameFlags.None,
            seq,
            ReadOnlyMemory<byte>.Empty,
            payload,
            cancellationToken);
    }

    /// <summary>Schreibt einen Frame ohne JSON-Header (Ping/Pong).</summary>
    public static ValueTask WriteControlAsync(
        Stream stream,
        byte kind,
        ushort seq,
        CancellationToken cancellationToken)
        => WriteRawAsync(stream, kind, FrameFlags.None, seq, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, cancellationToken);

    private static async ValueTask WriteRawAsync(
        Stream stream,
        byte kind,
        byte flags,
        ushort seq,
        ReadOnlyMemory<byte> json,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        var bodyLength = json.Length + payload.Length;
        if (bodyLength > FrameHeader.MaxBodyLength)
        {
            throw new CordonProtocolException($"Frame-Body zu gross: {bodyLength}.");
        }

        // Ein einziger Puffer, ein einziger Write: verhindert verschraenkte
        // Teilframes, wenn mehrere Threads auf derselben Pipe schreiben.
        var frame = new byte[FrameHeader.Size + bodyLength];
        new FrameHeader(kind, flags, seq, (uint)bodyLength).WriteTo(frame);
        if (json.Length > 0)
        {
            json.Span.CopyTo(frame.AsSpan(FrameHeader.Size));
        }

        if (payload.Length > 0)
        {
            payload.Span.CopyTo(frame.AsSpan(FrameHeader.Size + json.Length));
        }

        await stream.WriteAsync(frame, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<bool> TryReadExactlyAsync(
        Stream stream,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer[offset..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return false;
            }

            offset += read;
        }

        return true;
    }
}

/// <summary>Protokollverletzung durch den Peer. Fuehrt immer zum Verbindungsabbau.</summary>
public sealed class CordonProtocolException : Exception
{
    public CordonProtocolException(string message)
        : base(message)
    {
    }

    public CordonProtocolException(string message, Exception inner)
        : base(message, inner)
    {
    }

    public CordonProtocolException(string code, string message)
        : base(message)
    {
        Code = code;
    }

    /// <summary>Stabiler Ablehnungscode (z. B. <see cref="Cordon.Core.DenyCodes.ToolNotAllowed"/>).</summary>
    public string? Code { get; }
}
