using System.Globalization;
using System.Net.Sockets;
using System.Text;

namespace Cordon.Gateway;

/// <summary>
/// Ein per Interception gelesener HTTP-Request.
/// <para>
/// Der Parser ist absichtlich <b>minimal</b>: Request-Zeile und Header,
/// sonst nichts. Jede zusaetzliche HTTP-Semantik (Chunked-Encoding,
/// Trailer, Pipelining, Keep-Alive) waere Code auf dem Pfad eines
/// kompromittierten Agenten und damit zusaetzliche Angriffsflaeche.
/// </para>
/// </summary>
internal sealed class HttpRequestMessage
{
    private readonly byte[] _headerBytes;

    private HttpRequestMessage(
        string method,
        string absoluteTarget,
        string version,
        byte[] headerBytes,
        int contentLength)
    {
        Method = method;
        AbsoluteTarget = absoluteTarget;
        Version = version;
        _headerBytes = headerBytes;
        ContentLength = contentLength;
    }

    public string Method { get; }

    /// <summary>Ziel in absoluter Form, wie vom Client gesendet.</summary>
    public string AbsoluteTarget { get; }

    public string Version { get; }

    public int ContentLength { get; }

    /// <summary>Pfad plus Query, wie er an den Upstream geht.</summary>
    public string Path { get; private set; } = "/";

    /// <summary>Host-Header, falls vorhanden.</summary>
    public string? HostHeader { get; private set; }

    /// <summary>Gesamtzahl der gelesenen Header-Bytes.</summary>
    public int TotalBytes => _headerBytes.Length;

    public static HttpRequestMessage Create(
        string method,
        string absoluteTarget,
        string version,
        byte[] headerBytes,
        int contentLength,
        string? hostHeader)
    {
        var message = new HttpRequestMessage(method, absoluteTarget, version, headerBytes, contentLength)
        {
            HostHeader = hostHeader,
            Path = ExtractPath(absoluteTarget),
        };

        return message;
    }

    /// <summary>
    /// Baut die Header fuer den Upstream: Request-Zeile in Ursprungsform,
    /// <c>Connection: close</c> erzwungen (kein Keep-Alive-Zustand, den
    /// Cordon verwalten muesste).
    /// </summary>
    public byte[] ToUpstreamHeaderBytes()
    {
        var text = Encoding.ASCII.GetString(_headerBytes);
        var lines = text.Split("\r\n", StringSplitOptions.None);
        var builder = new StringBuilder(_headerBytes.Length + 64);

        builder.Append(Method).Append(' ').Append(Path).Append(' ').Append(Version).Append("\r\n");

        var hasConnectionHeader = false;

        // Index 0 ist die Request-Zeile; ab 1 folgen die Header bis zum
        // leeren Trenner.
        for (var i = 1; i < lines.Length; i++)
        {
            var line = lines[i];
            if (line.Length == 0)
            {
                break;
            }

            if (line.StartsWith("Proxy-Connection:", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (line.StartsWith("Connection:", StringComparison.OrdinalIgnoreCase))
            {
                hasConnectionHeader = true;
                builder.Append("Connection: close\r\n");
                continue;
            }

            builder.Append(line).Append("\r\n");
        }

        if (!hasConnectionHeader)
        {
            builder.Append("Connection: close\r\n");
        }

        builder.Append("\r\n");
        return Encoding.ASCII.GetBytes(builder.ToString());
    }

    private static string ExtractPath(string target)
    {
        if (target.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            || target.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            var schemeEnd = target.IndexOf("://", StringComparison.Ordinal) + 3;
            var pathStart = target.IndexOf('/', schemeEnd);
            return pathStart < 0 ? "/" : target[pathStart..];
        }

        return target.StartsWith('/') ? target : "/" + target;
    }
}

/// <summary>Liest und schreibt die minimale HTTP-Teilmenge, die Cordon braucht.</summary>
internal static class HttpRequestReader
{
    /// <summary>Obergrenze fuer die Header-Sektion.</summary>
    private const int MaxHeaderBytes = 64 * 1024;

    /// <summary>
    /// Liest Request-Zeile und Header. Gibt <c>null</c> zurueck, wenn der
    /// Client sofort geschlossen hat.
    /// </summary>
    public static async Task<HttpRequestMessage?> ReadAsync(
        Stream stream,
        int maxTotalBytes,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[MaxHeaderBytes];
        var filled = 0;
        var headerEnd = -1;

        while (headerEnd < 0)
        {
            if (filled >= buffer.Length)
            {
                // Header zu gross: kein Weiterlesen, kein Teil-Parsing.
                await WriteErrorAsync(stream, 431, "Cordon: Header zu gross.", cancellationToken)
                    .ConfigureAwait(false);
                return null;
            }

            var read = await stream.ReadAsync(buffer.AsMemory(filled), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return null;
            }

            filled += read;
            headerEnd = FindHeaderEnd(buffer, filled);
        }

        var headerBytes = new byte[headerEnd];
        Array.Copy(buffer, headerBytes, headerEnd);

        var text = Encoding.ASCII.GetString(headerBytes);
        var lines = text.Split("\r\n", StringSplitOptions.None);
        var requestLine = lines[0].Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);

        if (requestLine.Length < 3)
        {
            await WriteErrorAsync(stream, 400, "Cordon: ungueltige Request-Zeile.", cancellationToken)
                .ConfigureAwait(false);
            return null;
        }

        var method = requestLine[0];
        var target = requestLine[1];
        var version = requestLine[2];

        if (!version.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase))
        {
            await WriteErrorAsync(stream, 400, "Cordon: ungueltige HTTP-Version.", cancellationToken)
                .ConfigureAwait(false);
            return null;
        }

        var contentLength = 0;
        string? hostHeader = null;
        var chunked = false;

        for (var i = 1; i < lines.Length; i++)
        {
            var line = lines[i];
            if (line.Length == 0)
            {
                break;
            }

            var colon = line.IndexOf(':', StringComparison.Ordinal);
            if (colon <= 0)
            {
                continue;
            }

            var name = line[..colon].Trim();
            var value = line[(colon + 1)..].Trim();

            if (name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
            {
                if (!int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out contentLength)
                    || contentLength < 0)
                {
                    await WriteErrorAsync(stream, 400, "Cordon: ungueltiger Content-Length.", cancellationToken)
                        .ConfigureAwait(false);
                    return null;
                }
            }
            else if (name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase)
                && value.Contains("chunked", StringComparison.OrdinalIgnoreCase))
            {
                chunked = true;
            }
            else if (name.Equals("Host", StringComparison.OrdinalIgnoreCase))
            {
                hostHeader = value;
            }
        }

        // Chunked-Requests werden nicht unterstuetzt. Ein halb
        // implementierter Chunked-Parser waere ein Request-Smuggling-Risiko
        // und damit schlimmer als eine klare Ablehnung.
        if (chunked)
        {
            await WriteErrorAsync(
                    stream,
                    501,
                    "Cordon: Transfer-Encoding: chunked in Requests wird nicht unterstuetzt.",
                    cancellationToken)
                .ConfigureAwait(false);
            return null;
        }

        if (contentLength > maxTotalBytes)
        {
            await WriteErrorAsync(stream, 413, "Cordon: Request-Body zu gross.", cancellationToken)
                .ConfigureAwait(false);
            return null;
        }

        return HttpRequestMessage.Create(method, target, version, headerBytes, contentLength, hostHeader);
    }

    /// <summary>
    /// Kopiert den Request-Body vom Client zum Upstream. Es wird
    /// <b>gestreamt</b> statt gepuffert, damit ein grosser Upload keinen
    /// grossen Speicherblock in Cordon erzeugt.
    /// </summary>
    public static async Task CopyBodyAsync(
        Stream clientStream,
        Socket upstream,
        int contentLength,
        CancellationToken cancellationToken)
    {
        if (contentLength <= 0)
        {
            return;
        }

        var buffer = new byte[64 * 1024];
        var remaining = contentLength;

        while (remaining > 0)
        {
            var wanted = Math.Min(buffer.Length, remaining);
            var read = await clientStream.ReadAsync(buffer.AsMemory(0, wanted), cancellationToken)
                .ConfigureAwait(false);

            if (read == 0)
            {
                throw new IOException(
                    $"Client schloss die Verbindung nach {contentLength - remaining} von "
                    + $"{contentLength} Body-Bytes.");
            }

            await upstream.SendAsync(buffer.AsMemory(0, read), SocketFlags.None, cancellationToken)
                .ConfigureAwait(false);

            remaining -= read;
        }
    }

    /// <summary>
    /// Kopiert die Antwort, bis der Upstream schliesst. Cordon versucht
    /// <b>nicht</b>, das Ende anhand von <c>Content-Length</c> oder Chunked-
    /// Encoding zu bestimmen - es wird durchgereicht, bis die Verbindung
    /// endet. Das erzwingt <c>Connection: close</c> im weitergeleiteten
    /// Request.
    /// </summary>
    public static async Task<long> CopyResponseAsync(
        Socket upstream,
        Stream clientStream,
        long maxBytes,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[Core.Protocol.FrameHeader.MaxPayloadLength];
        long total = 0;

        while (true)
        {
            var read = await upstream.ReceiveAsync(buffer.AsMemory(), SocketFlags.None, cancellationToken)
                .ConfigureAwait(false);

            if (read == 0)
            {
                break;
            }

            total += read;
            if (total > maxBytes)
            {
                break;
            }

            await clientStream.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            await clientStream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }

        return total;
    }

    /// <summary>
    /// Schreibt eine minimalistische Fehlerantwort. Sie wird nur auf dem
    /// Interception-Pfad verwendet, wo Cordon TLS terminiert und daher
    /// ohnehin eine Antwort formulieren muss.
    /// </summary>
    public static async Task WriteErrorAsync(
        Stream stream,
        int statusCode,
        string message,
        CancellationToken cancellationToken)
    {
        var reason = statusCode switch
        {
            400 => "Bad Request",
            403 => "Forbidden",
            413 => "Payload Too Large",
            431 => "Request Header Fields Too Large",
            501 => "Not Implemented",
            503 => "Service Unavailable",
            _ => "Error",
        };

        // Der Text wird bewusst NICHT als HTML formatiert: eine
        // Fehlermeldung darf keine Skriptausfuehrung im Agenten anregen.
        var body = message + "\n";
        var bodyBytes = Encoding.UTF8.GetBytes(body);

        var head = new StringBuilder(256)
            .Append("HTTP/1.1 ").Append(statusCode).Append(' ').Append(reason).Append("\r\n")
            .Append("Content-Type: text/plain; charset=utf-8\r\n")
            .Append("Content-Length: ").Append(bodyBytes.Length.ToString(CultureInfo.InvariantCulture)).Append("\r\n")
            .Append("Connection: close\r\n")
            .Append("\r\n")
            .ToString();

        await stream.WriteAsync(Encoding.ASCII.GetBytes(head), cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(bodyBytes, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static int FindHeaderEnd(byte[] buffer, int length)
    {
        for (var i = 0; i + 3 < length; i++)
        {
            if (buffer[i] == (byte)'\r'
                && buffer[i + 1] == (byte)'\n'
                && buffer[i + 2] == (byte)'\r'
                && buffer[i + 3] == (byte)'\n')
            {
                return i + 4;
            }
        }

        return -1;
    }
}
