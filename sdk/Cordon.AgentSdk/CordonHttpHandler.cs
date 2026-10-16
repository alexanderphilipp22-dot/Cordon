using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Text;

namespace Cordon.AgentSdk;

/// <summary>
/// Ein <see cref="HttpMessageHandler"/>, der jeden Request durch einen
/// Cordon-Tunnel schickt - einschliesslich HTTPS, das als opaker
/// TLS-Passthrough ueber die Pipe laeuft.
/// <para>
/// <b>Es wird kein Proxy konfiguriert.</b> Es gibt keinen lokalen Port und
/// keine Umgebungsvariable, an die sich ein Agent halten muesste. Der
/// Transport ist die Pipe, und die Identitaet des Aufrufers stammt aus dem
/// Kernel. Ein Agent, der diesen Handler nicht benutzt, kann trotzdem nicht
/// ins Netz - er bekommt dann einfach keinen Zugriff.
/// </para>
/// <example>
/// <code>
/// await using var client = new CordonAgentClient("research");
/// await client.ConnectAsync();
///
/// using var http = new HttpClient(new CordonHttpHandler(client))
/// {
///     Timeout = Timeout.InfiniteTimeSpan,
/// };
///
/// var response = await http.GetAsync("https://docs.python.org/3/");
/// </code>
/// </example>
/// </summary>
public sealed class CordonHttpHandler : HttpMessageHandler
{
    private readonly CordonAgentClient _client;

    public CordonHttpHandler(CordonAgentClient client)
    {
        ArgumentNullException.ThrowIfNull(client);
        _client = client;
    }

    /// <summary>
    /// Antworten werden vollstaendig in den Speicher gelesen, bevor sie
    /// zurueckgegeben werden.
    /// <para>
    /// Grund: der Tunnel ist ein einziger, sequenzieller Bytestrom. Wuerde
    /// die Antwort gestreamt, muesste der <see cref="HttpClient"/> sie
    /// konsumieren, bevor der naechste Request denselben Tunnel benutzen
    /// kann - eine Fehlerquelle, die schwer zu diagnostizieren ist. Ein
    /// Cordon-Gateway ist ein Kontrollpunkt, kein Download-Beschleuniger;
    /// die Obergrenze ist bewusst gesetzt.
    /// </para>
    /// </summary>
    public int MaxResponseBytes { get; init; } = 128 * 1024 * 1024;

    /// <summary>
    /// Obergrenze fuer die Request-Zeile plus Header.
    /// </summary>
    public int MaxRequestHeaderBytes { get; init; } = 64 * 1024;

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (request.RequestUri is null)
        {
            throw new InvalidOperationException("Request ohne RequestUri.");
        }

        var uri = request.RequestUri;

        if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
        {
            throw new NotSupportedException(
                $"Schema '{uri.Scheme}' wird nicht unterstuetzt. Cordon tunnelt nur HTTP und HTTPS.");
        }

        var host = uri.IdnHost;
        var port = uri.Port;
        var useTls = uri.Scheme == Uri.UriSchemeHttps;

        // Der Tunnel wird pro Request geoeffnet. Das ist Absicht: jeder
        // Zielkontakt wird damit einzeln gegen die Scopes geprueft. Ein
        // wiederverwendeter Tunnel koennte nach einem Policy-Reload
        // weiterlaufen, obwohl der Grant entzogen wurde.
        await using var tunnel = await _client
            .OpenTunnelAsync(host, port, cancellationToken)
            .ConfigureAwait(false);

        Stream effectiveStream = tunnel;
        System.Net.Security.SslStream? sslStream = null;

        try
        {
            if (useTls)
            {
                sslStream = new System.Net.Security.SslStream(tunnel, leaveInnerStreamOpen: true);

                // Die Serverauthentifizierung bleibt AKTIV. Cordon sieht
                // keinen Klartext und kann daher nicht fuer den Agenten
                // pruefen. Ein deaktiviertes Zertifikatschecking waere eine
                // Einladung an jeden MITM, der nicht Cordon ist.
                await sslStream.AuthenticateAsClientAsync(
                        new System.Net.Security.SslClientAuthenticationOptions
                        {
                            TargetHost = host,
                            EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12
                                | System.Security.Authentication.SslProtocols.Tls13,
                            CertificateRevocationCheckMode =
                                System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck,
                        },
                        cancellationToken)
                    .ConfigureAwait(false);

                effectiveStream = sslStream;
            }

            var requestBytes = await BuildRequestBytesAsync(request, cancellationToken).ConfigureAwait(false);

            await effectiveStream.WriteAsync(requestBytes, cancellationToken).ConfigureAwait(false);
            await effectiveStream.FlushAsync(cancellationToken).ConfigureAwait(false);

            var responseBytes = await ReadAllAsync(effectiveStream, cancellationToken).ConfigureAwait(false);
            return ResponseParser.Parse(responseBytes);
        }
        catch (IOException ex)
        {
            var terminal = tunnel.TerminalError;
            throw new CordonDeniedException(
                "tunnel_failed",
                terminal is null
                    ? $"Tunnel zu {host}:{port} brach ab: {ex.Message}"
                    : $"Gateway meldete: {terminal}",
                ex);
        }
        finally
        {
            if (sslStream is not null)
            {
                await sslStream.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private async Task<byte[]> BuildRequestBytesAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var uri = request.RequestUri!;
        var builder = new StringBuilder(512);

        var path = uri.PathAndQuery;
        if (string.IsNullOrEmpty(path))
        {
            path = "/";
        }

        builder.Append(request.Method.Method)
            .Append(' ')
            .Append(path)
            .Append(" HTTP/1.1\r\n");

        var hostHeaderWritten = false;

        foreach (var header in request.Headers)
        {
            if (IsRestrictedRequestHeader(header.Key))
            {
                continue;
            }

            if (header.Key.Equals("Host", StringComparison.OrdinalIgnoreCase))
            {
                hostHeaderWritten = true;
            }

            AppendHeader(builder, header.Key, header.Value);
        }

        if (!hostHeaderWritten)
        {
            // Host MUSS gesetzt sein (HTTP/1.1). Der Wert stammt aus der URI,
            // nicht aus Agenteneingabe.
            builder.Append("Host: ").Append(FormatHostHeader(uri)).Append("\r\n");
        }

        byte[]? body = null;

        if (request.Content is not null)
        {
            body = await request.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);

            foreach (var header in request.Content.Headers)
            {
                if (IsRestrictedRequestHeader(header.Key))
                {
                    continue;
                }

                AppendHeader(builder, header.Key, header.Value);
            }

            if (!request.Content.Headers.Contains("Content-Length"))
            {
                builder.Append("Content-Length: ")
                    .Append(body.Length.ToString(CultureInfo.InvariantCulture))
                    .Append("\r\n");
            }
        }

        // Kein Keep-Alive: der Tunnel wird pro Request geschlossen, und der
        // Gateway-Relay endet mit dem Schliessen des Upstream-Sockets. Ein
        // "Connection: close" macht das explizit statt implizit.
        builder.Append("Connection: close\r\n");
        builder.Append("\r\n");

        var headerBytes = Encoding.ASCII.GetBytes(builder.ToString());

        if (headerBytes.Length > MaxRequestHeaderBytes)
        {
            throw new CordonDeniedException(
                "request_too_large",
                $"Request-Header ueberschreitet {MaxRequestHeaderBytes} Byte.");
        }

        if (body is null || body.Length == 0)
        {
            return headerBytes;
        }

        var result = new byte[headerBytes.Length + body.Length];
        headerBytes.CopyTo(result, 0);
        body.CopyTo(result, headerBytes.Length);
        return result;
    }

    private async Task<byte[]> ReadAllAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[64 * 1024];

        while (true)
        {
            var read = await stream.ReadAsync(chunk, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            if (buffer.Length + read > MaxResponseBytes)
            {
                throw new CordonDeniedException(
                    "response_too_large",
                    $"Antwort ueberschreitet {MaxResponseBytes} Byte.");
            }

            buffer.Write(chunk, 0, read);
        }

        return buffer.ToArray();
    }

    /// <summary>
    /// Header, die ausschliesslich die Verbindung zwischen Client und
    /// Proxy beschreiben oder vom Handler selbst gesetzt werden. Sie
    /// duerfen nicht an den Ursprungsserver weitergereicht werden.
    /// </summary>
    private static bool IsRestrictedRequestHeader(string name) =>
        name.Equals("Connection", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Proxy-Connection", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Keep-Alive", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Upgrade", StringComparison.OrdinalIgnoreCase);

    private static void AppendHeader(StringBuilder builder, string name, IEnumerable<string> values)
    {
        foreach (var value in values)
        {
            builder.Append(name).Append(": ").Append(value).Append("\r\n");
        }
    }

    private static string FormatHostHeader(Uri uri)
    {
        var isDefaultPort = (uri.Scheme == Uri.UriSchemeHttps && uri.Port == 443)
            || (uri.Scheme == Uri.UriSchemeHttp && uri.Port == 80);

        return isDefaultPort
            ? uri.IdnHost
            : string.Create(CultureInfo.InvariantCulture, $"{uri.IdnHost}:{uri.Port}");
    }

    /// <summary>Parser fuer die Antwort. Bewusst minimal und strikt.</summary>
    private static class ResponseParser
    {
        public static HttpResponseMessage Parse(byte[] raw)
        {
            if (raw.Length == 0)
            {
                throw new CordonDeniedException(
                    "empty_response",
                    "Das Gateway lieferte keine Antwort. Vermutlich wurde die Verbindung "
                    + "durch die Policy beendet.");
            }

            var headerEnd = FindHeaderEnd(raw);
            if (headerEnd < 0)
            {
                throw new CordonDeniedException(
                    "malformed_response",
                    "Antwort ohne vollstaendige Header-Sektion empfangen.");
            }

            var headerText = Encoding.ASCII.GetString(raw, 0, headerEnd);
            var lines = headerText.Split("\r\n", StringSplitOptions.None);

            var statusParts = lines[0].Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
            if (statusParts.Length < 2
                || !statusParts[0].StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase)
                || !int.TryParse(statusParts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var status))
            {
                throw new CordonDeniedException(
                    "malformed_response",
                    $"Ungueltige Statuszeile: '{lines[0]}'.");
            }

            var response = new HttpResponseMessage((HttpStatusCode)status)
            {
                ReasonPhrase = statusParts.Length > 2 ? statusParts[2] : null,
                Version = statusParts[0].EndsWith("1.0", StringComparison.Ordinal)
                    ? HttpVersion.Version10
                    : HttpVersion.Version11,
            };

            // Antwort-Header, die nicht in response.Headers passen, werden
            // gepuffert und erst nach der Content-Zuweisung gesetzt.
            var responseContentHeaders = new List<KeyValuePair<string, string>>();

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

                if (name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase)
                    && value.Contains("chunked", StringComparison.OrdinalIgnoreCase))
                {
                    chunked = true;
                    continue;
                }

                if (name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                {
                    // Wird nach der Dekodierung aus dem tatsaechlichen Body
                    // neu gesetzt - der Originalwert waere bei einer
                    // Chunked-Antwort falsch.
                    continue;
                }

                if (!response.Headers.TryAddWithoutValidation(name, value))
                {
                    responseContentHeaders.Add(new KeyValuePair<string, string>(name, value));
                }
            }

            var bodyOffset = headerEnd;
            var bodyLength = raw.Length - headerEnd;

            byte[] body;
            if (chunked)
            {
                // Chunked-Antworten werden dekodiert, damit der Aufrufer die
                // Nutzdaten erhaelt und nicht die Chunk-Rahmen.
                body = ChunkedDecoder.Decode(raw.AsSpan(bodyOffset, bodyLength));
            }
            else
            {
                body = new byte[bodyLength];
                if (bodyLength > 0)
                {
                    Array.Copy(raw, bodyOffset, body, 0, bodyLength);
                }
            }

            // Content wird ZULETZT zugewiesen: dann setzt ByteArrayContent
            // Content-Length selbst auf die korrekte (ggf. dekodierte) Laenge.
            response.Content = new ByteArrayContent(body);

            foreach (var header in responseContentHeaders)
            {
                _ = response.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            return response;
        }

        private static int FindHeaderEnd(byte[] buffer)
        {
            for (var i = 0; i + 3 < buffer.Length; i++)
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

    /// <summary>
    /// Minimaler Chunked-Decoder. Wirft bei ungueltigen Rahmen
    /// <see cref="CordonDeniedException"/> statt still etwas Falsches
    /// zurueckzugeben.
    /// </summary>
    internal static class ChunkedDecoder
    {
        public static byte[] Decode(ReadOnlySpan<byte> input)
        {
            using var output = new MemoryStream();
            var position = 0;

            while (true)
            {
                var lineEnd = IndexOfCrlf(input, position);
                if (lineEnd < 0)
                {
                    throw new CordonDeniedException(
                        "malformed_response",
                        "Chunked-Antwort endete ohne abschliessenden Chunk.");
                }

                var sizeLine = Encoding.ASCII.GetString(input[position..lineEnd]);

                // Chunk-Extensions abschneiden (nach ';').
                var semicolon = sizeLine.IndexOf(';', StringComparison.Ordinal);
                if (semicolon >= 0)
                {
                    sizeLine = sizeLine[..semicolon];
                }

                if (!int.TryParse(
                        sizeLine.Trim(),
                        NumberStyles.HexNumber,
                        CultureInfo.InvariantCulture,
                        out var size)
                    || size < 0)
                {
                    throw new CordonDeniedException(
                        "malformed_response",
                        $"Ungueltige Chunk-Groesse: '{sizeLine}'.");
                }

                position = lineEnd + 2;

                if (size == 0)
                {
                    return output.ToArray();
                }

                if (position + size > input.Length)
                {
                    throw new CordonDeniedException(
                        "malformed_response",
                        "Chunked-Antwort endete mitten in einem Chunk.");
                }

                output.Write(input.Slice(position, size));
                position += size;

                // Auf den Chunk abschliessendes CRLF pruefen.
                if (position + 1 >= input.Length
                    || input[position] != (byte)'\r'
                    || input[position + 1] != (byte)'\n')
                {
                    throw new CordonDeniedException(
                        "malformed_response",
                        "Chunk wird nicht von CRLF abgeschlossen.");
                }

                position += 2;
            }
        }

        private static int IndexOfCrlf(ReadOnlySpan<byte> input, int start)
        {
            for (var i = start; i + 1 < input.Length; i++)
            {
                if (input[i] == (byte)'\r' && input[i + 1] == (byte)'\n')
                {
                    return i;
                }
            }

            return -1;
        }
    }
}
