namespace Cordon.AgentSdk;

/// <summary>
/// Ein <see cref="Stream"/>, der einen autorisierten TCP-Tunnel durch die
/// Cordon-Pipe darstellt.
/// <para>
/// Der Stream ist bewusst ein normaler <see cref="Stream"/>: darauf kann ein
/// <c>SslStream</c> und darueber ein
/// <see cref="System.Net.Http.HttpClient"/> liegen. Der Agent benutzt also
/// gewohnte APIs, waehrend der Transport vollstaendig durch die OS-Grenze
/// laeuft.
/// </para>
/// <para>
/// <b>Nicht threadsicher.</b> Ein Tunnel ist ein sequenzieller Bytestrom;
/// parallele Reads oder Writes wuerden die Frame-Reihenfolge zerstoeren.
/// </para>
/// </summary>
public sealed class CordonTunnelStream : Stream
{
    private readonly CordonAgentClient _client;
    private readonly object _stateLock = new();

    private byte[] _pending = [];
    private int _pendingOffset;
    private bool _readEnded;
    private bool _writeEnded;
    private bool _disposed;
    private string? _terminalError;

    internal CordonTunnelStream(CordonAgentClient client)
    {
        _client = client;
    }

    public override bool CanRead => !_disposed;

    public override bool CanWrite => !_disposed && !_writeEnded;

    public override bool CanSeek => false;

    public override long Length =>
        throw new NotSupportedException("Ein Tunnel hat keine Laenge.");

    public override long Position
    {
        get => throw new NotSupportedException("Ein Tunnel ist nicht suchbar.");
        set => throw new NotSupportedException("Ein Tunnel ist nicht suchbar.");
    }

    /// <summary>
    /// Fehler, den das Gateway gemeldet hat, nachdem der Stream endete.
    /// <see cref="CordonHttpHandler"/> wertet ihn aus, damit eine Ablehnung
    /// nicht als leere, erfolgreiche Antwort erscheint.
    /// </summary>
    public string? TerminalError
    {
        get
        {
            lock (_stateLock)
            {
                return _terminalError;
            }
        }
    }

    public override async ValueTask<int> ReadAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (buffer.Length == 0)
        {
            return 0;
        }

        while (true)
        {
            byte[] available;

            lock (_stateLock)
            {
                if (_readEnded)
                {
                    return 0;
                }

                if (_pendingOffset < _pending.Length)
                {
                    available = _pending;
                }
                else
                {
                    available = [];
                }
            }

            if (available.Length > 0)
            {
                int offset;
                lock (_stateLock)
                {
                    offset = _pendingOffset;
                }

                var copy = Math.Min(available.Length - offset, buffer.Length);
                available.AsSpan(offset, copy).CopyTo(buffer.Span);

                lock (_stateLock)
                {
                    _pendingOffset = offset + copy;
                }

                return copy;
            }

            var result = await _client.ReadTunnelDataAsync(cancellationToken).ConfigureAwait(false);

            lock (_stateLock)
            {
                if (result.EndOfStream)
                {
                    _readEnded = true;
                    _terminalError = result.Error;
                    _pending = [];
                    _pendingOffset = 0;
                }
                else if (result.Payload.Length > 0)
                {
                    _pending = result.Payload;
                    _pendingOffset = 0;
                }
                else
                {
                    // Leerer Datenframe ohne FIN: kein Fortschritt, erneut lesen.
                    _pending = [];
                    _pendingOffset = 0;
                }
            }

            if (result.EndOfStream)
            {
                return 0;
            }
        }
    }

    public override async ValueTask WriteAsync(
        ReadOnlyMemory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        lock (_stateLock)
        {
            if (_writeEnded)
            {
                throw new IOException("Der Tunnel ist in Schreibrichtung bereits geschlossen.");
            }
        }

        if (buffer.Length == 0)
        {
            return;
        }

        var offset = 0;
        while (offset < buffer.Length)
        {
            var chunk = Math.Min(Core.Protocol.FrameHeader.MaxPayloadLength, buffer.Length - offset);
            await _client
                .WriteTunnelDataAsync(buffer.Slice(offset, chunk), cancellationToken)
                .ConfigureAwait(false);
            offset += chunk;
        }
    }

    public override Task WriteAsync(
        byte[] buffer,
        int offset,
        int count,
        CancellationToken cancellationToken) =>
        WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override Task<int> ReadAsync(
        byte[] buffer,
        int offset,
        int count,
        CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override void Write(byte[] buffer, int offset, int count) =>
        WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override int Read(byte[] buffer, int offset, int count) =>
        ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override void Flush()
    {
        // Es gibt keinen Puffer: jeder Write geht sofort als Frame raus.
    }

    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public override long Seek(long offset, SeekOrigin origin) =>
        throw new NotSupportedException("Ein Tunnel ist nicht suchbar.");

    public override void SetLength(long value) =>
        throw new NotSupportedException("Ein Tunnel hat keine feste Laenge.");

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            CloseAsync().AsTask().GetAwaiter().GetResult();
        }

        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        await CloseAsync().ConfigureAwait(false);
        await base.DisposeAsync().ConfigureAwait(false);
    }

    private async ValueTask CloseAsync()
    {
        lock (_stateLock)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _writeEnded = true;
        }

        try
        {
            await _client.CloseTunnelAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch (IOException)
        {
            // Peer bereits weg.
        }
        catch (ObjectDisposedException)
        {
            // Pipe bereits geschlossen.
        }
    }
}
