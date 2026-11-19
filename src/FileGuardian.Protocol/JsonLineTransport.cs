using System.Buffers;
using System.Text;
using System.Text.Json;

namespace FileGuardian.Protocol;

/// <summary>
/// Reads '\n'-terminated lines with a hard size cap so a misbehaving peer
/// cannot exhaust memory by never sending a newline.
/// </summary>
public sealed class BoundedLineReader(
    Stream stream,
    int maxLineBytes = ProtocolConstants.MaxMessageBytes,
    bool truncateOversizedLines = false)
{
    private readonly byte[] _buffer = new byte[16 * 1024];
    private readonly ArrayBufferWriter<byte> _line = new();
    private int _start;
    private int _end;
    private bool _discarding;

    /// <summary>Returns null at end of stream.</summary>
    public async ValueTask<string?> ReadLineAsync(CancellationToken token)
    {
        while (true)
        {
            int newline = Array.IndexOf(_buffer, (byte)'\n', _start, _end - _start);

            if (newline >= 0)
            {
                Append(_start, newline - _start);
                _start = newline + 1;

                bool wasDiscarding = _discarding;
                _discarding = false;

                string text = Decode();
                _line.Clear();

                return wasDiscarding ? text + " …[truncated]" : text;
            }

            Append(_start, _end - _start);
            _start = _end = 0;

            int read = await stream.ReadAsync(_buffer, token).ConfigureAwait(false);

            if (read == 0)
            {
                if (_line.WrittenCount == 0)
                    return null;

                string tail = Decode();
                _line.Clear();
                return tail;
            }

            _end = read;
        }
    }

    private void Append(int offset, int count)
    {
        if (count <= 0 || _discarding)
            return;

        if (_line.WrittenCount + count > maxLineBytes)
        {
            if (!truncateOversizedLines)
                throw new ProtocolViolationException(
                    $"Message exceeded {maxLineBytes} bytes.");

            int room = maxLineBytes - _line.WrittenCount;
            if (room > 0)
                _line.Write(_buffer.AsSpan(offset, room));

            _discarding = true;
            return;
        }

        _line.Write(_buffer.AsSpan(offset, count));
    }

    private string Decode()
    {
        ReadOnlySpan<byte> span = _line.WrittenSpan;
        if (span.Length > 0 && span[^1] == (byte)'\r')
            span = span[..^1];
        return Encoding.UTF8.GetString(span);
    }
}

/// <summary>Serializes one JSON message per line; safe for concurrent callers.</summary>
public sealed class JsonLineWriter(Stream stream)
{
    private static readonly byte[] NewLine = "\n"u8.ToArray();
    private readonly SemaphoreSlim _gate = new(1, 1);

    public async Task WriteAsync(RpcMessage message, CancellationToken token)
    {
        // Compact System.Text.Json output never contains a raw newline;
        // newlines inside strings are escaped.
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(message, ProtocolJson.Options);

        if (bytes.Length > ProtocolConstants.MaxMessageBytes)
            throw new ProtocolViolationException("Outgoing message is too large.");

        await _gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            await stream.WriteAsync(bytes, token).ConfigureAwait(false);
            await stream.WriteAsync(NewLine, token).ConfigureAwait(false);
            await stream.FlushAsync(token).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }
}
