using System.Collections.Concurrent;
using System.Text.Json;
using System.Threading.Channels;
using FileGuardian.Protocol;

namespace FileGuardian.Core.Plugins;

public sealed class PluginTimeoutException(string message) : TimeoutException(message);

public sealed class PluginRemoteException(string message) : Exception(message);

/// <summary>
/// Host side of the JSON-RPC link. Works over any pair of streams, so it is
/// unit-testable without launching a process.
///
/// Trust model: everything read from the plugin is untrusted. Messages are
/// size-capped, plugins can only send responses and two notification types,
/// and log notifications are rate-limited.
/// </summary>
public sealed class PluginConnection : IAsyncDisposable
{
    private const int MaxLogsPerSecond = 50;

    private readonly string _pluginId;
    private readonly BoundedLineReader _reader;
    private readonly JsonLineWriter _writer;
    private readonly Channel<RpcMessage> _outbound = Channel.CreateBounded<RpcMessage>(
        new BoundedChannelOptions(512) { SingleReader = true, FullMode = BoundedChannelFullMode.Wait });
    private readonly ConcurrentDictionary<long, TaskCompletionSource<JsonElement?>> _pending = new();
    private readonly CancellationTokenSource _lifetime = new();

    private long _nextId;
    private long _logWindowStart;
    private int _logsInWindow;
    private Task? _readLoop;
    private Task? _writeLoop;
    private int _closed;

    public PluginConnection(string pluginId, Stream fromPlugin, Stream toPlugin)
    {
        _pluginId = pluginId;
        _reader = new BoundedLineReader(fromPlugin);
        _writer = new JsonLineWriter(toPlugin);
    }

    public event Action<LogParams>? LogReceived;
    public event Action? PanelChanged;

    /// <summary>Raised once when the link fails or closes.</summary>
    public event Action<Exception?>? Closed;

    public void Start()
    {
        _readLoop = Task.Run(ReadLoopAsync);
        _writeLoop = Task.Run(WriteLoopAsync);
    }

    public async Task<TResult> RequestAsync<TParams, TResult>(
        string method, TParams parameters, TimeSpan timeout, CancellationToken token)
    {
        if (Volatile.Read(ref _closed) != 0)
            throw new InvalidOperationException($"Plugin '{_pluginId}' is not connected.");

        long id = Interlocked.Increment(ref _nextId);
        var tcs = new TaskCompletionSource<JsonElement?>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[id] = tcs;

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(token, _lifetime.Token);
        timeoutCts.CancelAfter(timeout);

        try
        {
            await _outbound.Writer.WriteAsync(new RpcMessage
            {
                Id = id,
                Method = method,
                Params = ProtocolJson.ToElement(parameters)
            }, timeoutCts.Token);

            JsonElement? result = await tcs.Task.WaitAsync(timeoutCts.Token);
            return ProtocolJson.FromElement<TResult>(result);
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested && !_lifetime.IsCancellationRequested)
        {
            throw new PluginTimeoutException(
                $"Plugin '{_pluginId}' did not answer '{method}' within {timeout.TotalMilliseconds:0} ms.");
        }
        finally
        {
            _pending.TryRemove(id, out _);
        }
    }

    /// <summary>Fire-and-forget. Returns false (dropped) if the plugin is backed up.</summary>
    public bool TryNotify<TParams>(string method, TParams parameters)
    {
        if (Volatile.Read(ref _closed) != 0)
            return false;

        return _outbound.Writer.TryWrite(new RpcMessage
        {
            Method = method,
            Params = ProtocolJson.ToElement(parameters)
        });
    }

    private async Task WriteLoopAsync()
    {
        try
        {
            await foreach (RpcMessage message in _outbound.Reader.ReadAllAsync(_lifetime.Token))
                await _writer.WriteAsync(message, _lifetime.Token);
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            Close(ex);
        }
    }

    private async Task ReadLoopAsync()
    {
        Exception? failure = null;

        try
        {
            while (!_lifetime.IsCancellationRequested)
            {
                string? line = await _reader.ReadLineAsync(_lifetime.Token);
                if (line is null)
                    break;

                if (line.Length == 0)
                    continue;

                RpcMessage message = JsonSerializer.Deserialize<RpcMessage>(line, ProtocolJson.Options)
                    ?? throw new ProtocolViolationException("Null message.");

                if (message.IsResponse)
                    HandleResponse(message);
                else if (message.IsNotification)
                    HandleNotification(message);
                else
                    throw new ProtocolViolationException("Plugins may not send requests to the host.");
            }
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            failure = ex;
        }

        Close(failure);
    }

    private void HandleResponse(RpcMessage message)
    {
        if (!_pending.TryRemove(message.Id!.Value, out var tcs))
            return; // Late reply after a timeout; ignore.

        if (message.Error is { } error)
            tcs.TrySetException(new PluginRemoteException(
                TextSanitizer.ForDisplay(error.Message, 1024)));
        else
            tcs.TrySetResult(message.Result);
    }

    private void HandleNotification(RpcMessage message)
    {
        switch (message.Method)
        {
            case ProtocolConstants.Methods.Log:
                if (!AllowLog())
                    return;
                LogReceived?.Invoke(ProtocolJson.FromElement<LogParams>(message.Params));
                break;

            case ProtocolConstants.Methods.PanelChanged:
                PanelChanged?.Invoke();
                break;

            default:
                throw new ProtocolViolationException($"Unknown notification '{TextSanitizer.ForDisplay(message.Method, 64)}'.");
        }
    }

    private bool AllowLog()
    {
        long second = Environment.TickCount64 / 1000;
        if (second != _logWindowStart)
        {
            _logWindowStart = second;
            _logsInWindow = 0;
        }

        return ++_logsInWindow <= MaxLogsPerSecond;
    }

    private void Close(Exception? reason)
    {
        if (Interlocked.Exchange(ref _closed, 1) != 0)
            return;

        _outbound.Writer.TryComplete();
        _lifetime.Cancel();

        foreach (var pending in _pending.Values)
            pending.TrySetException(new InvalidOperationException($"Plugin '{_pluginId}' disconnected."));

        Closed?.Invoke(reason);
    }

    public async ValueTask DisposeAsync()
    {
        Close(null);

        foreach (Task? t in new[] { _readLoop, _writeLoop })
        {
            if (t is null) continue;
            try { await t.WaitAsync(TimeSpan.FromSeconds(2)); } catch { }
        }

        _lifetime.Dispose();
    }
}
