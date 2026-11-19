using System.Text.Json;
using System.Threading.Channels;
using FileGuardian.Protocol;

namespace FileGuardian.Plugin.Sdk;

public static class PluginRunner
{
    /// <summary>Call from Main: <c>return await PluginRunner.RunAsync(new MyPlugin());</c></summary>
    public static async Task<int> RunAsync(FileGuardianPlugin plugin)
    {
        Stream stdin = Console.OpenStandardInput();
        Stream stdout = Console.OpenStandardOutput();

        // Stray Console.WriteLine calls must never corrupt the protocol stream.
        Console.SetOut(Console.Error);

        var session = new PluginSession(plugin, stdin, stdout);
        return await session.RunAsync();
    }
}

internal sealed class PluginSession
{
    private readonly FileGuardianPlugin _plugin;
    private readonly BoundedLineReader _reader;
    private readonly JsonLineWriter _writer;
    private readonly CancellationTokenSource _stop = new();

    // Events are processed in order on one queue so exporters see a stable sequence.
    private readonly Channel<HostEvent> _events = Channel.CreateBounded<HostEvent>(
        new BoundedChannelOptions(1024) { SingleReader = true, FullMode = BoundedChannelFullMode.DropOldest });

    private bool _initialized;

    public PluginSession(FileGuardianPlugin plugin, Stream input, Stream output)
    {
        _plugin = plugin;
        _reader = new BoundedLineReader(input);
        _writer = new JsonLineWriter(output);
        plugin.Attach(this);
    }

    public async Task<int> RunAsync()
    {
        Task eventPump = Task.Run(PumpEventsAsync);

        try
        {
            while (!_stop.IsCancellationRequested)
            {
                string? line = await _reader.ReadLineAsync(_stop.Token);
                if (line is null)
                    break; // Host closed stdin (or died): exit.

                if (line.Length == 0)
                    continue;

                RpcMessage? message = JsonSerializer.Deserialize<RpcMessage>(line, ProtocolJson.Options);
                if (message is null)
                    continue;

                if (message.IsRequest)
                    _ = Task.Run(() => HandleRequestAsync(message));
                else if (message.IsNotification && message.Method == ProtocolConstants.Methods.Event)
                    _events.Writer.TryWrite(ProtocolJson.FromElement<HostEvent>(message.Params));
            }
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync($"Plugin session failed: {ex.Message}");
            return 1;
        }
        finally
        {
            _events.Writer.TryComplete();
            try { await eventPump.WaitAsync(TimeSpan.FromSeconds(2)); } catch { }
        }

        return 0;
    }

    internal void Notify<T>(string method, T payload)
    {
        _ = SendAsync(new RpcMessage { Method = method, Params = ProtocolJson.ToElement(payload) });
    }

    private async Task HandleRequestAsync(RpcMessage request)
    {
        RpcMessage response = new() { Id = request.Id };
        CancellationToken token = _stop.Token;

        try
        {
            object result = await DispatchAsync(request, token);
            response.Result = ProtocolJson.ToElement(result);
        }
        catch (NotSupportedException ex)
        {
            response.Error = new RpcError(ProtocolConstants.ErrorCodes.MethodNotFound, ex.Message);
        }
        catch (Exception ex)
        {
            response.Error = new RpcError(ProtocolConstants.ErrorCodes.PluginError, ex.Message);
        }

        await SendAsync(response);

        if (request.Method == ProtocolConstants.Methods.Shutdown)
            _stop.Cancel();
    }

    private async Task<object> DispatchAsync(RpcMessage request, CancellationToken token)
    {
        if (!_initialized && request.Method != ProtocolConstants.Methods.Initialize)
            throw new InvalidOperationException("Not initialized.");

        switch (request.Method)
        {
            case ProtocolConstants.Methods.Initialize:
            {
                var p = ProtocolJson.FromElement<InitializeParams>(request.Params);
                if (p.ProtocolVersion != ProtocolConstants.ProtocolVersion)
                    throw new InvalidOperationException($"Unsupported protocol version {p.ProtocolVersion}.");

                _plugin.ApplySettings(p.Settings);
                await _plugin.OnInitializedAsync(token);
                _initialized = true;
                return _plugin.Describe() with { ProtocolVersion = ProtocolConstants.ProtocolVersion };
            }

            case ProtocolConstants.Methods.Filter:
                return await _plugin.FilterAsync(ProtocolJson.FromElement<FilterParams>(request.Params), token);

            case ProtocolConstants.Methods.Analyze:
                return await _plugin.AnalyzeAsync(ProtocolJson.FromElement<AnalyzeParams>(request.Params), token);

            case ProtocolConstants.Methods.GetPanel:
                return await _plugin.GetPanelAsync(token);

            case ProtocolConstants.Methods.PanelAction:
                return await _plugin.OnPanelActionAsync(
                    ProtocolJson.FromElement<PanelActionParams>(request.Params).ActionId, token);

            case ProtocolConstants.Methods.UpdateSettings:
                _plugin.ApplySettings(ProtocolJson.FromElement<UpdateSettingsParams>(request.Params).Settings);
                await _plugin.OnSettingsChangedAsync(token);
                return EmptyResult.Instance;

            case ProtocolConstants.Methods.Shutdown:
                return EmptyResult.Instance;

            default:
                throw new NotSupportedException($"Unknown method '{request.Method}'.");
        }
    }

    private async Task PumpEventsAsync()
    {
        await foreach (HostEvent e in _events.Reader.ReadAllAsync())
        {
            try
            {
                await _plugin.OnEventAsync(e, CancellationToken.None);
            }
            catch (Exception ex)
            {
                await Console.Error.WriteLineAsync($"Event handler failed: {ex.Message}");
            }
        }
    }

    private async Task SendAsync(RpcMessage message)
    {
        try
        {
            await _writer.WriteAsync(message, CancellationToken.None);
        }
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync($"Write failed: {ex.Message}");
            _stop.Cancel();
        }
    }
}
