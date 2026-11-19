using System.IO.Pipes;
using System.Text;
using FileGuardian.Core.Plugins;
using FileGuardian.Protocol;

namespace FileGuardian.Tests;

/// <summary>Drives PluginConnection against a fake, possibly hostile, plugin.</summary>
public class ConnectionTests
{
    private sealed class Link : IAsyncDisposable
    {
        public readonly AnonymousPipeServerStream HostToPlugin = new(PipeDirection.Out);
        public readonly AnonymousPipeClientStream PluginIn;
        public readonly AnonymousPipeServerStream PluginToHost = new(PipeDirection.Out);
        public readonly AnonymousPipeClientStream HostIn;
        public readonly PluginConnection Connection;
        public readonly TaskCompletionSource<Exception?> Closed = new();

        public Link()
        {
            PluginIn = new AnonymousPipeClientStream(PipeDirection.In, HostToPlugin.ClientSafePipeHandle);
            HostIn = new AnonymousPipeClientStream(PipeDirection.In, PluginToHost.ClientSafePipeHandle);
            Connection = new PluginConnection("test.plugin", HostIn, HostToPlugin);
            Connection.Closed += e => Closed.TrySetResult(e);
            Connection.Start();
        }

        public async Task PluginSendAsync(string json)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(json + "\n");
            await PluginToHost.WriteAsync(bytes);
            await PluginToHost.FlushAsync();
        }

        public async ValueTask DisposeAsync()
        {
            await Connection.DisposeAsync();
            foreach (IDisposable d in new IDisposable[] { HostToPlugin, PluginIn, PluginToHost, HostIn })
                d.Dispose();
        }
    }

    [Fact]
    public async Task RequestResponseRoundTrip()
    {
        await using var link = new Link();
        var reader = new BoundedLineReader(link.PluginIn);

        Task<FilterResult> pending = link.Connection.RequestAsync<FilterParams, FilterResult>(
            ProtocolConstants.Methods.Filter, new FilterParams("a.txt", ".txt", 1), TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);

        string? line = await reader.ReadLineAsync(TestContext.Current.CancellationToken);
        Assert.Contains("\"method\":\"filter\"", line);

        await link.PluginSendAsync("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"capture\":false,\"reason\":\"no\"}}");
        FilterResult result = await pending;
        Assert.False(result.Capture);
    }

    [Fact]
    public async Task SilentPluginTimesOut()
    {
        await using var link = new Link();
        await Assert.ThrowsAsync<PluginTimeoutException>(() =>
            link.Connection.RequestAsync<EmptyResult, EmptyResult>(
                ProtocolConstants.Methods.GetPanel, EmptyResult.Instance, TimeSpan.FromMilliseconds(200), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task PluginIssuingRequestIsDisconnected()
    {
        await using var link = new Link();
        await link.PluginSendAsync("{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"deleteEverything\"}");

        Exception? reason = await link.Closed.Task.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
        Assert.IsType<ProtocolViolationException>(reason);
    }

    [Fact]
    public async Task OversizedMessageDisconnects()
    {
        await using var link = new Link();
        _ = link.PluginSendAsync(new string('x', ProtocolConstants.MaxMessageBytes + 10));

        Exception? reason = await link.Closed.Task.WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
        Assert.IsType<ProtocolViolationException>(reason);
    }
}
