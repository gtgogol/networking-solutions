using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;

namespace TcpUdpPortScanner;

public class Scanner(ScanOptions options)
{
    private ScanOptions Options { get; } = options;

    public async IAsyncEnumerable<ScanResult> Scan(IPAddress ip, List<(string Protocol, int Port)> targets, CancellationToken cancelationToken = default)
    {
        {
            var channel = Channel.CreateUnbounded<ScanResult>();
            var limit = new SemaphoreSlim(Options.Threads);
            var producer = Task.Run(async () =>
            {
                var tasks = targets.Select(async target =>
                {
                    await limit.WaitAsync(cancelationToken);
                    try
                    {
                        var result = target.Protocol == "tcp" ? await ScanTcp(ip, target.Port, cancelationToken) 
                            : await ScanUdp(ip, target.Port, cancelationToken);
                        if (result is not null)
                            await channel.Writer.WriteAsync(result, cancelationToken);
                    }
                    finally { limit.Release(); }
                });
                try { await Task.WhenAll(tasks); }
                finally { channel.Writer.Complete(); }
            }, cancelationToken);
            await foreach (var result in channel.Reader.ReadAllAsync(cancelationToken))
                yield return result;
            await producer;
        }
    }

    private async Task<ScanResult?> ScanTcp(IPAddress ip, int port, CancellationToken cancelationToken)
    {
        using var socket = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancelationToken);
        connectCts.CancelAfter(Options.Timeout);

        var watch = System.Diagnostics.Stopwatch.StartNew();
        if (!await ConnectTcpAsync(ip, port, socket, connectCts.Token, cancelationToken))
            return null;
        watch.Stop();
        var timeMs = watch.Elapsed.TotalMilliseconds;
        
        string? applicationProtocol = null;
        if (Options.Guess)
        {
            var probes = new[] { ProtocolProbes.Dns(), ProtocolProbes.Http(), ProtocolProbes.Echo() };
            var buf = new byte[4096];
            foreach (var probe in probes)
            {
                using var probeCts = CancellationTokenSource.CreateLinkedTokenSource(cancelationToken);
                probeCts.CancelAfter(Options.Timeout);
                try
                {
                    var toSend = probe.IsDns ? WithDnsTcpLengthPrefix(probe.Data) : probe.Data;
                    await socket.SendAsync(toSend, SocketFlags.None, probeCts.Token);
                    var answerLength = await socket.ReceiveAsync(buf, SocketFlags.None, probeCts.Token);
                    if (answerLength <= 0)
                        continue;

                    var payload = probe.IsDns && answerLength > 2
                        ? buf.AsSpan(2, answerLength - 2)
                        : buf.AsSpan(0, answerLength);

                    applicationProtocol = probe.Recognize(payload);
                    if (applicationProtocol is not null)
                        break;
                }
                catch (SocketException)
                {
                    
                }
                catch (OperationCanceledException) when (!cancelationToken.IsCancellationRequested) {}
            }
        }
        
        return new ScanResult("tcp", port, timeMs, applicationProtocol ?? "-");
    }

    private async Task<ScanResult?> ScanUdp(IPAddress ip, int port, CancellationToken cancelationToken)
    {
        using var socket = new Socket(ip.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        await socket.ConnectAsync(ip, port, cancelationToken);
        var probes = new[] { ProtocolProbes.Dns(), ProtocolProbes.Echo() };
        var buf = new byte[4096];
        string? applicationProtocol = null;
        foreach (var probe in probes)
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancelationToken);
            cts.CancelAfter(Options.Timeout);
            try
            {
                await socket.SendAsync(probe.Data, SocketFlags.None, cts.Token);
                var answerLength = await socket.ReceiveAsync(buf, SocketFlags.None, cts.Token);
                applicationProtocol = Options.Guess ? probe.Recognize(buf.AsSpan(0, answerLength)) : null;
            }
            catch (SocketException e) when (e.SocketErrorCode is SocketError.ConnectionRefused or SocketError.ConnectionReset)
            {
                return null;
            }
            catch (OperationCanceledException) when (!cancelationToken.IsCancellationRequested) { }
        }
        return new ScanResult("udp", port, null, applicationProtocol ?? "-");
    }
    
    private async Task<bool> ConnectTcpAsync(
        IPAddress ip,
        int port,
        Socket socket,
        CancellationToken timeoutToken,
        CancellationToken userToken)
    {
        try
        {
            await socket.ConnectAsync(ip, port, timeoutToken);
            return true;
        }
        catch (OperationCanceledException) when (!userToken.IsCancellationRequested)
        {
            return false;
        }
        catch (SocketException)
        {
            return false;
        }
    }

    private static byte[] WithDnsTcpLengthPrefix(byte[] dnsMessage)
    {
        var packet = new byte[2 + dnsMessage.Length];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(0, 2), (ushort)dnsMessage.Length);
        dnsMessage.CopyTo(packet.AsSpan(2));
        return packet;
    }
}

public record ScanOptions(TimeSpan Timeout, int Threads, bool Verbose, bool Guess);

public record ScanResult(string Protocol, int Port, double? TimeMs, string? AppProtocol)
{
    public string Format(ScanOptions options)
    {
        var parts = new List<string> { Protocol.ToUpper(), Port.ToString() };
        if (options.Verbose)
            parts.Add(TimeMs is { } t ? $"{t:F0}" : "-");
        if (options.Guess)
            parts.Add(AppProtocol ?? "-");
        return string.Join(" ", parts);
    } 
}