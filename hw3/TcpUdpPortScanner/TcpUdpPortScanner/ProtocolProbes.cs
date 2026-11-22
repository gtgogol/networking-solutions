using System.Buffers.Binary;
using System.Text;


namespace TcpUdpPortScanner;

public class ProtocolProbe(byte[] data, Func<ReadOnlySpan<byte>, string?> recognize, bool isDns = false)
{
    public byte[] Data { get; } = data;
    public bool IsDns { get; } = isDns;
    public string? Recognize(ReadOnlySpan<byte> response) => recognize(response);
}

public static class ProtocolProbes
{
    public static ProtocolProbe Echo()
    {
        var payload = new byte[16];
        Random.Shared.NextBytes(payload);
        return new ProtocolProbe(payload, response =>
            response.SequenceEqual(payload) ? "echo" : null);
    }

    public static ProtocolProbe Dns()
    {
        var id = (ushort)Random.Shared.Next(0, 0x10000);
        var data = new byte[]
        {
            (byte)(id >> 8), (byte)id, // ID
            0x01, 0x00,                // Флаги
            0x00, 0x01,                // Вопросы=1
            0x00, 0x00,                // Answers
            0x00, 0x00,                // Authority
            0x00, 0x00,                // Additional
            0x07,                      // длина "example"
            (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e',
            0x03,                      // длина "com"
            (byte)'c', (byte)'o', (byte)'m',
            0x00,                      // точка
            0x00, 0x01,                // QTYPE A
            0x00, 0x01                 // QCLASS IN
        };
        return new ProtocolProbe(data, response =>
        {
            if (response.Length < 12)
                return null;
            var respId = BinaryPrimitives.ReadUInt16BigEndian(response);
            var flags = BinaryPrimitives.ReadUInt16BigEndian(response[2..]);
            var isResponse = (flags & 0x8000) != 0;
            return respId == id && isResponse ? "dns" : null;
        }, true);
    }

    public static ProtocolProbe Http()
    {
        var request = Encoding.ASCII.GetBytes("GET / HTTP/1.0\r\nHost: port_scanner\r\nConnection: close\r\n\r\n");
        return new ProtocolProbe(request, response =>
        {
            if (response.Length < 5)
                return null;
            return response.StartsWith("HTTP/"u8) ? "http" : null;
        });
    }
}