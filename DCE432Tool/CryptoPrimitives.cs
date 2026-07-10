using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace DCE432;

internal static class CryptoPrimitives
{
    public static async Task<byte[]> Argon2idAsync(string password, byte[] salt, int memoryKiB, int iterations, int parallelism)
    {
        var argon = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            MemorySize = memoryKiB,
            Iterations = iterations,
            DegreeOfParallelism = Math.Clamp(parallelism, 1, 8)
        };
        return await argon.GetBytesAsync(32).ConfigureAwait(false);
    }

    public static byte[] Hkdf(byte[] ikm, byte[] salt, string label, byte[]? context = null, int length = 32)
    {
        using var extract = new HMACSHA256(salt);
        var prk = extract.ComputeHash(ikm);
        var labelBytes = Encoding.UTF8.GetBytes(label);
        var info = new byte[labelBytes.Length + (context?.Length ?? 0)];
        Buffer.BlockCopy(labelBytes, 0, info, 0, labelBytes.Length);
        if (context is not null) Buffer.BlockCopy(context, 0, info, labelBytes.Length, context.Length);

        var result = new byte[length];
        var previous = Array.Empty<byte>();
        var offset = 0;
        byte counter = 1;
        using var expand = new HMACSHA256(prk);
        while (offset < length)
        {
            var blockInput = new byte[previous.Length + info.Length + 1];
            Buffer.BlockCopy(previous, 0, blockInput, 0, previous.Length);
            Buffer.BlockCopy(info, 0, blockInput, previous.Length, info.Length);
            blockInput[^1] = counter++;
            previous = expand.ComputeHash(blockInput);
            var take = Math.Min(previous.Length, length - offset);
            Buffer.BlockCopy(previous, 0, result, offset, take);
            offset += take;
        }
        CryptographicOperations.ZeroMemory(prk);
        return result;
    }

    public static byte[] Sha256(string value) => SHA256.HashData(Encoding.UTF8.GetBytes(value));

    public static byte[] Combine(params byte[][] arrays)
    {
        var length = arrays.Sum(a => a.Length);
        var output = new byte[length];
        var offset = 0;
        foreach (var array in arrays)
        {
            Buffer.BlockCopy(array, 0, output, offset, array.Length);
            offset += array.Length;
        }
        return output;
    }
}

internal sealed class KeyStream : IDisposable
{
    private readonly HMACSHA256 _hmac;
    private readonly byte[] _buffer = new byte[32];
    private int _offset = 32;
    private ulong _counter;

    public KeyStream(byte[] key, string domain)
    {
        _hmac = new HMACSHA256(key);
        Domain = Encoding.UTF8.GetBytes(domain);
    }

    private byte[] Domain { get; }

    private void Refill()
    {
        var input = new byte[Domain.Length + 8];
        Buffer.BlockCopy(Domain, 0, input, 0, Domain.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(input.AsSpan(Domain.Length), _counter++);
        var block = _hmac.ComputeHash(input);
        Buffer.BlockCopy(block, 0, _buffer, 0, 32);
        _offset = 0;
    }

    public byte NextByte()
    {
        if (_offset >= _buffer.Length) Refill();
        return _buffer[_offset++];
    }

    public uint NextUInt32()
    {
        Span<byte> data = stackalloc byte[4];
        for (var i = 0; i < 4; i++) data[i] = NextByte();
        return BinaryPrimitives.ReadUInt32LittleEndian(data);
    }

    public ulong NextUInt64() => ((ulong)NextUInt32() << 32) | NextUInt32();

    public int NextInt(int minInclusive, int maxExclusive)
    {
        if (maxExclusive <= minInclusive) return minInclusive;
        var range = (uint)(maxExclusive - minInclusive);
        var limit = uint.MaxValue - uint.MaxValue % range;
        uint value;
        do value = NextUInt32(); while (value >= limit);
        return minInclusive + (int)(value % range);
    }

    public void Dispose() => _hmac.Dispose();
}
