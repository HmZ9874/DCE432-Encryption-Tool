using System.Text;

namespace DCE432;

public sealed record OuterHeader(
    bool DeviceBound,
    int MemoryKiB,
    int Iterations,
    int Parallelism,
    long CreatedUnixSeconds,
    string FileType,
    byte[] Salt,
    byte[] Seed,
    byte[] Nonce,
    long CipherLength)
{
    public const byte Version = 1;
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("DCE432\r\n");

    public byte[] Serialize()
    {
        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms, Encoding.UTF8, true);
        bw.Write(Magic);
        bw.Write(Version);
        bw.Write((byte)(DeviceBound ? 1 : 0));
        bw.Write((byte)1); // Argon2id
        bw.Write((byte)1); // AES-256-GCM
        bw.Write(MemoryKiB);
        bw.Write(Iterations);
        bw.Write(Parallelism);
        bw.Write(CreatedUnixSeconds);
        var typeBytes = Encoding.UTF8.GetBytes(FileType ?? string.Empty);
        if (typeBytes.Length > 255) throw new InvalidDataException("The file type field is too long.");
        bw.Write((byte)typeBytes.Length);
        bw.Write(typeBytes);
        bw.Write(Salt);
        bw.Write(Seed);
        bw.Write(Nonce);
        bw.Write(CipherLength);
        return ms.ToArray();
    }

    public static (OuterHeader Header, byte[] RawHeader) Read(Stream input)
    {
        using var captured = new MemoryStream();
        using var tee = new TeeReader(input, captured);
        using var br = new BinaryReader(tee, Encoding.UTF8, true);
        var magic = br.ReadBytes(Magic.Length);
        if (!magic.SequenceEqual(Magic)) throw new InvalidDataException("This is not a DCE-432 encrypted file.");
        var version = br.ReadByte();
        if (version != Version) throw new InvalidDataException($"DCE-432 v{version} files are not supported.");
        var flags = br.ReadByte();
        if (br.ReadByte() != 1) throw new InvalidDataException("Unsupported key derivation algorithm.");
        if (br.ReadByte() != 1) throw new InvalidDataException("Unsupported authenticated encryption algorithm.");
        var memory = br.ReadInt32();
        var iterations = br.ReadInt32();
        var parallel = br.ReadInt32();
        if (memory is < 32768 or > 1048576 || iterations is < 1 or > 20 || parallel is < 1 or > 32)
            throw new InvalidDataException("The Argon2id parameters in this file are invalid or unsafe.");
        var created = br.ReadInt64();
        var typeLen = br.ReadByte();
        var fileType = Encoding.UTF8.GetString(br.ReadBytes(typeLen));
        var salt = br.ReadBytes(16);
        var seed = br.ReadBytes(32);
        var nonce = br.ReadBytes(12);
        var cipherLength = br.ReadInt64();
        if (salt.Length != 16 || seed.Length != 32 || nonce.Length != 12 || cipherLength < 0 || cipherLength > 2_000_000_000)
            throw new InvalidDataException("The DCE-432 file header is damaged.");
        var header = new OuterHeader((flags & 1) != 0, memory, iterations, parallel, created, fileType, salt, seed, nonce, cipherLength);
        return (header, captured.ToArray());
    }

    private sealed class TeeReader : Stream
    {
        private readonly Stream _source;
        private readonly Stream _capture;
        public TeeReader(Stream source, Stream capture) { _source = source; _capture = capture; }
        public override int Read(byte[] buffer, int offset, int count)
        {
            var read = _source.Read(buffer, offset, count);
            if (read > 0) _capture.Write(buffer, offset, read);
            return read;
        }
        public override int Read(Span<byte> buffer)
        {
            var read = _source.Read(buffer);
            if (read > 0) _capture.Write(buffer[..read]);
            return read;
        }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}

internal sealed record TransformMetadata(
    long CreatedUnixSeconds,
    Guid FileId,
    string OriginalFileName,
    string EnvironmentSnapshot,
    byte[] DeviceId,
    byte PerformanceLevel,
    int Rounds,
    int[] D3,
    int[] D4,
    int[] D3Folded,
    int[] D2,
    int[] Padding,
    long OriginalLength,
    byte[] OriginalHash,
    byte[] Matrix)
{
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("DCEI");

    public byte[] Serialize()
    {
        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms, Encoding.UTF8, true);
        bw.Write(Magic);
        bw.Write((byte)1);
        bw.Write(CreatedUnixSeconds);
        bw.Write(FileId.ToByteArray());
        bw.Write(OriginalFileName);
        bw.Write(EnvironmentSnapshot);
        bw.Write(DeviceId.Length);
        bw.Write(DeviceId);
        bw.Write(PerformanceLevel);
        bw.Write(Rounds);
        foreach (var v in D3) bw.Write(v);
        foreach (var v in D4) bw.Write(v);
        foreach (var v in D3Folded) bw.Write(v);
        foreach (var v in D2) bw.Write(v);
        foreach (var v in Padding) bw.Write(v);
        bw.Write(OriginalLength);
        bw.Write(OriginalHash);
        bw.Write((long)Matrix.Length);
        bw.Write(Matrix);
        return ms.ToArray();
    }

    public static TransformMetadata Deserialize(byte[] data)
    {
        using var ms = new MemoryStream(data, false);
        using var br = new BinaryReader(ms, Encoding.UTF8, true);
        if (!br.ReadBytes(4).SequenceEqual(Magic) || br.ReadByte() != 1) throw new InvalidDataException("Invalid internal package version.");
        var created = br.ReadInt64();
        var fileId = new Guid(br.ReadBytes(16));
        var name = br.ReadString();
        var env = br.ReadString();
        var deviceIdLength = br.ReadInt32();
        if (deviceIdLength is < 0 or > 1024) throw new InvalidDataException("Invalid device identifier length.");
        var deviceId = br.ReadBytes(deviceIdLength);
        var level = br.ReadByte();
        var rounds = br.ReadInt32();
        var d3 = ReadInts(br, 3);
        var d4 = ReadInts(br, 4);
        var d3f = ReadInts(br, 3);
        var d2 = ReadInts(br, 2);
        var padding = ReadInts(br, 4);
        var originalLength = br.ReadInt64();
        var hash = br.ReadBytes(32);
        var matrixLength = br.ReadInt64();
        if (level > 15 || rounds is < 12 or > 20 || originalLength < 0 || matrixLength < 0 || matrixLength > int.MaxValue)
            throw new InvalidDataException("Invalid internal parameters.");
        var matrix = br.ReadBytes((int)matrixLength);
        if (matrix.Length != matrixLength || ms.Position != ms.Length) throw new InvalidDataException("Invalid internal package length.");
        return new TransformMetadata(created, fileId, name, env, deviceId, level, rounds, d3, d4, d3f, d2, padding, originalLength, hash, matrix);
    }

    private static int[] ReadInts(BinaryReader br, int count) => Enumerable.Range(0, count).Select(_ => br.ReadInt32()).ToArray();
}
