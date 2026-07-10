using System.Diagnostics;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace DCE432;

public sealed record EncryptionOptions(int PerformanceLevel, bool DeviceBound, byte[]? DeviceSecret = null);
public sealed record EncryptionResult(string OutputPath, string? RecoveryKey, long OriginalBytes, long EncryptedBytes, int PerformanceLevel, int Rounds);
public sealed record DecryptionResult(string OutputPath, string OriginalFileName, long OriginalBytes);

public static class Dce432Engine
{
    public const long MaxInputBytes = 256L * 1024 * 1024;

    public static int DetectPerformanceLevel()
    {
        var cores = Environment.ProcessorCount;
        var memoryGiB = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes / 1024d / 1024d / 1024d;
        var score = 2;
        if (cores >= 4) score += 2;
        if (cores >= 8) score += 2;
        if (cores >= 16) score += 2;
        if (memoryGiB >= 8) score += 2;
        if (memoryGiB >= 16) score += 2;
        if (memoryGiB >= 32) score += 2;
        return Math.Clamp(score, 0, 15);
    }

    public static async Task<EncryptionResult> EncryptFileAsync(string inputPath, string outputPath, string password, EncryptionOptions options, IProgress<string>? progress = null)
    {
        ValidatePassword(password);
        var info = new FileInfo(inputPath);
        if (!info.Exists) throw new FileNotFoundException("The input file could not be found.", inputPath);
        if (info.Length > MaxInputBytes) throw new InvalidOperationException("DCE-432 v0.1 supports files up to 256 MB.");
        if (Path.GetFullPath(inputPath).Equals(Path.GetFullPath(outputPath), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("The output file cannot overwrite the input file.");

        progress?.Report("Reading the source file...");
        var original = await File.ReadAllBytesAsync(inputPath).ConfigureAwait(false);
        var level = Math.Clamp(options.PerformanceLevel, 0, 15);
        var profile = PerformanceProfile.ForLevel(level);
        var salt = RandomNumberGenerator.GetBytes(16);
        var seed = RandomNumberGenerator.GetBytes(32);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var created = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var deviceId = DeviceSecrets.GetOrCreateDeviceId();
        byte[]? deviceSecret = null;
        string? recovery = null;
        if (options.DeviceBound)
        {
            deviceSecret = options.DeviceSecret ?? DeviceSecrets.GetOrCreateDeviceSecret();
            recovery = DeviceSecrets.EncodeRecoveryKey(deviceSecret);
        }

        progress?.Report($"Running Argon2id ({profile.MemoryKiB / 1024} MB, {profile.Iterations} passes)...");
        var passwordKey = await CryptoPrimitives.Argon2idAsync(password, salt, profile.MemoryKiB, profile.Iterations, profile.Parallelism).ConfigureAwait(false);
        var rootKey = BuildRootKey(passwordKey, seed, options.DeviceBound, deviceSecret);
        CryptographicOperations.ZeroMemory(passwordKey);
        try
        {
            var env = BuildEnvironmentSnapshot(level);
            var envHash = CryptoPrimitives.Sha256("DCE-ENV-v1|" + env + "|" + Convert.ToHexString(deviceId));
            progress?.Report("Running the reversible 3D -> 4D -> 3D -> 2D cascade...");
            var transformed = TransformForward(original, rootKey, seed, envHash, profile, out var d3, out var d4, out var d3f, out var d2, out var padding);
            var metadata = new TransformMetadata(
                created, Guid.NewGuid(), Path.GetFileName(inputPath), env, deviceId, (byte)level, profile.Rounds,
                d3, d4, d3f, d2, padding, original.LongLength, SHA256.HashData(original), transformed);
            var package = metadata.Serialize();
            var fileType = Path.GetExtension(inputPath);
            var header = new OuterHeader(options.DeviceBound, profile.MemoryKiB, profile.Iterations, profile.Parallelism, created, fileType, salt, seed, nonce, package.LongLength);
            var aad = header.Serialize();
            var cipher = new byte[package.Length];
            var tag = new byte[16];
            var outerKey = CryptoPrimitives.Hkdf(rootKey, seed, "DCE/OUTER-AEAD");
            progress?.Report("Generating AES-256-GCM authenticated ciphertext...");
            using (var aes = new AesGcm(outerKey, tag.Length)) aes.Encrypt(nonce, package, cipher, tag, aad);
            CryptographicOperations.ZeroMemory(outerKey);
            CryptographicOperations.ZeroMemory(package);
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outputPath))!);
            var temp = outputPath + ".tmp-" + Guid.NewGuid().ToString("N");
            try
            {
                await using (var fs = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 131072, FileOptions.Asynchronous | FileOptions.WriteThrough))
                {
                    await fs.WriteAsync(aad).ConfigureAwait(false);
                    await fs.WriteAsync(cipher).ConfigureAwait(false);
                    await fs.WriteAsync(tag).ConfigureAwait(false);
                }
                File.Move(temp, outputPath, true);
            }
            finally { if (File.Exists(temp)) File.Delete(temp); }
            progress?.Report("Encryption complete. The authentication tag has been written.");
            return new EncryptionResult(outputPath, recovery, original.LongLength, new FileInfo(outputPath).Length, level, profile.Rounds);
        }
        finally { CryptographicOperations.ZeroMemory(rootKey); CryptographicOperations.ZeroMemory(original); }
    }

    public static async Task<DecryptionResult> DecryptFileAsync(string inputPath, string outputPath, string password, string? recoveryKey, IProgress<string>? progress = null)
    {
        ValidatePassword(password);
        await using var fs = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read, 131072, FileOptions.Asynchronous);
        var (header, aad) = OuterHeader.Read(fs);
        if (fs.Length - fs.Position != header.CipherLength + 16) throw new InvalidDataException("Invalid DCE-432 file length or authentication tag.");
        var cipher = new byte[checked((int)header.CipherLength)];
        await fs.ReadExactlyAsync(cipher).ConfigureAwait(false);
        var tag = new byte[16];
        await fs.ReadExactlyAsync(tag).ConfigureAwait(false);
        byte[]? deviceSecret = null;
        if (header.DeviceBound)
        {
            deviceSecret = !string.IsNullOrWhiteSpace(recoveryKey)
                ? DeviceSecrets.DecodeRecoveryKey(recoveryKey)
                : DeviceSecrets.TryReadDeviceSecret() ?? throw new InvalidOperationException("This file is device-bound. Decrypt it on the original device or enter the saved recovery key.");
        }

        progress?.Report($"Using the saved Argon2id parameters ({header.MemoryKiB / 1024} MB)...");
        var passwordKey = await CryptoPrimitives.Argon2idAsync(password, header.Salt, header.MemoryKiB, header.Iterations, header.Parallelism).ConfigureAwait(false);
        var rootKey = BuildRootKey(passwordKey, header.Seed, header.DeviceBound, deviceSecret);
        CryptographicOperations.ZeroMemory(passwordKey);
        try
        {
            var outerKey = CryptoPrimitives.Hkdf(rootKey, header.Seed, "DCE/OUTER-AEAD");
            var package = new byte[cipher.Length];
            try
            {
                using var aes = new AesGcm(outerKey, tag.Length);
                aes.Decrypt(header.Nonce, cipher, tag, package, aad);
            }
            catch (CryptographicException)
            {
                throw new CryptographicException("Authentication failed. The password or recovery key is incorrect, or the file has been modified.");
            }
            finally { CryptographicOperations.ZeroMemory(outerKey); }

            var metadata = TransformMetadata.Deserialize(package);
            CryptographicOperations.ZeroMemory(package);
            var envHash = CryptoPrimitives.Sha256("DCE-ENV-v1|" + metadata.EnvironmentSnapshot + "|" + Convert.ToHexString(metadata.DeviceId));
            progress?.Report("Authentication passed. Reversing the 2D -> 3D -> 4D -> 3D cascade...");
            var original = TransformInverse(metadata, rootKey, header.Seed, envHash);
            if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(original), metadata.OriginalHash))
                throw new InvalidDataException("The internal plaintext check failed. The file may be damaged.");
            if (Path.GetFullPath(inputPath).Equals(Path.GetFullPath(outputPath), StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("The output file cannot overwrite the encrypted file.");
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outputPath))!);
            var temp = outputPath + ".tmp-" + Guid.NewGuid().ToString("N");
            try
            {
                await File.WriteAllBytesAsync(temp, original).ConfigureAwait(false);
                File.Move(temp, outputPath, true);
            }
            finally { if (File.Exists(temp)) File.Delete(temp); CryptographicOperations.ZeroMemory(original); }
            progress?.Report("Decryption complete. The plaintext hash has been verified.");
            return new DecryptionResult(outputPath, metadata.OriginalFileName, metadata.OriginalLength);
        }
        finally { CryptographicOperations.ZeroMemory(rootKey); }
    }

    public static OuterHeader Inspect(string path)
    {
        using var fs = File.OpenRead(path);
        return OuterHeader.Read(fs).Header;
    }

    private static byte[] BuildRootKey(byte[] passwordKey, byte[] seed, bool deviceBound, byte[]? deviceSecret)
    {
        if (!deviceBound) return CryptoPrimitives.Hkdf(passwordKey, seed, "DCE/ROOT/PORTABLE");
        if (deviceSecret is null || deviceSecret.Length != 32) throw new InvalidOperationException("Invalid device key.");
        var combined = CryptoPrimitives.Combine(passwordKey, deviceSecret);
        try { return CryptoPrimitives.Hkdf(combined, seed, "DCE/ROOT/DEVICE-BOUND"); }
        finally { CryptographicOperations.ZeroMemory(combined); }
    }

    private static byte[] TransformForward(byte[] original, byte[] rootKey, byte[] seed, byte[] envHash, PerformanceProfile profile,
        out int[] d3, out int[] d4, out int[] d3f, out int[] d2, out int[] padding)
    {
        var stageRatio = Math.Pow(profile.ExpansionRatio, 0.25);
        var k3 = CryptoPrimitives.Hkdf(rootKey, seed, "DCE/3D", envHash);
        var k34 = CryptoPrimitives.Hkdf(rootKey, seed, "DCE/3D-4D", envHash);
        var k4m = CryptoPrimitives.Hkdf(rootKey, seed, "DCE/4D-MIX", envHash);
        var k43 = CryptoPrimitives.Hkdf(rootKey, seed, "DCE/4D-3D", envHash);
        var k32 = CryptoPrimitives.Hkdf(rootKey, seed, "DCE/3D-2D", envHash);

        d3 = DimensionGenerator.Generate3D(Math.Max(1, original.Length), stageRatio, k3, "DIM-3");
        var c3 = Product(d3);
        var stage3 = PermuteForward(original, c3, k3, "PI-3");

        var wordsNeeded = (c3 + 3) / 4;
        d4 = DimensionGenerator.Generate4D(wordsNeeded, stageRatio, k34, "DIM-4");
        var c4Bytes = checked(Product(d4) * 4);
        var lifted = PermuteForward(stage3, c4Bytes, k34, "PI-34");
        var words = BytesToWords(lifted);
        Mix4D(words, d4, k4m, profile.Rounds, inverse: false);
        var mixed = WordsToBytes(words);

        d3f = DimensionGenerator.Generate3D(mixed.Length, stageRatio, k43, "DIM-3F");
        var c3f = Product(d3f);
        var folded3 = PermuteForward(mixed, c3f, k43, "PI-43");

        d2 = DimensionGenerator.Generate2D(folded3.Length, stageRatio, k32, "DIM-2");
        var c2 = Product(d2);
        var matrix = PermuteForward(folded3, c2, k32, "PI-32");
        padding = [c3 - original.Length, c4Bytes - c3, c3f - mixed.Length, c2 - c3f];
        foreach (var key in new[] { k3, k34, k4m, k43, k32 }) CryptographicOperations.ZeroMemory(key);
        return matrix;
    }

    private static byte[] TransformInverse(TransformMetadata metadata, byte[] rootKey, byte[] seed, byte[] envHash)
    {
        ValidateDimensions(metadata);
        var k3 = CryptoPrimitives.Hkdf(rootKey, seed, "DCE/3D", envHash);
        var k34 = CryptoPrimitives.Hkdf(rootKey, seed, "DCE/3D-4D", envHash);
        var k4m = CryptoPrimitives.Hkdf(rootKey, seed, "DCE/4D-MIX", envHash);
        var k43 = CryptoPrimitives.Hkdf(rootKey, seed, "DCE/4D-3D", envHash);
        var k32 = CryptoPrimitives.Hkdf(rootKey, seed, "DCE/3D-2D", envHash);
        try
        {
            var c3f = Product(metadata.D3Folded);
            var folded3 = PermuteInverse(metadata.Matrix, c3f, k32, "PI-32");
            var c4Bytes = checked(Product(metadata.D4) * 4);
            var mixed = PermuteInverse(folded3, c4Bytes, k43, "PI-43");
            var words = BytesToWords(mixed);
            Mix4D(words, metadata.D4, k4m, metadata.Rounds, inverse: true);
            var lifted = WordsToBytes(words);
            var c3 = Product(metadata.D3);
            var stage3 = PermuteInverse(lifted, c3, k34, "PI-34");
            return PermuteInverse(stage3, checked((int)metadata.OriginalLength), k3, "PI-3");
        }
        finally { foreach (var key in new[] { k3, k34, k4m, k43, k32 }) CryptographicOperations.ZeroMemory(key); }
    }

    private static byte[] PermuteForward(byte[] source, int destinationLength, byte[] key, string domain)
    {
        if (destinationLength < source.Length) throw new InvalidOperationException("The permutation target space is too small.");
        var output = new byte[destinationLength];
        using var padding = new KeyStream(key, domain + "/DECOY");
        var (a, b) = AffineParameters(destinationLength, key, domain);
        for (var i = 0; i < destinationLength; i++)
        {
            var j = (int)(((ulong)a * (ulong)i + (ulong)b) % (ulong)destinationLength);
            output[j] = i < source.Length ? source[i] : padding.NextByte();
        }
        return output;
    }

    private static byte[] PermuteInverse(byte[] source, int wantedLength, byte[] key, string domain)
    {
        if (wantedLength < 0 || wantedLength > source.Length) throw new InvalidDataException("Invalid inverse permutation length.");
        var output = new byte[wantedLength];
        var (a, b) = AffineParameters(source.Length, key, domain);
        for (var i = 0; i < wantedLength; i++)
        {
            var j = (int)(((ulong)a * (ulong)i + (ulong)b) % (ulong)source.Length);
            output[i] = source[j];
        }
        return output;
    }

    private static (long A, long B) AffineParameters(int length, byte[] key, string domain)
    {
        if (length <= 1) return (1, 0);
        using var rng = new KeyStream(key, domain + "/PERM");
        long a;
        do a = (long)(rng.NextUInt64() % (ulong)length); while (a < 1 || Gcd(a, length) != 1);
        var b = (long)(rng.NextUInt64() % (ulong)length);
        return (a, b);
    }

    private static void Mix4D(uint[] words, int[] dims, byte[] key, int rounds, bool inverse)
    {
        if (!inverse)
        {
            for (var round = 0; round < rounds; round++) ApplyRound(words, dims, key, round, false);
        }
        else
        {
            for (var round = rounds - 1; round >= 0; round--) ApplyRound(words, dims, key, round, true);
        }
    }

    private static void ApplyRound(uint[] words, int[] dims, byte[] masterKey, int round, bool inverse)
    {
        var roundContext = BitConverter.GetBytes(round);
        var roundKey = CryptoPrimitives.Hkdf(masterKey, Array.Empty<byte>(), "ROUND", roundContext);
        try
        {
            var permutes = round % 5 == 4;
            if (inverse && permutes) PermuteWords(words, roundKey, "ROUND-PERM", true);
            using var stream = new KeyStream(roundKey, "ARX/" + (round % 4));
            var axis = round % 4;
            for (var i = 0; i < words.Length; i++)
            {
                var coordinate = CoordinateOnAxis(i, dims, axis);
                if ((coordinate & 1) != 0 || coordinate + 1 >= dims[axis]) continue;
                var neighbor = i + AxisStride(dims, axis);
                var k = stream.NextUInt32();
                var r = stream.NextInt(5, 28);
                var s = stream.NextInt(5, 28);
                unchecked
                {
                    if (!inverse)
                    {
                        var uPrime = words[i] + BitOperations.RotateLeft(words[neighbor], r) + k;
                        var vPrime = words[neighbor] ^ BitOperations.RotateLeft(uPrime, s);
                        words[i] = uPrime;
                        words[neighbor] = vPrime;
                    }
                    else
                    {
                        var v = words[neighbor] ^ BitOperations.RotateLeft(words[i], s);
                        var u = words[i] - BitOperations.RotateLeft(v, r) - k;
                        words[i] = u;
                        words[neighbor] = v;
                    }
                }
            }
            if (!inverse && permutes) PermuteWords(words, roundKey, "ROUND-PERM", false);
        }
        finally { CryptographicOperations.ZeroMemory(roundKey); }
    }

    private static void PermuteWords(uint[] words, byte[] key, string domain, bool inverse)
    {
        var temp = new uint[words.Length];
        var (a, b) = AffineParameters(words.Length, key, domain);
        if (!inverse)
            for (var i = 0; i < words.Length; i++) temp[(int)(((ulong)a * (ulong)i + (ulong)b) % (ulong)words.Length)] = words[i];
        else
            for (var i = 0; i < words.Length; i++) temp[i] = words[(int)(((ulong)a * (ulong)i + (ulong)b) % (ulong)words.Length)];
        Array.Copy(temp, words, words.Length);
    }

    private static int CoordinateOnAxis(int index, int[] d, int axis) => axis switch
    {
        0 => index / (d[1] * d[2] * d[3]),
        1 => index / (d[2] * d[3]) % d[1],
        2 => index / d[3] % d[2],
        _ => index % d[3]
    };

    private static int AxisStride(int[] d, int axis) => axis switch { 0 => d[1] * d[2] * d[3], 1 => d[2] * d[3], 2 => d[3], _ => 1 };
    private static uint[] BytesToWords(byte[] bytes)
    {
        if (bytes.Length % 4 != 0) throw new InvalidDataException("The 4D byte space is not aligned.");
        var words = new uint[bytes.Length / 4];
        Buffer.BlockCopy(bytes, 0, words, 0, bytes.Length);
        return words;
    }
    private static byte[] WordsToBytes(uint[] words) { var bytes = new byte[words.Length * 4]; Buffer.BlockCopy(words, 0, bytes, 0, bytes.Length); return bytes; }

    private static void ValidateDimensions(TransformMetadata m)
    {
        var c3 = Product(m.D3); var c4b = checked(Product(m.D4) * 4); var c3f = Product(m.D3Folded); var c2 = Product(m.D2);
        if (m.Matrix.Length != c2 || m.OriginalLength > c3 || c3 > c4b || c4b > c3f || c3f > c2)
            throw new InvalidDataException("Authenticated dimension or length fields are inconsistent.");
        var expected = new[] { c3 - (int)m.OriginalLength, c4b - c3, c3f - c4b, c2 - c3f };
        if (!expected.SequenceEqual(m.Padding)) throw new InvalidDataException("Authenticated padding length fields are inconsistent.");
    }

    private static int Product(int[] values)
    {
        long product = 1;
        foreach (var value in values) { if (value < 1) throw new InvalidDataException("Dimensions must be positive."); product *= value; }
        if (product > int.MaxValue) throw new InvalidDataException("The dimension space is too large.");
        return (int)product;
    }
    private static long Gcd(long a, long b) { while (b != 0) (a, b) = (b, a % b); return Math.Abs(a); }

    private static string BuildEnvironmentSnapshot(int level) =>
        $"utc={DateTimeOffset.UtcNow:O};os={RuntimeInformation.OSDescription};arch={RuntimeInformation.OSArchitecture};process={RuntimeInformation.ProcessArchitecture};level={level}";

    private static void ValidatePassword(string password)
    {
        if (string.IsNullOrEmpty(password)) throw new ArgumentException("Enter a password.");
        if (password.Length < 8) throw new ArgumentException("The password must contain at least 8 characters.");
    }
}

internal sealed record PerformanceProfile(int MemoryKiB, int Iterations, int Parallelism, double ExpansionRatio, int Rounds)
{
    public static PerformanceProfile ForLevel(int level)
    {
        var p = Math.Clamp(level, 0, 15);
        var parallel = Math.Clamp(Environment.ProcessorCount / 2, 1, 8);
        return p switch
        {
            <= 3 => new(64 * 1024, 3, Math.Min(2, parallel), 1.10, 12),
            <= 7 => new(96 * 1024, 3, Math.Min(4, parallel), 1.25, 12),
            <= 11 => new(128 * 1024, 4, Math.Min(6, parallel), 1.50, 16),
            _ => new(256 * 1024, 4, parallel, 2.00, 20)
        };
    }
}

internal static class DimensionGenerator
{
    public static int[] Generate2D(int minimum, double ratio, byte[] key, string domain) => Generate(minimum, ratio, 2, key, domain);
    public static int[] Generate3D(int minimum, double ratio, byte[] key, string domain) => Generate(minimum, ratio, 3, key, domain);
    public static int[] Generate4D(int minimum, double ratio, byte[] key, string domain) => Generate(minimum, ratio, 4, key, domain);

    private static int[] Generate(int minimum, double ratio, int dimensions, byte[] key, string domain)
    {
        minimum = Math.Max(1, minimum);
        var max = Math.Max(minimum, (int)Math.Ceiling(minimum * ratio));
        using var rng = new KeyStream(key, domain);
        var desired = rng.NextInt(minimum, max == int.MaxValue ? max : max + 1);
        int[]? best = null;
        long bestCapacity = long.MaxValue;
        for (var attempt = 0; attempt < 512; attempt++)
        {
            var dims = new int[dimensions];
            long assignedProduct = 1;
            for (var i = 0; i < dimensions - 1; i++)
            {
                var remaining = dimensions - i;
                var basis = Math.Max(2, (int)Math.Ceiling(Math.Pow((double)desired / assignedProduct, 1d / remaining)));
                var spread = Math.Max(1, basis / 4);
                dims[i] = Math.Max(2, basis + rng.NextInt(-spread, spread + 1));
                assignedProduct *= dims[i];
            }
            dims[^1] = Math.Max(2, (int)Math.Ceiling((double)desired / assignedProduct));
            long capacity = dims.Aggregate<int, long>(1, (p, v) => p * v);
            var aspect = (double)dims.Max() / dims.Min();
            if (capacity >= minimum && capacity < bestCapacity && aspect <= 4.0)
            {
                best = dims; bestCapacity = capacity;
                if (capacity <= max) break;
            }
        }
        if (best is not null) return best;
        var fallback = Enumerable.Repeat(Math.Max(2, (int)Math.Ceiling(Math.Pow(minimum, 1d / dimensions))), dimensions).ToArray();
        while (fallback.Aggregate<int, long>(1, (p, v) => p * v) < minimum) fallback[^1]++;
        return fallback;
    }
}

public static class DeviceSecrets
{
    private static readonly string DirectoryPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DCE432");
    private static readonly string SecretPath = Path.Combine(DirectoryPath, "device.key");
    private static readonly string IdPath = Path.Combine(DirectoryPath, "device.id");

    public static byte[] GetOrCreateDeviceSecret() => GetOrCreate(SecretPath);
    public static byte[] GetOrCreateDeviceId() => GetOrCreate(IdPath);
    public static byte[]? TryReadDeviceSecret()
    {
        try { var bytes = File.Exists(SecretPath) ? File.ReadAllBytes(SecretPath) : null; return bytes?.Length == 32 ? bytes : null; }
        catch { return null; }
    }
    private static byte[] GetOrCreate(string path)
    {
        Directory.CreateDirectory(DirectoryPath);
        if (File.Exists(path))
        {
            var existing = File.ReadAllBytes(path);
            if (existing.Length == 32) return existing;
        }
        var value = RandomNumberGenerator.GetBytes(32);
        File.WriteAllBytes(path, value);
        return value;
    }
    public static string EncodeRecoveryKey(byte[] key) => "DCE-RK1-" + Convert.ToBase64String(key).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    public static byte[] DecodeRecoveryKey(string value)
    {
        var text = value.Trim();
        if (!text.StartsWith("DCE-RK1-", StringComparison.OrdinalIgnoreCase)) throw new FormatException("Invalid recovery key format.");
        text = text[8..].Replace('-', '+').Replace('_', '/');
        text += new string('=', (4 - text.Length % 4) % 4);
        var bytes = Convert.FromBase64String(text);
        if (bytes.Length != 32) throw new FormatException("Invalid recovery key length.");
        return bytes;
    }
}
