using System.Security.Cryptography;
using System.Text;
using DCE432;

var root = Path.Combine(Path.GetTempPath(), "dce432-selftest-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
try
{
    var input = Path.Combine(root, "original-test.txt");
    var encrypted = Path.Combine(root, "test.dce432");
    var decrypted = Path.Combine(root, "restored.txt");
    var content = Encoding.UTF8.GetBytes("DCE-432 deterministic round-trip test\n" + string.Concat(Enumerable.Repeat("0123456789abcdef", 500)));
    await File.WriteAllBytesAsync(input, content);
    await Dce432Engine.EncryptFileAsync(input, encrypted, "correct horse battery staple", new EncryptionOptions(2, false));
    await Dce432Engine.DecryptFileAsync(encrypted, decrypted, "correct horse battery staple", null);
    var restored = await File.ReadAllBytesAsync(decrypted);
    if (!content.SequenceEqual(restored)) throw new Exception("Portable-mode round-trip mismatch.");

    var secret = RandomNumberGenerator.GetBytes(32);
    var bound = Path.Combine(root, "device-bound.dce432");
    var boundOut = Path.Combine(root, "device-bound-restored.txt");
    var result = await Dce432Engine.EncryptFileAsync(input, bound, "correct horse battery staple", new EncryptionOptions(2, true, secret));
    await Dce432Engine.DecryptFileAsync(bound, boundOut, "correct horse battery staple", result.RecoveryKey);
    if (!content.SequenceEqual(await File.ReadAllBytesAsync(boundOut))) throw new Exception("Device-bound round-trip mismatch.");

    var tampered = await File.ReadAllBytesAsync(encrypted); tampered[^20] ^= 0x40; await File.WriteAllBytesAsync(encrypted, tampered);
    try { await Dce432Engine.DecryptFileAsync(encrypted, decrypted, "correct horse battery staple", null); throw new Exception("Tamper detection did not trigger."); }
    catch (CryptographicException) { }
    Console.WriteLine("PASS: portable round-trip, device recovery round-trip, tamper rejection");
}
finally { try { Directory.Delete(root, true); } catch { } }
