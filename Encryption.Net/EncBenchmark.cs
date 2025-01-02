using BenchmarkDotNet.Attributes;
using System.Security.Cryptography;
using System.Text;

namespace BenchmarkExample;

public class EncBenchmark
{
    private readonly Aes aes;
    private readonly string original;
    private readonly byte[] encrypted;

    public EncBenchmark()
    {
        aes = Aes.Create();
        aes.Key = Enc.GenerateRandomKey(32);
        aes.IV = Enc.GenerateRandomKey(16);
        original = Encoding.UTF8.GetString(Enc.GenerateRandomKey(1_000_000));
        encrypted = Enc.EncryptStringToBytes(original, aes.Key, aes.IV);
    }

    [Benchmark]
    public void Encrypt()
    {
        Enc.EncryptStringToBytes(original, aes.Key, aes.IV);
    }

    [Benchmark]
    public void Decrypt()
    {
        Enc.DecryptStringFromBytes(encrypted, aes.Key, aes.IV);
    }
}