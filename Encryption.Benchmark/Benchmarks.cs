using BenchmarkDotNet.Attributes;
using Encryption.Common;
using Encryption.Engine;

namespace Encryption.Benchmark;

public class Benchmarks
{
    private const int Scale = 100_000;
    private const int Times = 32;

    private readonly Random random;
    private readonly byte[] key;
    private readonly byte[] data;
    private readonly byte[] encrypted;

    public Benchmarks()
    {
        random = new();
        key = random.Get_Random_Bytes(32);
        data = random.Get_Random_Bytes(Scale);
        encrypted = Key_Encryption.Encrypt(data, key, Times);
    }

    [Benchmark]
    public void Encrypt()
    {
        Key_Encryption.Encrypt(data, key, Times);
    }

    [Benchmark]
    public void Decrypt()
    {
        Key_Encryption.Decrypt(encrypted, key);
    }
}