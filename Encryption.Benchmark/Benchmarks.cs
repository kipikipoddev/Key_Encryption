using BenchmarkDotNet.Attributes;
using Encryption.Engine;

namespace Encryption.Benchmark;

public class Benchmarks
{
    private const int Scale = 1_000_000;
    private const int Times = 10;

    private readonly Random random;
    private readonly byte[] key;
    private readonly byte[] data;
    private readonly byte[] encrypted;

    public Benchmarks()
    {
        random = new();
        key = Get_Random_Bytes(16);
        data = Get_Random_Bytes(Scale);
        encrypted = Key_Encryption.Encrypt(data, key, 16, Times);
    }

    [Benchmark]
    public void Encrypt()
    {
        Key_Encryption.Encrypt(data, key, 16, Times);
    }

    [Benchmark]
    public void Decrypt()
    {
        Key_Decryption.Decrypt(encrypted, key);
    }

    private byte[] Get_Random_Bytes(int size)
    {
        var bytes = new byte[size];
        random.NextBytes(bytes);
        return bytes;
    }
}