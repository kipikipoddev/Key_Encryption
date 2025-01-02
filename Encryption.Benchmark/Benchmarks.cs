using BenchmarkDotNet.Attributes;
using Encryption.Engine;

namespace Encryption.Benchmark;

public class Benchmarks
{
    private const int Scale = 1_000_000;
    private readonly byte[] byte_data;

    public Benchmarks()
    {
        byte_data = Randomizer.Get(Scale);
    }

    [Benchmark]
    public void Encrypt()
    {
        var data = new Encrypt_Data(byte_data);
        Key_Encryption.Encrypt(data);
    }

    [Benchmark]
    public void Encrypt_And_Decrypt()
    {
        var data = new Encrypt_Data(byte_data);
        Key_Encryption.Encrypt(data);
        Key_Decryption.Decrypt(data);
    }
}