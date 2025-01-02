using BenchmarkDotNet.Attributes;
using Encryption.Engine;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace Encryption.Benchmark;

public class Benchmarks
{
    private const int Scale = 1_000_000;
    private readonly byte[] byte_data;
    private readonly Encrypt_Data data;

    public Benchmarks()
    {
        byte_data = Randomizer.Get(Scale);
        data = new Encrypt_Data(byte_data);
    }

    [Benchmark]
    public void Encrypt()
    {
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