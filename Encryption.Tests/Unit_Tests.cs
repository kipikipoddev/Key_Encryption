using Encryption.Engine;

namespace Encryption.Tests;

public class Unit_Tests
{
    private Random random;
    private byte[] key;

    [SetUp]
    public void Setup()
    {
        random = new();
        key = Get_Random_Bytes(16);
    }

    [TestCase(100)]
    [TestCase(1_000)]
    [TestCase(10_000)]
    [TestCase(100_000)]
    public void Key_Encryption_Test(int length)
    {
        var data = Get_Random_Bytes(length);

        var encrypted = Key_Encryption.Encrypt(data, key);
        var decrypted = Key_Decryption.Decrypt(encrypted, key);

        Assert.That(data, Is.EqualTo(decrypted));
    }

    [Test]
    public void IV_Test()
    {
        var data = Get_Random_Bytes(100);

        var encrypted = Key_Encryption.Encrypt(data, key, 10);
        var encrypted2 = Key_Encryption.Encrypt(data, key, 10);

        Assert.That(encrypted[0], Is.Not.EqualTo(encrypted2[0]));
    }

    private byte[] Get_Random_Bytes(int size)
    {
        var bytes = new byte[size];
        random.NextBytes(bytes);
        return bytes;
    }
}
