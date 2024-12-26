using Encryption.Common;
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
        key = random.Get_Random_Bytes(16);
    }

    [TestCase(10)]
    [TestCase(100)]
    [TestCase(1_000)]
    [TestCase(10_000)]
    [TestCase(100_000)]
    public void Key_Encryption_Test(int length)
    {
        var data = random.Get_Random_Bytes(length);

        var encrypted = Key_Encryption.Encrypt(data, key, 128);
        var decrypted = Key_Decryption.Decrypt(encrypted, key, 128);

        Assert.That(data, Is.EqualTo(decrypted));
    }

    [Test]
    public void IV_Test()
    {
        var data = random.Get_Random_Bytes(16);

        var encrypted = Key_Encryption.Encrypt(data, key, 16);
        var encrypted2 = Key_Encryption.Encrypt(data, key, 16);

        Assert.That(encrypted[0], Is.Not.EqualTo(encrypted2[0]));
    }
}
