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
        key = random.Get_Random_Bytes(32);
    }

    [TestCase(100)]
    [TestCase(1_000)]
    [TestCase(10_000)]
    public void Key_Encryption_Test(int length)
    {
        var data = random.Get_Random_Bytes(length);

        var encrypted = Key_Encryption.Encrypt(data, key, 200);
        var decrypted = Key_Encryption.Decrypt(encrypted, key);

        Assert.That(data, Is.EqualTo(decrypted));
    }
}
