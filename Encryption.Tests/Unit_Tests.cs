using Encryption.Engine;

namespace Encryption.Tests;

public class Unit_Tests
{
    [TestCase(100)]
    [TestCase(1_000)]
    [TestCase(10_000)]
    [TestCase(100_000)]
    public void Encryption_Test(int length)
    {
        var data = Randomizer.Get(length);
        var copy = new byte[data.Length];
        Array.Copy(data, copy, data.Length);
        var encrypt_data = new Encrypt_Data(copy);

        Key_Encryption.Encrypt(encrypt_data);
        Key_Decryption.Decrypt(encrypt_data);

        Assert.That(data, Is.EqualTo(copy));
    }

    [Test]
    public void Encryption_Zeros_Test()
    {
        var encrypt_data = new Encrypt_Data(new byte[100]);

        Key_Encryption.Encrypt(encrypt_data);
        Key_Decryption.Decrypt(encrypt_data);

        Assert.That(new byte[100], Is.EqualTo(encrypt_data.Data));
    }

    [Test]
    public void Encryption_Extra_Is_Zeros_Test()
    {
        var encrypt_data = new Encrypt_Data(new byte[32]);

        Key_Encryption.Encrypt(encrypt_data);

        Assert.That(new byte[16], Is.EqualTo(encrypt_data.Extra));
    }

    [Test]
    public void Encryption_Encrypt_All_Data_Test()
    {
        var encrypt_data = new Encrypt_Data(new byte[100], 16, 1);

        Key_Encryption.Encrypt(encrypt_data);

        var last = encrypt_data.Data.Skip(100 - 4).ToArray();
        Assert.That(new byte[4], Is.Not.EqualTo(last));
    }

}