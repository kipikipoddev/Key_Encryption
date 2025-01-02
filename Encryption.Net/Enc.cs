using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class Enc
{
    public static byte[] GenerateRandomKey(int size)
    {
        var key = new byte[size];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(key);
        }
        return key;
    }

    public static byte[] EncryptStringToBytes(string plainText, byte[] key, byte[] iv)
    {
        if (string.IsNullOrEmpty(plainText))
            throw new ArgumentNullException(nameof(plainText));
        if (key == null || key.Length <= 0)
            throw new ArgumentNullException(nameof(key));
        if (iv == null || iv.Length <= 0)
            throw new ArgumentNullException(nameof(iv));

        using Aes aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;

        using var encryption = aes.CreateEncryptor(aes.Key, aes.IV);
        using var msEncrypt = new MemoryStream();
        using (var csEncrypt = new CryptoStream(msEncrypt, encryption, CryptoStreamMode.Write))
        using (var swEncrypt = new StreamWriter(csEncrypt))
        {
            swEncrypt.Write(plainText);
        }
        return msEncrypt.ToArray();
    }

    public static string DecryptStringFromBytes(byte[] cipherText, byte[] key, byte[] iv)
    {
        if (cipherText == null || cipherText.Length <= 0)
            throw new ArgumentNullException(nameof(cipherText));
        if (key == null || key.Length <= 0)
            throw new ArgumentNullException(nameof(key));
        if (iv == null || iv.Length <= 0)
            throw new ArgumentNullException(nameof(iv));

        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;

        using var descriptor = aes.CreateDecryptor(aes.Key, aes.IV);
        using var msDecrypt = new MemoryStream(cipherText);
        using var csDecrypt = new CryptoStream(msDecrypt, descriptor, CryptoStreamMode.Read);
        using var srDecrypt = new StreamReader(csDecrypt);
        return srDecrypt.ReadToEnd();
    }
}
