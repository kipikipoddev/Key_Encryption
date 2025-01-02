using BenchmarkDotNet.Running;
using BenchmarkExample;
using System;
using System.Collections;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main()
    {
        BenchmarkRunner.Run<EncBenchmark>();

        // Sample text to encrypt
        string original = "Hello, AES Encryption!";

        // Generate a random key and IV
        using Aes aes = Aes.Create();
        aes.Key = Enc.GenerateRandomKey(32); // 32 bytes = 256 bits for AES-256
        aes.IV = Enc.GenerateRandomKey(16); // 16 bytes = 128 bits IV

        // Encrypt the text
        byte[] encrypted = Enc.EncryptStringToBytes(original, aes.Key, aes.IV);

        // Decrypt the text
        string decrypted = Enc.DecryptStringFromBytes(encrypted, aes.Key, aes.IV);

        // Display results
        Console.WriteLine("Original: " + original);
        Console.WriteLine("Encrypted (Base64): " + Convert.ToBase64String(encrypted));
        Console.WriteLine("Decrypted: " + decrypted);
    }
}
