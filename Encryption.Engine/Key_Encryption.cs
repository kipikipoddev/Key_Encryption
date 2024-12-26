using System.Security.Cryptography;

namespace Encryption.Engine;

public class Key_Encryption
{
    public static byte[] Encrypt(byte[] data, byte[] key, byte times)
    {
        var blocked_data = Get_Blocked_Data(data, key);

        Encrypt(blocked_data, key, times);

        Encrypt_Block(blocked_data[^1], key, blocked_data[^2]);

        return blocked_data.SelectMany(innerArray => innerArray).ToArray();
    }

    private static void Encrypt(byte[][] data, byte[] key, byte times)
    {
        for (int t = 0; t < times; t++)
        {
            for (int i = 1; i < data.Length - 2; i++)
            {
                var prev = (t != 0 && i == 1) ? data[^2] : data[i - 1];
                Encrypt_Block(data[i], key, prev);
            }
        }
    }

    private static byte[][] Get_Blocked_Data(byte[] data, byte[] key)
    {
        var block_length = key.Length;
        var blocked_data = new byte[(data.Length / block_length) + 3][];
        blocked_data[0] = Get_IV(block_length);

        for (int i = 1; i < blocked_data.Length - 1; i++)
        {
            blocked_data[i] = new byte[block_length];
            var length = Math.Min(block_length, data.Length - (i - 1) * block_length);
            Array.Copy(data, (i - 1) * block_length, blocked_data[i], 0, length);
        }
        blocked_data[^1] = new byte[block_length];
        return blocked_data;
    }

    private static void Encrypt_Block(byte[] data, byte[] key, byte[] prev)
    {
        for (int i = 0; i < data.Length; i++)
            data[i] = (byte)(data[i] ^ prev[i] ^ key[i]);
    }

    private static byte[] Get_IV(int length)
    {
        var randomBytes = new byte[length];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(randomBytes);
        }
        return randomBytes;
    }
}