using System.Security.Cryptography;

namespace Encryption.Engine;

public class Key_Encryption
{
    public static byte[] Encrypt(byte[] data, byte[] key, int times)
    {
        var blocked_data = Get_Blocked_Data(data, key, times);

        Encrypt_Blocked_Data(blocked_data, key, times);

        Encrypt_Block(blocked_data[^2], key, blocked_data[^3]);

        return blocked_data.SelectMany(innerArray => innerArray).ToArray();
    }

    private static void Encrypt_Blocked_Data(byte[][] data, byte[] key, int times)
    {
        for (int t = 0; t < times; t++)
            for (int i = 1; i < data.Length - 2; i++)
                Encrypt_Block(data[i], key, (t != 0 && i == 1) ? data[^3] : data[i - 1]);
    }

    private static byte[][] Get_Blocked_Data(byte[] data, byte[] key, int times)
    {
        var block_length = key.Length;
        var blocked_data = new byte[(data.Length / block_length) + 4][];
        Copy_Data(data, block_length, blocked_data);
        Add_Meta_Data(data, times, block_length, blocked_data);
        return blocked_data;
    }

    private static void Add_Meta_Data(byte[] data, int times, int block_length, byte[][] blocked_data)
    {
        blocked_data[0] = Get_IV(block_length);
        blocked_data[^2] = new byte[block_length];
        blocked_data[^1] = [.. BitConverter.GetBytes(times), .. BitConverter.GetBytes(data.Length)];
    }

    private static void Copy_Data(byte[] data, int block_length, byte[][] blocked_data)
    {
        for (int i = 1; i < blocked_data.Length - 2; i++)
        {
            blocked_data[i] = new byte[block_length];
            var length = Math.Min(block_length, data.Length - (i - 1) * block_length);
            Array.Copy(data, (i - 1) * block_length, blocked_data[i], 0, length);
        }
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