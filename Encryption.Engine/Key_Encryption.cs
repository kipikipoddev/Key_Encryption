using System.Collections.Generic;

namespace Encryption.Engine;

public class Key_Encryption
{
    private const int Meta_Data = 2;

    private readonly static Random random = new();

    public static byte[] Encrypt(byte[] data, byte[] key, byte times)
    {
        var first = (byte)random.Next();
        Array.Resize(ref data, data.Length + Meta_Data);

        for (int x = 0; x < times; x++)
            for (int i = 0; i < data.Length - Meta_Data; i++)
                data[i] += Get_Extra(data, key, first, i);

        data[^2] = times;
        data[^1] = first;
        return data;
    }

    public static byte[] Decrypt(byte[] data, byte[] key)
    {
        var times = data[^2];
        var first = data[^1];

        Array.Resize(ref data, data.Length - Meta_Data);

        for (int x = 0; x < times; x++)
            for (int i = data.Length - 1; i >= 0; i--)
                data[i] -= Get_Extra(data, key, first, i);

        return data;
    }

    private static byte Get_Extra(byte[] data, byte[] key, byte first, int i)
    {
        var prefix = (i > 0 ? data[i - 1] : first);
        var suffix =  key[i % key.Length];
        return (byte)(prefix + suffix);
    }
}