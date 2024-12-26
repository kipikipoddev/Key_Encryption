using System.Security.Cryptography;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace Encryption.Engine;

public class Key_Encryption
{
    public static byte[] Encrypt(byte[] data, byte[] key, byte times)
    {
        var iv = Get_IV(key.Length);
        var org_length = data.Length;

        Array.Resize(ref data, data.Length + 1 + key.Length);

        data[org_length] = times;
        for (int i = 0; i < key.Length; i++)
            data[org_length + i + 1] = iv[i];

        Process_Data(data, key, times, iv);

        return data;
    }

    public static byte[] Decrypt(byte[] data, byte[] key)
    {
        var org_length = data.Length - key.Length - 1;
        var times = data[org_length];
        var iv = new byte[key.Length];
        for (int i = 0; i < key.Length; i++)
            data[org_length + 1 + i] = iv[i];

        Array.Resize(ref data, org_length);

        Process_Data(data, key, times, iv);

        return data;
    }

    private static void Process_Data(byte[] data, byte[] key, byte times, byte[] iv)
    {
        for (int t = 0; t < times; t++)
            for (int block = 0; block < data.Length / key.Length + 1; block++)
                Process_Block(data, key, iv, block, t == 0);
    }

    private static void Process_Block(byte[] data, byte[] key, byte[] iv, int block, bool is_first)
    {
        var index = block * key.Length;
        var encrypted = Get_Block(data, key, iv, index, is_first);
        var i = 0;
        foreach (var e in encrypted)
            data[index + (i++)] = e;
    }

    private static IEnumerable<byte> Get_Block(byte[] data, byte[] key, byte[] iv, int index, bool is_first)
    {
        var length = Math.Min(key.Length, data.Length - index);
        for (int i = 0; i < length; i++)
        {
            var suffix = (is_first && index == 0 ?
                iv[i] :
                index == 0 ?
                    data[data.Length - key.Length + i] :
                    data[index + i]);
            yield return (byte)(key[i] ^ data[index + i] ^ suffix);
        }
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