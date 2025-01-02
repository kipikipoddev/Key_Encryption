using System.Collections;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;

namespace Encryption.Engine;

public class Key_Encryption : Base_Key
{
    public static byte[] Encrypt(byte[] data, byte[] key, byte block_size = 16, int times = 10)
    {
        var key_bit = new BitArray(key);
        var iv = Get_IV(block_size);
        var iv_bits = new BitArray(iv);
        var arrays = Get_Bit_Blocks(data, data.Length, block_size).ToArray();

        for (int t = 0; t < times; t++)
        {
            for (var b = 0; b < arrays.Length; b++)
            {
                var last = Get_Prev(arrays, iv_bits, t, b);
                arrays[b] = arrays[b].Xor(last).Xor(key_bit);
            }
        }
        return Get_Bytes(arrays).Concat(iv).ToArray();
    }

    private static byte[] Get_IV(int length)
    {
        var randomBytes = new byte[length];
        using (var rng = RandomNumberGenerator.Create())
            rng.GetBytes(randomBytes);
        return randomBytes;
    }


    private static IEnumerable<bool> Byte_To_Bits(byte input)
    {
        for (int i = 7; i >= 0; i--)
            yield return (input & (1 << i)) != 0;
    }

    private static byte Bits_To_Byte(IEnumerable<bool> bits)
    {
        byte result = 0;
        var i = 0;
        foreach (var item in bits)
        {
            if (item)
                result |= (byte)(1 << (7 - i));
            i++;
        }

        return result;
    }
}