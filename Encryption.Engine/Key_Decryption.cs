using System.Collections;

namespace Encryption.Engine;

public class Key_Decryption : Base_Key
{
    public static byte[] Decrypt(byte[] data, byte[] key, byte block_size = 16, byte times = 10)
    {
        var key_bit = new BitArray(key);
        var iv = data.Skip(data.Length - block_size).Take(block_size).ToArray();
        var iv_bits = new BitArray(iv);
        var arrays = Get_Bit_Blocks(data, data.Length - block_size, block_size).ToArray();

        for (int t = times - 1; t >= 0; t--)
        {
            for (var b = arrays.Length - 1; b >= 0; b--)
            {
                var last = Get_Prev(arrays, iv_bits, t, b);
                arrays[b] = arrays[b].Xor(last).Xor(key_bit);
            }
        }

        return Get_Bytes(arrays).ToArray();
    }

}