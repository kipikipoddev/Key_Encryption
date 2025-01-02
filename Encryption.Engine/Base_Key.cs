using System;
using System.Collections;

namespace Encryption.Engine;

public abstract class Base_Key
{
    protected static IEnumerable<byte> Get_Bytes(BitArray[] data)
    {
        for (int i = 0; i < data.Length; i++)
        {
            var block = BitArrayToBytes(data[i]);
            foreach (var b in block)
                yield return b;
        }
    }

    protected static BitArray Get_Prev(BitArray[] arrays, BitArray iv, int t, int b)
    {
        if (b > 0)
            return arrays[b - 1];
        if (t == 0)
            return iv;
        return arrays[^1];
    }

    protected static IEnumerable<BitArray> Get_Bit_Blocks(byte[] data, int length, byte block_size)
    {
        var blocks = length / block_size + (length % block_size == 0 ? 0 : 1);
        for (int i = 0; i <blocks; i++)
        {
            var block = data.Skip(i * block_size).Take(block_size).ToArray();
            if (block.Length < block_size)
                block = [.. block, .. new byte[block_size - block.Length]];
            yield return new BitArray(block);
        }
    }

    protected static void XOr_Block(byte[] data, int index, int prev_index, byte[] key)
    {
        for (int i = 0; i < key.Length; i++)
            data[index + i] = (byte)(data[index + i] ^ data[prev_index + i] ^ key[i]);
    }

    protected static void XOr_Block(byte[] data, int index, byte[] key)
    {
        for (int i = 0; i < key.Length; i++)
            data[index + i] = (byte)(data[index + i] ^ key[i]);
    }

    private static byte[] BitArrayToBytes(BitArray bitArray)
    {
        if (bitArray.Length == 0)
            return Array.Empty<byte>();

        int byteCount = (bitArray.Length + 7) / 8;
        byte[] bytes = new byte[byteCount];

        for (int i = 0; i < bitArray.Length; i++)
            if (bitArray[i])
                bytes[i / 8] |= (byte)(1 << (i % 8));
        return bytes;
    }
}