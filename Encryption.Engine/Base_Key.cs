using System;

namespace Encryption.Engine;

public abstract class Base_Key
{
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
}