namespace Encryption.Engine;

public class Key_Decryption: Base_Key
{
    public static byte[] Decrypt(byte[] data, byte[] key)
    {
        var block_size = key.Length;
        var org_length = BitConverter.ToInt32(data, data.Length - 8);
        var times = BitConverter.ToInt32(data, data.Length - 4);
        var padding = org_length % block_size;
        var length = org_length + padding;

        Decrypt(data, key, block_size, times, length);
        Array.Resize(ref data, org_length);

        return data;
    }

    private static void Decrypt(byte[] data, byte[] key, int block_size, int times, int length)
    {
        var blocks = length / block_size;
        for (int t = 0; t < times; t++)
            for (var block_index = blocks - 1; block_index >= 0; block_index--)
                Decrypt_Block(data, key, block_size, times, length, t, block_index);
    }

    private static void Decrypt_Block(byte[] data, byte[] key, int block_size, int times, int length, int t, int block_index)
    {
        var prev_index = Get_Prev_Index(length, block_size, block_index, t == times - 1);
        XOr_Block(data, block_index * block_size, prev_index, key);
    }

    private static int Get_Prev_Index(int data_length, int block_size, int block_index, bool last_time)
    {
        if (block_index == 0)
            if (last_time)
                return data_length;
            else
                return data_length - block_size;
        return (block_index - 1) * block_size;
    }
}