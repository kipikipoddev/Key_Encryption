using System.Security.Cryptography;

namespace Encryption.Engine;

public class Key_Encryption : Base_Key
{
    public static byte[] Encrypt(byte[] data, byte[] key, int times)
    {
        var block_size = key.Length;
        var org_length = data.Length;
        var padding = org_length % block_size;
        var length = org_length + padding;

        Array.Resize(ref data, length + block_size * 2 + 8);
        Add_Metadata(data, times, block_size, org_length, length);

        Encrypt_Data(data, key, times, length, block_size);

        XOr_Block(data, length + block_size, length - block_size, key);
        return data;
    }

    private static void Encrypt_Data(byte[] data, byte[] key, int times, int length, int block_size)
    {
        var blocks = length / block_size;
        for (int time_index = 0; time_index < times; time_index++)
            for (int block_index = 0; block_index < blocks; block_index++)
                Encrypt_Block(data, key, length, block_size, block_index, time_index == 0);
    }

    private static void Encrypt_Block(byte[] data, byte[] key, int data_length, int block_size, int block_index, bool is_first_time)
    {
        var prev_index = Get_Prev_Index(data_length, block_size, block_index, is_first_time);
        XOr_Block(data, block_index * block_size, prev_index, key);
    }

    private static int Get_Prev_Index(int data_length, int block_size, int block_index, bool is_first_time)
    {
        if (block_index == 0)
            if (is_first_time)
                return data_length;
            else
                return data_length - block_size;
        return (block_index - 1) * block_size;
    }

    private static void Add_Metadata(byte[] data, int times, int block_size, int org_length, int length)
    {
        Buffer.BlockCopy(Get_IV(block_size), 0, data, length, block_size);
        Buffer.BlockCopy(BitConverter.GetBytes(org_length), 0, data, length + block_size * 2, 4);
        Buffer.BlockCopy(BitConverter.GetBytes(times), 0, data, length + block_size * 2 + 4, 4);
    }

    private static byte[] Get_IV(int length)
    {
        var randomBytes = new byte[length];
        using (var rng = RandomNumberGenerator.Create())
            rng.GetBytes(randomBytes);
        return randomBytes;
    }
}