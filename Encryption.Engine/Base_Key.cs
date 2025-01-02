namespace Encryption.Engine;

public abstract class Base_Key
{
    protected static void Encrypt_Block(Encrypt_Data data, int block_index, bool is_first_time)
    {
        var prev_data = Get_Prev_Block(data, block_index, is_first_time);
        var prev_index = Get_Prev_Index(data, block_index, is_first_time);
        var key_index = block_index % 2 == 0 ? 0 : data.Block_Size;
        XOr_Block(data, block_index, prev_data, prev_index, key_index);
    }

    protected static void XOr_Block(byte[] data, byte[] key)
    {
        for (int i = 0; i < data.Length; i++)
            data[i] = (byte)(data[i] ^ key[i]);
    }

    private static byte[] Get_Prev_Block(Encrypt_Data data, int block_index, bool is_first_time)
    {
        return block_index == 0 & is_first_time ? data.IV : data.Data;
    }

    private static int Get_Prev_Index(Encrypt_Data data, int block_index, bool is_first_time)
    {
        if (block_index == 0)
            if (is_first_time)
                return 0;
            else
                return data.Blocks - 1;
        return block_index - 1; ;
    }

    private static void XOr_Block(Encrypt_Data data, int data_index, byte[] prev_data, int prev_index, int key_index)
    {
        data_index *= data.Block_Size;
        prev_index *= data.Block_Size;
        for (int i = 0; i < data.Block_Size; i++)
        {
            if (prev_index + i >= prev_data.Length)
                data.Data[data_index + i] = (byte)(data.Data[data_index + i] ^ data.Extra[i] ^ data.Key[key_index + i]);
            else if (data_index + i < data.Data.Length)
                data.Data[data_index + i] = (byte)(data.Data[data_index + i] ^ prev_data[prev_index + i] ^ data.Key[key_index + i]);
            else
                data.Extra[i] = (byte)(data.Extra[i] ^ prev_data[prev_index + i] ^ data.Key[key_index + i]);
        }
    }
}