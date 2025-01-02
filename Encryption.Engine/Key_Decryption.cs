namespace Encryption.Engine;

public class Key_Decryption : Base_Key
{
    public static void Decrypt(Encrypt_Data data)
    {
        XOr_Block(data.IV, data.Key);

        for (int time_index = data.Times - 1; time_index >= 0; time_index--)
            for (int block_index = data.Blocks - 1; block_index >= 0; block_index--)
                Encrypt_Block(data, block_index, time_index == 0);
    }
}