namespace Encryption.Engine;

public class Key_Encryption : Base_Key
{
    public static void Encrypt(Encrypt_Data data)
    {
        for (int time_index = 0; time_index < data.Times; time_index++)
            for (int block_index = 0; block_index < data.Blocks; block_index++)
                Encrypt_Block(data, block_index, time_index == 0);

        XOr_Block(data.IV, data.Key);
    }
}