namespace Encryption.Engine;

public class Key_Decryption
{
    public static byte[] Decrypt(byte[] data, byte[] key, byte times)
    {
        var blocked_data = Get_Blocked_Data(data, key);

        Decrypt(blocked_data, key, times);

        var decrypted = new byte[key.Length * blocked_data.Length - 2];
        for (int block = 1; block < blocked_data.Length - 2; block++)
            Array.Copy(blocked_data[block], 0, decrypted, (block - 1) * key.Length, key.Length);
        return decrypted;
    }

    private static void Decrypt(byte[][] data, byte[] key, byte times)
    {
        for (int t = 0; t < times; t++)
        {
            for (int i = data.Length - 2; i > 0; i--)
            {
                var prev = data[i + 1];
                if (t != 0 && i == data.Length - 2)
                    prev = data[1];
                Decrypt_Block(data[i], key, prev);
            }
        }
        Decrypt_Block(data[1], key, data[0]);
    }

    private static byte[][] Get_Blocked_Data(byte[] data, byte[] key)
    {
        var block_length = key.Length;
        var blocked_data = new byte[data.Length / block_length][];

        for (int i = 0; i < blocked_data.Length; i++)
        {
            blocked_data[i] = new byte[block_length];
            Array.Copy(data, i * block_length, blocked_data[i], 0, block_length);
        }
        return blocked_data;
    }

    private static void Decrypt_Block(byte[] data, byte[] key, byte[] prev)
    {
        for (int i = 0; i < data.Length; i++)
            data[i] = (byte)(data[i] ^ prev[i] ^ key[i]);
    }
}