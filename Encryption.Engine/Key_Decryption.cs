namespace Encryption.Engine;

public class Key_Decryption
{
    public static byte[] Decrypt(byte[] data, byte[] key)
    {
        var blocked_data = Get_Blocked_Data(data, key.Length);
        var times = BitConverter.ToInt32(data, data.Length - 8);
        var org_length = BitConverter.ToInt32(data, data.Length - 4);

        Decrypt_Block(blocked_data[^1], key, blocked_data[^2]);
        if (blocked_data[^1].Any(d => d != 0))
            throw new Exception();

        Decrypt(blocked_data, key, times);

        return Get_Decrypted_Data(blocked_data, org_length);
    }

    private static void Decrypt(byte[][] data, byte[] key, int times)
    {
        for (int t = 0; t < times; t++)
        {
            for (int i = data.Length - 2; i > 0; i--)
            {
                var prev = Get_Prev_Block(data, times, t, i);
                Decrypt_Block(data[i], key, prev);
            }
        }
    }

    private static byte[] Get_Prev_Block(byte[][] data, int times, int t, int i)
    {
        if (i != 1)
            return data[i - 1];
        if (t == times - 1)
            return data[0];
        else
            return data[^2];
    }

    private static byte[][] Get_Blocked_Data(byte[] data, int block_length)
    {
        var blocked_data = new byte[data.Length / block_length][];

        for (int i = 0; i < blocked_data.Length; i++)
        {
            blocked_data[i] = new byte[block_length];
            Array.Copy(data, i * block_length, blocked_data[i], 0, block_length);
        }
        return blocked_data;
    }

    private static byte[] Get_Decrypted_Data(byte[][] blocked_data, int org_length)
    {
        var decrypted = new byte[org_length];
        var block_length = blocked_data[0].Length;
        for (int block = 1; block < blocked_data.Length - 1; block++)
        {
            var index = (block - 1) * block_length;
            if (index + block_length > decrypted.Length)
                block_length = (byte)(decrypted.Length - index);
            Array.Copy(blocked_data[block], 0, decrypted, index, block_length);
        }

        return decrypted;
    }

    private static void Decrypt_Block(byte[] data, byte[] key, byte[] prev)
    {
        for (int i = 0; i < data.Length; i++)
            data[i] = (byte)(data[i] ^ prev[i] ^ key[i]);
    }
}