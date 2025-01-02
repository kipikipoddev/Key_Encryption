namespace Encryption.Engine;

public class Encrypt_Data
{
    public byte[] Data;
    public byte[] Key;
    public byte[] IV;
    public byte[] Extra;
    public byte Block_Size;
    public byte Times;

    public int Blocks;

    public Encrypt_Data(byte[] data, byte block_size = 16, byte times = 10)
    {
        Data = data;
        Block_Size = block_size;
        Times = times;
        Key = Randomizer.Get(block_size * 2);
        IV = Randomizer.Get(block_size);
        Extra = new byte[Block_Size];
        Blocks = data.Length / Block_Size + (data.Length % Block_Size == 0 ? 0 : 1);
    }
}