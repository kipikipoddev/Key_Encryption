namespace Encryption.Common;

public static class Random_Extensions
{
    public static byte[] Get_Random_Bytes(this Random random, int size)
    {
        var bytes = new byte[size];
        random.NextBytes(bytes);
        return bytes;
    }
}