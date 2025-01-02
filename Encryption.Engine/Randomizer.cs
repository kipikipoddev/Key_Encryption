using System.Security.Cryptography;

namespace Encryption.Engine;

public static class Randomizer
{
    public readonly static RandomNumberGenerator random = RandomNumberGenerator.Create();

    public static byte[] Get(int length)
    {
        var randomBytes = new byte[length];
        random.GetBytes(randomBytes);
        return randomBytes;
    }
}
