using System.Text;

namespace Encryption.Common;

public static class String_Extensions
{
    public static byte[] To_Bytes(this string str)
    {
        return Encoding.UTF8.GetBytes(str);
    }

    public static string To_String(this byte[] data)
    {
        return Encoding.UTF8.GetString(data);
    }
}