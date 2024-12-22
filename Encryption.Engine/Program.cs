using Encryption.Common;
using Encryption.Engine;
using System.Text;

internal partial class Program
{
    private static void Main(string[] args)
    {
        Test();
    }

    private static void Test()
    {
        var str = "Hello world!";
        var key = Guid.NewGuid().ToByteArray();

        var encrypted = Key_Encryption.Encrypt(str.To_Bytes(), key, 200);

        Console.WriteLine(string.Join(' ', encrypted.Select(e => (int)e)));

        var decrypted = Key_Encryption.Decrypt(encrypted, key);

        Console.WriteLine(decrypted.To_String());
    }
}