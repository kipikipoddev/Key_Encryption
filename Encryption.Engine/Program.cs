using Encryption.Common;
using Encryption.Engine;
using System.Text;

internal partial class Program
{
    private static void Main(string[] args)
    {
        //Test();
        Test2();
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

    private static void Test2()
    {
        var data = File.ReadAllBytes(".\\Advanced_Encryption_Standard.pdf");
        var key = Guid.NewGuid().ToByteArray();

        var encrypted = Key_Encryption.Encrypt(data, key, 128);

        File.WriteAllBytes(".\\Advanced_Encryption_Standard.enc", encrypted);

        var decrypted = Key_Encryption.Decrypt(encrypted, key);

        File.WriteAllBytes(".\\Advanced_Encryption_Standard_dyc.pdf", encrypted);
    }
}