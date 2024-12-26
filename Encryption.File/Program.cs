using Encryption.Engine;

var data = File.ReadAllBytes(".\\Advanced_Encryption_Standard.pdf");
var key = Guid.NewGuid().ToByteArray();

var encrypted = Key_Encryption.Encrypt(data, key, 128);

File.WriteAllBytes(".\\Advanced_Encryption_Standard.enc", encrypted);

var decrypted = Key_Decryption.Decrypt(encrypted, key, 128);

File.WriteAllBytes(".\\Advanced_Encryption_Standard_dyc.pdf", encrypted);