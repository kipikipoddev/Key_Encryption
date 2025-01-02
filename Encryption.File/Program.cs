using Encryption.Engine;

var data = File.ReadAllBytes(".\\Advanced_Encryption_Standard.pdf");
var key = Guid.NewGuid().ToByteArray();

var encrypted = Key_Encryption.Encrypt(data, key, 10);

File.WriteAllBytes(".\\Advanced_Encryption_Standard.enc", encrypted);

var decrypted = Key_Decryption.Decrypt(encrypted, key);

File.WriteAllBytes(".\\Advanced_Encryption_Standard_dyc.pdf", decrypted);