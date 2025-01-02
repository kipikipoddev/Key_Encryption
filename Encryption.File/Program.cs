using Encryption.Engine;
using System.Text.Json;

var data = File.ReadAllBytes(".\\Advanced_Encryption_Standard.pdf");
var encrypt_data = new Encrypt_Data(data);

Key_Encryption.Encrypt(encrypt_data);

File.WriteAllBytes(".\\Advanced_Encryption_Standard.enc", encrypt_data.Data);

Key_Decryption.Decrypt(encrypt_data);

File.WriteAllBytes(".\\Advanced_Encryption_Standard_dyc.pdf", encrypt_data.Data);