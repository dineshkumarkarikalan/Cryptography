using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace json
{
    internal class CryptoGraphy
    {
        internal static void CryptographicHashFunctionDemo()
        {
            Console.WriteLine("***** Cryptographic hash demo *****");

            foreach (var message in new[] {
                "Fox",
                "The red fox jumps over the blue dog",
                "The red fox jumps ouer the blue dog",
                "The red fox jumps oevr the blue dog",
                "The red fox jumps oer the blue dog"})
            {
                Console.WriteLine($"{message} => {ComputeHash(message)}");
            }

            Console.Write(Environment.NewLine);
        }
        internal static string ComputeHash(string message)
        {
            using var sha256 = SHA256.Create();
            var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(message));
            return Convert.ToHexString(hashedBytes);
        }
        #region symmerticEncryption
        internal static void SymmetricEncryptionDemo()
        {
            Console.WriteLine("***** Symmetric encryption demo *****");

            var unencryptedMessage = "To be or not to be, that is the question, whether tis nobler in the...";
            Console.WriteLine("Unencrypted message: " + unencryptedMessage);

            // 1. Create a key (shared key between sender and reciever).
            byte[] key, iv;
            using (Aes aesAlg = Aes.Create())
            {
                key = aesAlg.Key;
                iv = aesAlg.IV;
            }

            // 2. Sender: Encrypt message using key
            var encryptedMessage = Encrypt(unencryptedMessage, key, iv);
            Console.WriteLine("Sending encrypted message: " + Convert.ToHexString(encryptedMessage));

            // 3. Receiver: Decrypt message using same key
            var decryptedMessage = Decrypt(encryptedMessage, key, iv);
            Console.WriteLine("Recieved and decrypted message: " + decryptedMessage);

            Console.Write(Environment.NewLine);
        }


        internal static byte[] Encrypt(string message, byte[] key, byte[] iv)
        {
            using var aesAlg = Aes.Create();
            aesAlg.Key = key;
            aesAlg.IV = iv;

            var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using var ms = new MemoryStream();
            using var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
            using (var sw = new StreamWriter(cs))
            {
                sw.Write(message); // Write all data to the stream.
            }
            return ms.ToArray();
        }

        internal static string Decrypt(byte[] cipherText, byte[] key, byte[] iv)
        {
            using var aesAlg = Aes.Create();
            aesAlg.Key = key;
            aesAlg.IV = iv;

            var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using var ms = new MemoryStream(cipherText);
            using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
            using var sr = new StreamReader(cs);
            return sr.ReadToEnd();
        }
        #endregion
        #region asymmetricEncription
        internal static void AsymmetricEncryptionDemo()
        {
            Console.WriteLine("***** Asymmetric encryption demo *****");

            var unencryptedMessage = "To be or not to be, that is the question, whether tis nobler in the...";
            Console.WriteLine("Unencrypted message: " + unencryptedMessage);

            // 1. Create a public / private key pair.
            RSAParameters privateAndPublicKeys, publicKeyOnly;
            using (var rsaAlg = RSA.Create())
            {
                privateAndPublicKeys = rsaAlg.ExportParameters(true);
                publicKeyOnly = rsaAlg.ExportParameters(false);
            }

            // 2. Sender: Encrypt message using public key
            var encryptedMessage = Encrypt(unencryptedMessage, publicKeyOnly);
            Console.WriteLine("Sending encrypted message: " + Convert.ToHexString(encryptedMessage));

            // 3. Receiver: Decrypt message using private key
            var decryptedMessage = Decrypt(encryptedMessage, privateAndPublicKeys);
            Console.WriteLine("Recieved and decrypted message: " + decryptedMessage);

            Console.Write(Environment.NewLine);
        }
        internal static byte[] Encrypt(string message, RSAParameters rsaParameters)
        {
            using var rsaAlg = RSA.Create(rsaParameters);
            return rsaAlg.Encrypt(Encoding.UTF8.GetBytes(message), RSAEncryptionPadding.Pkcs1);
        }

        internal static string Decrypt(byte[] cipherText, RSAParameters rsaParameters)
        {
            using var rsaAlg = RSA.Create(rsaParameters);
            var decryptedMessage = rsaAlg.Decrypt(cipherText, RSAEncryptionPadding.Pkcs1);
            return Encoding.UTF8.GetString(decryptedMessage);
        }
        #endregion
        #region Digital signatures
        internal static void MessageSignatureDemo()
        {
            Console.WriteLine("***** Message signature demo *****");

            var message = "To be or not to be, that is the question, whether tis nobler in the...";
            Console.WriteLine("Message to be verified: " + message);

            // 1. Create a public / private key pair.
            RSAParameters privateAndPublicKeys, publicKeyOnly;
            using (var rsaAlg = RSA.Create())
            {
                privateAndPublicKeys = rsaAlg.ExportParameters(includePrivateParameters: true);
                publicKeyOnly = rsaAlg.ExportParameters(includePrivateParameters: false);
            }

            // 2. Sender: Sign message using private key
            var signature = Sign(message, privateAndPublicKeys);
            Console.WriteLine("Message signature: " + Convert.ToHexString(signature));

            // 3. Receiver: Verify message authenticity using public key
            var isTampered = Verify(message, signature, publicKeyOnly);
            Console.WriteLine("Message is untampered: " + isTampered.ToString());

            Console.Write(Environment.NewLine);
        }
        internal static byte[] Sign(string message, RSAParameters rsaParameters)
        {
            using var rsaAlg = RSA.Create(rsaParameters);
            return rsaAlg.SignData(Encoding.UTF8.GetBytes(message), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        internal static bool Verify(string message, byte[] signature, RSAParameters rsaParameters)
        {
            using var rsaAlg = RSA.Create(rsaParameters);
            return rsaAlg.VerifyData(Encoding.UTF8.GetBytes(message), signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        #endregion
    }
}
