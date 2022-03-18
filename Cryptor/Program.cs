using System;
using System.Configuration;
using System.IO;
using System.Security.Cryptography;

namespace Cryptor
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                DisplayHelp();
                return;
            }

            var action = args[0];
            var input = args[1];

            var key = args.Length > 2 ? args[2] : null;
            var iv = args.Length > 3 ? args[3] : null;

            if (action is "-e" or "--encrypt")
            {
                try
                {
                    using Rijndael myRijndael = Rijndael.Create();
                    var keyAndIvWasProvided = SetKeyAndInitializationVector(myRijndael, key, iv);
                    if (!keyAndIvWasProvided)
                    {
                        Console.WriteLine("No Key and/or IV was found/provided, so generated new ones:");
                        Console.WriteLine($"KEY = {BitConverter.ToString(myRijndael.Key)}");
                        Console.WriteLine($"IV = {BitConverter.ToString(myRijndael.IV)}");
                        Console.WriteLine("You may want to copy them and add them to the App.config file.");
                    }

                    // Encrypt the string to an array of bytes.
                    byte[] encrypted = EncryptStringToBytes(input, myRijndael.Key, myRijndael.IV);
                    var chars = Convert.ToBase64String(encrypted);
                    
                    //display encrypted text
                    Console.WriteLine(string.Join("", chars));
                }
                catch (Exception e)
                {
                    Console.WriteLine("Error: {0}", e.Message);
                }
            }
            else if(action is "-d" or "--decrypt")
            {
                try
                {
                    using Rijndael myRijndael = Rijndael.Create();
                    SetKeyAndInitializationVector(myRijndael, key, iv);

                    // Decrypt the bytes to a string.
                    var base64decoded = Convert.FromBase64CharArray(input.ToCharArray(), 0, input.Length);
                    string decryptedText = DecryptStringFromBytes(
                        base64decoded, myRijndael.Key, myRijndael.IV);

                    //Display decrypted text
                    Console.WriteLine(decryptedText);
                }
                catch (Exception e)
                {
                    Console.WriteLine("Error: {0}", e.Message);
                }
            }
            else
            {
                DisplayHelp();
            }

            static void DisplayHelp()
            {
                Console.WriteLine("Cryptor v0.1");
                Console.WriteLine("USAGE:");
                Console.WriteLine("  cryptor -e whatToEncrypt [Key] [IV]");
                Console.WriteLine("  cryptor -d whatToDecrypt [Key] [IV]");
            }

            static byte[] EncryptStringToBytes(string plainText, byte[] Key, byte[] IV)
            {
                // Check arguments.
                if (plainText == null || plainText.Length <= 0)
                    throw new ArgumentNullException("plainText");
                if (Key == null || Key.Length <= 0)
                    throw new ArgumentNullException("Key");
                if (IV == null || IV.Length <= 0)
                    throw new ArgumentNullException("IV");
                byte[] encrypted;
                // Create an Rijndael object
                // with the specified key and IV.
                using Rijndael rijAlg = Rijndael.Create();
                rijAlg.Key = Key;
                rijAlg.IV = IV;
                rijAlg.Padding = PaddingMode.PKCS7;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {

                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }

                // Return the encrypted bytes from the memory stream.
                return encrypted;
            }

            static string DecryptStringFromBytes(byte[] cipherText, byte[] Key, byte[] IV)
            {
                // Check arguments.
                if (cipherText == null || cipherText.Length <= 0)
                    throw new ArgumentNullException("cipherText");
                if (Key == null || Key.Length <= 0)
                    throw new ArgumentNullException("Key");
                if (IV == null || IV.Length <= 0)
                    throw new ArgumentNullException("IV");

                // Declare the string used to hold
                // the decrypted text.
                string plaintext = null;

                // Create an Rijndael object
                // with the specified key and IV.
                using Rijndael rijAlg = Rijndael.Create();
                rijAlg.Key = Key;
                rijAlg.IV = IV;
                rijAlg.Padding = PaddingMode.PKCS7;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

                return plaintext;
            }
        }

        private static bool SetKeyAndInitializationVector(Rijndael myRijndael, string key, string iv)
        {
            if (!(string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(iv)))
            {
                myRijndael.Key = Convert.FromHexString(key);
                myRijndael.IV = Convert.FromHexString(iv);
                return true;
            }
            if (!(string.IsNullOrWhiteSpace(ConfigurationManager.AppSettings["key"]) ||
                       string.IsNullOrWhiteSpace(ConfigurationManager.AppSettings["iv"])))
            {
                myRijndael.Key = Convert.FromHexString(ConfigurationManager.AppSettings["key"].Replace("-", ""));
                myRijndael.IV = Convert.FromHexString(ConfigurationManager.AppSettings["iv"].Replace("-", ""));
                return true;
            }
            return false;
        }
    }
}
