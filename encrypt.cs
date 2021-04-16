/* 
 * This code is largerly derived from the microsoft documentation on rfc2898
 * https://docs.microsoft.com/en-us/dotnet/api/
 *           system.security.cryptography.rfc2898derivebytes?view=net-5.0
 * 
 */

/* Notes About File
 * @File: pbkdf2.cs
 * @Name: Christian Dunham
 * @Number: 1978955
 * @Date: 12Apr2021
 * @Program Name:  pbkdf2
 *
 * Program Purpose:
 *    This program implements a multi-threaded client server program that uses
 *    TCP sockets to evaluate reads and writes made by the system.
 *
 * Design Rational:  
 *    One decision was xyz.... because....  
 *
 * Dynamic Memory:
 *    The only dynamic memory comes from the socket API and taken care of in
 *    the server code. Testing VS change git.
 *
 *******************************************************************************
 *******************************************************************************
 *
 *                        Special Cases Identified
 * : connection errors : Check and send message to console
 *
 *******************************************************************************
 *
 *******************************************************************************
 *Product BackLog :
 *                 1) xyz
 *
 *******************************************************************************
 *
 *******************************************************************************
 * Code Outline :
 *
 *                       Client : Program
 *              
 *                              : Section 1  : Glbl Var & Functions
 *
 *                              : Section 2  : main()
 *
 ******************************************************************************* 
 *
 *                        Included Libraries
 *
 *******************************************************************************
 *******************************************************************************
*/
using System;
using System.IO;
using System.Text;
using System.Security.Cryptography; //For rfc2898
using System.Diagnostics; //For timer



public class rfc2898key
{
    // Generate a key k1 with password pwd1 and salt salt1.
    // Encrypt data1 with key k1 using symmetric encryption, creating edata1.
    // Decrypt edata1 with key k2 using symmetric decryption, creating data2.
    // data2 should equal data1.

    private const string usageText = "Usage: RFC2898 <password>\nYou must specify the password for encryption.\n";
    public static void Main(string[] passwordargs)
    {
        //Implement timer for diagnostics
        //Code modified from https://docs.microsoft.com/en-us/dotnet/
        //         api/system.diagnostics.stopwatch.elapsed?view=net-5.0
        Stopwatch stopWatch = new Stopwatch();
        stopWatch.Start();
        //If no file name is specified, write usage text.
        if (passwordargs.Length == 0)
        {
            Console.WriteLine(usageText);
        }
        else
        {
            string pwd1 = passwordargs[0];
            string plainText = "This is the plaintext to encrypt test.";

            //Create a byte array to hold the random value.
            byte[] salt1 = new byte[8];

            //Use CryptoService to generate random bytes for salt
            using (RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider())
            {
                // Fill the array with a random value.
                rngCsp.GetBytes(salt1);
            }

            //data1 can be a string or contents of a file.
            //TODO: needs to be a file some how
            string data1 = "Some test data";
            //The default iteration count is 1000 so the two methods use the same iteration count.
            int myIterations = 1000000;
            try
            {
                /*
                 * 1. Create a master key using PBKDF#2
                 * The rfc2898DeriveBytes function from the .NET Cryptography.Security
                 * takes a password, salt, number of iterations, and algorith
                 * to create the master key.
                 * pwd1: the password to encrypt
                 * salt1: a set of at least 8 bytes
                 * myIterations: number of iterations (at least 1000)
                 * HashAlgorithmName: hashing algorithm - see 
                 *       https://docs.microsoft.com/en-us/dotnet/api/
                 *       system.security.cryptography.hashalgorithmname?
                 *       view=net-5.0
                 *       For more information
                 * output: k1: a master key from arguments
                 * TODO import time api and test different iterations
                */


                //Make master key object
                Rfc2898DeriveBytes masterKey_Obj = new Rfc2898DeriveBytes
                    (pwd1, salt1, myIterations, HashAlgorithmName.SHA256);



                //Use rfc2898 object to make master key
                byte[] masterKey_Bytes = masterKey_Obj.GetBytes(32);

                /*
                 * 2. Create encryption key and hmac key
                 * Once we have an rfc2898 generated master key we use it 
                 * to derive the keys, but change the salt and iterations.
                 * masterKey_Bytes: the password to encrypt
                 * salt2/3: unique to each key needs to be at least 8 bytes
                 * numIter: number of iterations set to 1 as per specificaition
                 * HashAlgorithmName: hashing algorithm - see 
                 *       https://docs.microsoft.com/en-us/dotnet/api/
                 *       system.security.cryptography.hashalgorithmname?
                 *       view=net-5.0
                 *       For more information
                 * output: encryptionKey/HMAC_Key: a master key from arguments
                 */

                //Encryption Key Creation
                string encryptionSalt_String = "I am the Encryption Key";
                int numIter = 1;
                byte[] salt2 = Encoding.ASCII.GetBytes(encryptionSalt_String);
                Rfc2898DeriveBytes encryptionKey = new Rfc2898DeriveBytes
                   (masterKey_Bytes, salt2, numIter, HashAlgorithmName.SHA256);

                //HMAC Key Creation
                string HMAC_Salt_String = "I am the HMAC Key";
                byte[] salt3 = Encoding.ASCII.GetBytes(HMAC_Salt_String);
                Rfc2898DeriveBytes HMAC_Key = new Rfc2898DeriveBytes
                   (masterKey_Bytes, salt3, numIter, HashAlgorithmName.SHA256);

                /*
                 * 3. Encrypt data using CBC chaining mode
                 * Must work with 3DES, AES128, AES256
                 * Use random IV that is one block size
                 * Do not assume block size
                 * output: 
                 */
                byte[] encrypted = encrypt(plainText, encryptionKey);
                Console.WriteLine("Encrypted (b64-encode): {0}", Convert.ToBase64String(encrypted));
                /*

                //encrypt data
                MemoryStream encryptionStream = new MemoryStream();
                CryptoStream encrypt = new CryptoStream(encryptionStream,
encryptedKey.CreateEncryptor(), CryptoStreamMode.Write);
                byte[] utfD1 = new System.Text.UTF8Encoding(false).GetBytes(
data1);

                encrypt.Write(utfD1, 0, utfD1.Length);
                encrypt.FlushFinalBlock();
                encrypt.Close();
                byte[] edata1 = encryptionStream.ToArray();
                Console.WriteLine(Convert.ToBase64String(edata1));
                */

                //k1.Reset();

                //Rfc2898DeriveBytes encryptKey = masterKey.CryptDeriveKey("AES","SHA256",256,encAlg.IV);

                /*
                // Try to decrypt, thus showing it can be round-tripped.
                Aes decAlg = Aes.Create();
                decAlg.Key = k2.GetBytes(32);
                decAlg.IV = encAlg.IV;
                MemoryStream decryptionStreamBacking = new MemoryStream();
                CryptoStream decrypt = new CryptoStream(
decryptionStreamBacking, decAlg.CreateDecryptor(), CryptoStreamMode.Write);
                decrypt.Write(edata1, 0, edata1.Length);
                decrypt.Flush();
                decrypt.Close();
                k2.Reset();
                string data2 = new UTF8Encoding(false).GetString(
decryptionStreamBacking.ToArray());

                if (!data1.Equals(data2))
                {
                    Console.WriteLine("Error: The two values are not equal.");
                }
                else
                {
                    Console.WriteLine("The two values are equal.");
                    Console.WriteLine("k1 iterations: {0}", k1.IterationCount);
                    Console.WriteLine("k2 iterations: {0}", k2.IterationCount);
                }
                */
            }
            catch (Exception e)
            {
                Console.WriteLine("Error: {0}", e);
            }
        }
        //Get time
        stopWatch.Stop();
        TimeSpan ts = stopWatch.Elapsed;
        string elapsedTime = String.Format("{0:00}:{1:00}:{2:00}.{3:00}",
              ts.Hours, ts.Minutes, ts.Seconds, ts.Milliseconds);
        Console.WriteLine("RunTime " + stopWatch.Elapsed);
    }

    /*
     * encrypt(string plainText, byte[] key)
     * 
     *  
    */
    static byte[] encrypt(string plainText, Rfc2898DeriveBytes encryptedKey) 
    {
        byte[] encrypted;
        byte[] IV;

        using (Aes aes_enc = Aes.Create())
        {
            aes_enc.Key = encryptedKey.GetBytes(32);
            aes_enc.GenerateIV();
            IV = aes_enc.IV;
            aes_enc.Mode = CipherMode.CBC;
            var encryptor = aes_enc.CreateEncryptor(aes_enc.Key, aes_enc.IV);

            using (var msEncrypt = new MemoryStream())
            {
                using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (var swEncrypt = new StreamWriter(csEncrypt))
                    {
                        //Write all data to the stream.
                        swEncrypt.Write(plainText);
                    }
                    encrypted = msEncrypt.ToArray();
                }
            }
        }

        var combinedIvCt = new byte[IV.Length + encrypted.Length];
        Array.Copy(IV, 0, combinedIvCt, 0, IV.Length);
        Array.Copy(encrypted, 0, combinedIvCt, IV.Length, encrypted.Length);

        // Return the encrypted bytes from the memory stream. 
        return combinedIvCt;
    }
}

