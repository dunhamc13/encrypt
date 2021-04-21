/* 
 * This code is largerly derived from the microsoft documentation on rfc2898
 * https://docs.microsoft.com/en-us/dotnet/api/
 *           system.security.cryptography.rfc2898derivebytes?view=net-5.0
 * 
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
   

    /*
     * encrypt(byte[] dataToEncrypt, byte[] key, byte[] metaData, byte[] hmac_key, string signedFile)
     * Code here modified from: https://docs.microsoft.com/en-us/dotnet/api/
     *                              system.security.cryptography.aes?view=netframework-4.8
     * output: []byte : dataStruct : [metadata][hmac][iv][encrypted data]
    */
    public static byte[] encrypt(byte[] dataToEncrypt, byte[] encryptedKey, byte[] metaData, byte[] HMAC_key, string signedFile) 
    {
        //varaibles for enctrypted data and iv
        byte[] encrypted;
        byte[] IV;

        //Use AES to create encryption
        using (Aes aes_enc = Aes.Create())
        {
            aes_enc.Key = encryptedKey;
            aes_enc.GenerateIV();                    //for random IV
            IV = aes_enc.IV;
            aes_enc.Mode = CipherMode.CBC;           //for CBC mode
            var encryptor = aes_enc.CreateEncryptor(aes_enc.Key, aes_enc.IV);
            //use memory stream to encrypt data
            using (var msEncrypt = new MemoryStream())
            {
                using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (var swEncrypt = new StreamWriter(csEncrypt))
                    {
                        //Write all data to the stream.
                        swEncrypt.Write(dataToEncrypt);
                    }//end write stream
                    encrypted = msEncrypt.ToArray();
                }//end cryptostream
            }//end memory stream
        }//end aes encrypt

        //Combine IV and encrypted bytes to compute hash
        var combinedIvEncrypted = new byte[IV.Length + encrypted.Length];
        Array.Copy(IV, 0, combinedIvEncrypted, 0, IV.Length);
        Array.Copy(encrypted, 0, combinedIvEncrypted, IV.Length, encrypted.Length);
        byte[] mac = HMAC_Signature(HMAC_key, combinedIvEncrypted);

        /*
          * 4. Create HMAC of the IV and encrypted data
        */
        var dataStruct = new byte[metaData.Length + mac.Length + IV.Length + encrypted.Length];
        Array.Copy(metaData, 0, dataStruct, 0, metaData.Length);
        Array.Copy(mac, 0, dataStruct, metaData.Length + metaData.Length, mac.Length);
        Array.Copy(IV, 0, dataStruct, metaData.Length + mac.Length, IV.Length);
        Array.Copy(encrypted, 0, dataStruct, metaData.Length + mac.Length + IV.Length, encrypted.Length);

        //Write encrypted structure to file
        File.WriteAllBytes(signedFile, dataStruct);

        // Return the encrypted bytes from the memory stream. 
        return dataStruct;
    }//end encrypt

/*
  * HMAC_Signature(byte[] key, byte[] sourceFile)
  * Code here modified from: https://docs.microsoft.com/en-us/dotnet/api/
  *                              system.security.cryptography.hmacsha512?view=net-5.0  
  * output : byte[] hashValue : hash value from the hmac key covering the IV and Enctrypted dat
*/
    public static byte[] HMAC_Signature(byte[] key, byte[] sourceFile)
    {
 
        //variables for returning hash and the hmac key from hmac object
        byte[] hashValue;

        // Initialize the keyed hash object.
        using (HMACSHA512 hmac = new HMACSHA512(key))
        {
            // Compute the hash of the input file.
            // HMAC Statement
            Console.WriteLine("\n++++++++++++ Generating HMAC ++++++++++++++");
            hashValue = hmac.ComputeHash(sourceFile);
            Console.WriteLine("HMAC (b64-encode): {0}", Convert.ToBase64String(hashValue), "\n\n");
        }
        return hashValue;
    } // end HMAC_Signature

    /*
     * decrypt(byte[] dataToEncrypt, byte[] key, byte[] metaData, byte[] hmac_key, string signedFile)
     * Code here modified from: https://docs.microsoft.com/en-us/dotnet/api/
     *                              system.security.cryptography.aes?view=netframework-4.8
     * output: []byte : dataStruct : [metadata][hmac][iv][encrypted data]
*/
    static string DecryptStringFromBytes_Aes(byte[] cipherTextCombined, byte[] Key)
    {

        // Declare the string used to hold 
        // the decrypted text. 
        string plaintext = null;

        // Create an Aes object 
        // with the specified key and IV. 
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = Key;

            byte[] IV = new byte[aesAlg.BlockSize / 8];
            byte[] cipherText = new byte[cipherTextCombined.Length - IV.Length];

            Array.Copy(cipherTextCombined, IV, IV.Length);
            Array.Copy(cipherTextCombined, IV.Length, cipherText, 0, cipherText.Length);

            aesAlg.IV = IV;

            aesAlg.Mode = CipherMode.CBC;

            // Create a decrytor to perform the stream transform.
            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            // Create the streams used for decryption. 
            using (var msDecrypt = new MemoryStream(cipherText))
            {
                using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (var srDecrypt = new StreamReader(csDecrypt))
                    {

                        // Read the decrypted bytes from the decrypting stream
                        // and place them in a string.
                        plaintext = srDecrypt.ReadToEnd();
                    }
                }
            }

        }

        return plaintext;

    }
}//end class

