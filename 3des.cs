/* 
 * This code is largerly derived from the microsoft documentation on rfc2898
 * https://docs.microsoft.com/en-us/dotnet/api/
 *           system.security.cryptography.tripledes?view=net-5.0
 *           
 *           3des was a rush implementation, strongly using source code from:
 *           https://www.c-sharpcorner.com/article/tripledes-encryption-in-c-sharp/
 * 
 * Notes About File
 * @File: 3des.cs
 * @Name: Christian Dunham
 * @Number: 1978955
 * @Date: 12Apr2021
 * @Program Name:  encryption_utility
 *
 * Program Purpose:
 *    This program implements an encryption utility for a windows based system.  
 *    The 3des supports deprecated 3des encryption.
 *
 * Design Rational:  
 *    One decision was to make this an object that could store all 3 keys
 *    to make ease of retrieval for decryption.
 *
 * Dynamic Memory:
 *    Use of higher level language omitted memory maintainance
 *
 *******************************************************************************
 *******************************************************************************
 *                        Special Cases Identified
 * : ??? : 
 *******************************************************************************
 *******************************************************************************
 *Product BackLog :
 *                 1) Make this my own work
 *                 2) I don't think this qualifies as CBC mode
 *
 *******************************************************************************
 *******************************************************************************
 * Code Outline :        
 *                              : attributes :
 *                              : initializer :
 *                              : getMasterKey :
 *                              : getDerivedKey :
 ******************************************************************************* 
 *                        Included Libraries
 *******************************************************************************
 *******************************************************************************
*/
using System;
using System.Collections.Generic;
using System.IO;  //Console.WriteLine
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography; //For rfc2898

namespace encrypt_utility
{
    public static class _3des
    {
        public static void Apply3DES(byte[] raw, int originalDataLength)
        {
            try
            {
                // Create 3DES that generates a new key and initialization vector (IV).  
                // Same key must be used in encryption and decryption  
                using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
                {
                    // Encrypt string  
                    byte[] encrypted = Encrypt(raw, tdes.Key, tdes.IV);
                    // Print encrypted string  
                    Console.WriteLine("Encrypted data: {0}", Convert.ToBase64String(encrypted));
                    // Decrypt the bytes to a string.  
                    byte[] decrypted = Decrypt(encrypted, tdes.Key, tdes.IV, originalDataLength);
                    // Print decrypted string. It should be same as raw data  
                    Console.WriteLine("Decrypted data: {0}", Convert.ToBase64String(decrypted));
                }
            }
            catch (Exception exp)
            {
                Console.WriteLine(exp.Message);
            }
        }
        public static byte[] Encrypt(byte[] dataToEncrypt, byte[] Key, byte[] IV)
        {


            byte[] encrypted;
            // Create a new TripleDESCryptoServiceProvider.  
            using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
            {
                // Create encryptor  
                ICryptoTransform encryptor = tdes.CreateEncryptor(Key, IV);
                // Create MemoryStream  
                using (var ms = new MemoryStream())
                {
                    // Create crypto stream using the CryptoStream class. This class is the key to encryption  
                    // and encrypts and decrypts data from any given stream. In this case, we will pass a memory stream  
                    // to encrypt  
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        cs.Write(dataToEncrypt, 0, dataToEncrypt.Length);
                        cs.Close();
                        
                    }
                    encrypted = ms.ToArray();
                }
            }
            // Return encrypted data  
            return encrypted;
        }
        public static byte[] Decrypt(byte[] cipherText, byte[] Key, byte[] IV, int originalDataLength)
        {
            byte[] decrypted = new byte[cipherText.Length];
            // Create TripleDESCryptoServiceProvider  
            using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
            {
                // Create a decryptor  
                ICryptoTransform decryptor = tdes.CreateDecryptor(Key, IV);
                // Create the streams used for decryption.  
                using (MemoryStream ms = new MemoryStream(cipherText))
                {
                    // Create crypto stream  
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        cs.Read(decrypted, 0, decrypted.Length);
                        cs.Close();
                    }
                }
            }
            byte[] trimmed = new byte[originalDataLength];
            Array.Copy(decrypted, 0, trimmed, 0, trimmed.Length);
            return trimmed;
        }
    }
}
