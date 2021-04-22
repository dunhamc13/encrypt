﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography; //For rfc2898
using System.IO;

namespace encrypt_utility
{
    class decrypt
    {

        /*
         * decrypt(byte[] dataToEncrypt, string passwrod)
         * Code here modified from: https://docs.microsoft.com/en-us/dotnet/api/
         *                              system.security.cryptography.aes?view=netframework-4.8
         * output: []byte : dataStruct : [metadata][hmac][iv][encrypted data]
    */
        public static byte[] DecryptFromBytes(byte[] dataStructure, string pwd1, byte[] salt1, int myIterations)
        {

            // Declare the string used to hold 
            // the decrypted text. 
            //string plaintext = null;
            byte[] decrypted;

            // Create an Aes object 
            // with the specified key and IV. 
            using (Aes aesAlg = Aes.Create())
            {
                KeyGen keyGen_Master = new KeyGen(pwd1, salt1, myIterations);
                aesAlg.Key = keyGen_Master.MasterKey;
                byte[] HMAC_Key = keyGen_Master.HMACKey;
                aesAlg.Padding = PaddingMode.Zeros;

                byte[] IV = new byte[aesAlg.BlockSize / 8];
                byte[] encryptedData = new byte[dataStructure.Length - IV.Length - 11 - 64];
                byte[] storedHMAC = new byte[64];
                byte[] combinedIVEncrypted = new byte[32];

                Array.Copy(dataStructure, dataStructure.Length - 32, IV, 0, IV.Length);
                Array.Copy(dataStructure, dataStructure.Length - 16, encryptedData, 0, encryptedData.Length);
                Array.Copy(dataStructure, dataStructure.Length - 32, combinedIVEncrypted, 0, combinedIVEncrypted.Length);
                Array.Copy(dataStructure,11, storedHMAC, 0, storedHMAC.Length);

                //verify signature
                verifyHMAC(HMAC_Key, storedHMAC, combinedIVEncrypted);
                aesAlg.IV = IV;
                aesAlg.Mode = CipherMode.CBC;

                using (var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV))
                {
                    decrypted = use_crypto(encryptedData, decryptor);
                }
            }
            return decrypted;
        }

        public static byte[] use_crypto(byte[] encryptedData, ICryptoTransform cryptoTransform)
        {
            using (var memStream = new MemoryStream())
            using (var cryptoStream = new CryptoStream(memStream, cryptoTransform, CryptoStreamMode.Write))
            {
                cryptoStream.Write(encryptedData, 0, encryptedData.Length);
                cryptoStream.FlushFinalBlock();

                return memStream.ToArray();
            }
        }

        // compare the data has not been tampered with.
        public static bool verifyHMAC(byte[] key, byte[] storedHMAC, byte[] combinedData)
        {
            bool hacked = false;
            // Initialize the keyed hash object.
            byte[] computedHash = HMAC_Gen.HMAC_Signature(key, combinedData);
            Console.WriteLine("Stub 2.a verify check storedHMAC {0}", Convert.ToBase64String(storedHMAC));
            Console.WriteLine("Stub 2.b verify check computedHa {0}", Convert.ToBase64String(computedHash));

            Console.WriteLine("Stored Length {0} computed length {1}", storedHMAC.Length, computedHash.Length);

            for (int i = 0; i < storedHMAC.Length; i++)
            {
                if (computedHash[i] != storedHMAC[i])
                {
                    hacked = true;
                }
            }
            if (hacked)
            {
                Console.WriteLine("Hash values differ! Signed file has been tampered with!");
                return false;
            }
            else
            {
                Console.WriteLine("Hash values agree -- no tampering occurred.");
                return true;
            }
        } //end VerifyFile
    }
}
