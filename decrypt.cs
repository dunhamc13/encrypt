/* 
 * This code is largerly derived from the microsoft documentation on rfc2898
 * https://docs.microsoft.com/en-us/dotnet/api/
 *           system.security.cryptography.aes?view=net-5.0
 * 
 * Notes About File
 * @File: decrypt.cs
 * @Name: Christian Dunham
 * @Number: 1978955
 * @Date: 12Apr2021
 * @Program Name:  encryption_utility
 *
 * Program Purpose:
 *    This program implements an encryption utility for a windows based system.  
 *    The decrypt class is responsible for decrypting enctrypted byte arrays.
 *    Additionally, it checks the HMAC signature
 *
 *******************************************************************************
 *******************************************************************************
 * Code Outline :        
 *                              : DecryptFromBytes :
 *                              : VerifyHMAC :
 ******************************************************************************* 
 *                        Included Libraries
 *******************************************************************************
 *******************************************************************************
*/
using System;
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
         * DecryptFromBytes(byte[] dataStructure, string pwd1, byte[] salt1, int myIterations)
         * Code here modified from: https://docs.microsoft.com/en-us/dotnet/api/
         *                              system.security.cryptography.aes?view=netframework-4.8
         * dataStructure : dataStruct : [metadata][hmac][iv][encrypted data]
         * pwd1 : the password from user
         * salt1 : random 8 bytes for master key
         * myIterations : num iterations from user
         * originalDataLength : data length before encryption to fix padding
         * output: []byte : trimmedDecrypted byte array  [ must trim due to padding ]
        */
        public static byte[] DecryptFromBytes(byte[] dataStructure, string pwd1, byte[] salt1, int myIterations, int originalDataLength, int metaDataLength, int encryptedDataLength, int IVLength, int macLength,int keySize, int hashAlgorithm)
        {

            // variables to return
            byte[] decrypted = new byte[encryptedDataLength];


            // Create an Aes object with the specified key and IV. 
            using (Aes decAlg = Aes.Create())
            {
                KeyGen keyGen_Master = new KeyGen(pwd1, salt1, myIterations, keySize, hashAlgorithm);
                decAlg.Key = keyGen_Master.MasterKey;
                byte[] HMAC_Key = keyGen_Master.HMACKey;
                byte[] enc_Key = keyGen_Master.EncryptionKey;
                decAlg.Padding = PaddingMode.PKCS7;

                // Create byte arrays to parse out data
                byte[] metaData = new byte[metaDataLength];
                byte[] IV = new byte[decAlg.BlockSize / 8];
                byte[] encryptedData = new byte[encryptedDataLength];
                byte[] storedHMAC = new byte[macLength];
                byte[] combinedIVEncrypted = new byte[encryptedDataLength + IVLength];

                // Copy data to arrays
                Array.Copy(dataStructure, 0, metaData, 0, metaData.Length);
                Array.Copy(dataStructure, dataStructure.Length - encryptedDataLength - IVLength, IV, 0, IV.Length);
                Array.Copy(dataStructure, dataStructure.Length - encryptedDataLength, encryptedData, 0, encryptedData.Length);
                Array.Copy(dataStructure, dataStructure.Length - encryptedDataLength - IVLength, combinedIVEncrypted, 0, combinedIVEncrypted.Length);
                Array.Copy(dataStructure, metaDataLength, storedHMAC, 0, storedHMAC.Length);

                //verify signature
                verifyHMAC(HMAC_Key, storedHMAC, combinedIVEncrypted);

                // STUB FOR GRADING AND VERIFICAITON TODO: DELETE
                //Console.WriteLine("\nMetadata is {0}", Encoding.UTF8.GetString(metaData));
                //Console.WriteLine("\nParsed Decrypt IV {0}", Convert.ToBase64String(IV));
                //Console.WriteLine("Stubbing output encryptedData {0}", Convert.ToBase64String(encryptedData));

                //Use Streams to encrypt  
                //TODO : moving cipher mode up causes decrypt difference.. find out why
                decAlg.IV = IV;
                decAlg.Mode = CipherMode.CBC;
                using (var decryptor = decAlg.CreateDecryptor(enc_Key, decAlg.IV))
                {
                    using (MemoryStream ms = new MemoryStream(encryptedData))
                    {
                        using (var cryptoStream = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            cryptoStream.Read(decrypted, 0, decrypted.Length);
                            cryptoStream.Close();
                        }//end cryptostream
                        ms.Close();
                    }//end memory stream
                }//end decryptor
            }//end aes decryption key
            //must trim due to padding
            byte[] trimmed = new byte[originalDataLength];
            Array.Copy(decrypted, 0, trimmed, 0, trimmed.Length);
            return trimmed;
        }//end decrpypt from bytes

        /*
         * verifyHMAC(byte[] key, byte[] storedHMAC, byte[] combinedData)
         * Code here modified from: https://docs.microsoft.com/en-us/dotnet/api/
         *                              system.security.cryptography.aes?view=netframework-4.8
         * key : the encryption key
         * storeHMAC : the parsed hmac from before to compare for hack
         * combinedData : IV and encrypted data
         * output: hacked : true or false
        */
        public static bool verifyHMAC(byte[] key, byte[] storedHMAC, byte[] combinedData)
        {
            bool hacked = false;
            // Initialize the keyed hash object.
            byte[] computedHash = HMAC_Gen.HMAC_Signature(key, combinedData);

            //loop through size of hash
            for (int i = 0; i < storedHMAC.Length; i++)
            {
                if (computedHash[i] != storedHMAC[i])
                {
                    hacked = true;
                }//end if hacked
            }//end loopp
            if (hacked)
            {
                Console.WriteLine("Hash values differ! Signed file has been tampered with!\n");
                return false;
            }//end if hacked
            //must not be hacked
            else
            {
                Console.WriteLine("Hash values agree -- no tampering occurred.\n");
                return true;
            }//end not hacked
        } //end VerifyFile
    }//end decrypt class
}//end namespace encrption utility
