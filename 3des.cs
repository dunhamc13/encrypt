/* 
 * This code is largerly derived from the microsoft documentation on rfc2898
 * https://docs.microsoft.com/en-us/dotnet/api/
 *           system.security.cryptography.tripledes?view=net-5.0
 *           
 *           Second source code for inspiration in design from:
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
 *******************************************************************************
 *******************************************************************************
 *                        Special Cases Identified
 * : ??? : 
 *******************************************************************************
 *******************************************************************************
 *Product BackLog :
 *                 1) Fixed
 *                 2) I don't think this qualifies as CBC mode
 *
 *******************************************************************************
 *******************************************************************************
 * Code Outline :        
 *                              : UPdate this :
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



public class _3des 
{ 
    public int metaDataLength;
    public int encryptedDataLength;
    public int IVLength;
    public int hmacLength;
    public byte[] encryptedData;
    public _3des(byte[] dataToEncrypt, int originalDataLength, string pwd1, byte[] masterKey, byte[] encryptedKey, byte[] metaData, byte[] HMAC_key, string signedFile, byte[] salt1, int myIterations, int macLength, int keySize, int hashAlgorithm)
    {
        alg3DES(dataToEncrypt, originalDataLength, pwd1, masterKey, encryptedKey, metaData, HMAC_key, signedFile, salt1, myIterations, macLength, keySize, hashAlgorithm);
        //encryptedData = Encrypt(dataToEncrypt, encryptedKey, IV, metaData, originalDataLength, HMAC_key, signedFile);
    }

    /*
        * alg3DES(byte[] raw, int originalDataLength)
        * Code here modified from: https://www.c-sharpcorner.com/article/tripledes-encryption-in-c-sharp/
        * dataToEncrypt : the raw data
        * originalDataLength : holds the orignal data length for trimming later
        * output: to console displays orininal encryption and decryption
    */
    public void alg3DES(byte[] dataToEncrypt, int originalDataLength, string pwd1, byte[] masterKey, byte[] encryptedKey, byte[] metaData, byte[] HMAC_Key, string signedFile, byte[] salt1, int myIterations, int macLength, int keySize, int hashAlgorithm)
    {
        try
        {
            // Create 3DES instance from deprecated class  
            using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
            {
                tdes.Key = encryptedKey;
                tdes.GenerateIV();
                byte[] IV = tdes.IV;
                tdes.Mode = CipherMode.CBC;

                //Create encrypted byte array
                byte[] encrypted = Encrypt(dataToEncrypt, tdes.Key, tdes.IV, metaData, originalDataLength, HMAC_Key, signedFile);
                //Console.WriteLine("Encrypted data: {0}", Convert.ToBase64String(encrypted));

                // Decrypt the encrypted data.  
                byte[] decrypted = Decrypt(encrypted, pwd1, salt1, myIterations, originalDataLength, metaDataLength, encryptedDataLength, IVLength, macLength, keySize, hashAlgorithm);
                //Console.WriteLine("Decrypted data: {0}", Convert.ToBase64String(decrypted));
            }//end 3DES instance
        }//end try

        //must have had an error
        catch (Exception exp)
        {
            Console.WriteLine(exp.Message);
        }//end catch
    }//end alg3DES

    /*
        * Encrypt(byte[] dataToEncrypt, byte[] Key, byte[] IV)
        * Code here modified from: https://www.c-sharpcorner.com/article/tripledes-encryption-in-c-sharp/
        * dataToEncrypt : the raw data
        * Key : a 192 bit key or 24 bytes
        * IV : a 16byte initialization vector
        * output: encrypted byte array
    */
    public byte[] Encrypt(byte[] dataToEncrypt, byte[] Key, byte[] IV,byte[] metaData, int originalDataLength, byte[] HMAC_key, string signedFile)
    {

        //byte array to hold data
        byte[] encrypted;

        // Create 3DES instance
        using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
        {
            // Create encryptor, use memorystream and crypto stream to write data to encrypted
            ICryptoTransform encryptor = tdes.CreateEncryptor(Key, IV); 
            using (var ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    cs.Write(dataToEncrypt, 0, dataToEncrypt.Length);
                    cs.Close();   
                }//end crypto stream
                encrypted = ms.ToArray();
            }//end memory stream
        }//end 3DES instance 

            //get the HMAC of the IV and encrypted data
        byte[] mac = HMAC_Gen.HMAC_Signature(HMAC_key, encrypted);
        this.hmacLength = mac.Length;
        //TODO: STUB 
        //Console.WriteLine("Original output encryptedData {0}", Convert.ToBase64String(encrypted));

        // Create data structure to hold metadata hmac iv and encrypted data
        var dataStruct = new byte[metaData.Length + mac.Length + IV.Length + encrypted.Length];
        Array.Copy(metaData, 0, dataStruct, 0, metaData.Length);
        Array.Copy(mac, 0, dataStruct, metaData.Length, mac.Length);
        Array.Copy(IV, 0, dataStruct, metaData.Length + mac.Length, IV.Length);
        Array.Copy(encrypted, 0, dataStruct, metaData.Length + mac.Length + IV.Length, encrypted.Length);
        this.metaDataLength = metaData.Length;
        this.encryptedDataLength = encrypted.Length;
        this.IVLength = IV.Length;
        //TODO: STUB
        //Console.WriteLine("Encrypted Structure Created:\nMetadata length {0} HMAC length {1} IV length {2} Encrytped Data length {3}\nEncrypted File with .enc located in root folder.", metaData.Length, mac.Length, IV.Length, encrypted.Length);
        //Write encrypted structure to file
        File.WriteAllBytes(signedFile, dataStruct);

        // Encryption Complete Statement
        Console.WriteLine("++++++++++ Encryption Complete ++++++++++++");
        return dataStruct;
    }//end encrypt

    /*
        * Decrypt(byte[] cipherText, byte[] Key, byte[] IV, int originalDataLength)
        * Code here modified from: https://www.c-sharpcorner.com/article/tripledes-encryption-in-c-sharp/
        * encrytped : the encrytped data
        * Key : the 192 bit key or 24 bytes
        * IV : the 16byte initialization vector
        * orignalDataLength : needed to trim final decrypt of padding
        * output: decrypted byte array
    */
    public byte[] Decrypt(byte[] dataStructure, string pwd1, byte[] salt1, int myIterations, int originalDataLength, int metaDataLength, int encryptedDataLength, int IVLength, int macLength, int keySize, int hashAlgorithm)
    {
        // Decrypt
        Console.WriteLine("\n+++++++++++++++++++++++++++++++++++++++++++");
        Console.WriteLine("+++++++++++++++ Decryption ++++++++++++++++");
        Console.WriteLine("Sending encrypted data structure to parse..");
        Console.WriteLine("parsing structure...  Check for tampering..");
        //byte array to hold data
        byte[] decrypted = new byte[encryptedDataLength];

        KeyGen keyGen_Master = new KeyGen(pwd1, salt1, myIterations, keySize, hashAlgorithm);


        // Create 3DES instance, use decryptor, memorystream, and cryptostream to write data
        using (TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider())
        {
            tdes.Key = keyGen_Master.MasterKey;
            tdes.Mode = CipherMode.CBC;
            byte[] HMAC_Key = keyGen_Master.HMACKey;
            byte[] enc_Key = keyGen_Master.EncryptionKey;

            // Create byte arrays to parse out data
            byte[] metaData = new byte[metaDataLength];
            byte[] IV = new byte[IVLength];
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

            ICryptoTransform decryptor = tdes.CreateDecryptor(enc_Key, IV);
            using (MemoryStream ms = new MemoryStream(dataStructure))
            {
                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                {
                    cs.Read(decrypted, 0, decrypted.Length);
                    cs.Close();
                }//end cryptostream
            }//end memorystream
        }//end 3des instance

        //trim padded bytes
        byte[] trimmed = new byte[originalDataLength];
        //Array.Copy(decrypted, 0, trimmed, 0, trimmed.Length);
        Console.WriteLine("+++++++++++++++++++++++++++++++++++++++++++");
        Console.WriteLine("+++++++++++ Decryption Complete +++++++++++");
        return trimmed;
    }//end decrypt

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
}//end 3des class
