/* 
 * This code is largerly derived from the microsoft documentation on AES
 * https://docs.microsoft.com/en-us/dotnet/api/
 *           system.security.cryptography.aes?view=net-5.0
 * 
 * Notes About File
 * @File: Encrypt_Util.cs
 * @Name: Christian Dunham
 * @Number: 1978955
 * @Date: 12Apr2021
 * @Program Name:  encryption_utility
 *
 * Program Purpose:
 *    This program implements an encryption utility for a windows based system.  
 *    The Encryption_Util Class conducts the enctryption of byte arrays.
 *
 * Design Rational:  
 *    One decision was to push this class by it self in order to increase 
 *    modularaiztation.
 *
 * Dynamic Memory:
 *    Use of higher level language omitted memory maintainance
 *
 *******************************************************************************
 *******************************************************************************
 *                        Special Cases Identified
 * : Jpg : Will it work? Need test
 *******************************************************************************
 *******************************************************************************
 *Product BackLog :
 *                 1) implement additional algorithms
 *
 *******************************************************************************
 *******************************************************************************
 * Code Outline :        
 *                              : encrypt  : 
 ******************************************************************************* 
 *                        Included Libraries
 *******************************************************************************
 *******************************************************************************
*/
using System;
using System.IO;  //Console.WriteLine
using System.Text;
using System.Security.Cryptography; //For rfc2898
using System.Diagnostics; //For timer



public class Encryption_Util
{
    public int metaDataLength;
    public int encryptedDataLength;
    public int IVLength;
    public int hmacLength;
    public byte[] encryptedData;
    public Encryption_Util(byte[] dataToEncrypt, byte[] encryptedKey, byte[] metaData, byte[] HMAC_key, string signedFile)
    {
        encryptedData = encrypt(dataToEncrypt, encryptedKey, metaData, HMAC_key, signedFile);
    }
    /*
     * encrypt(byte[] dataToEncrypt, byte[] key, byte[] metaData, byte[] hmac_key, string signedFile)
     * Code here modified from: https://docs.microsoft.com/en-us/dotnet/api/
     *                              system.security.cryptography.aes?view=netframework-4.8
     * key : the encryption key
     * metadata : holds information about algorithm and iterations for decryption
     * hmac_key : hmac key for creating a mac signature
     * signedFile : location of the encrypted file at endstate
     * output: []byte : dataStruct : [metadata][hmac][iv][encrypted data]
    */
    public byte[] encrypt(byte[] dataToEncrypt, byte[] encryptedKey, byte[] metaData, byte[] HMAC_key, string signedFile) 
    {
        //varaibles for enctrypted data and iv
        byte[] encrypted = new byte[dataToEncrypt.Length];
        byte[] IV;
   
        //Use AES to create encryption
        using (Aes aes_enc = Aes.Create())
        {
            aes_enc.Mode = CipherMode.CBC;           //for CBC mode
            if (encryptedKey.Length == 8)
                aes_enc.BlockSize = 64;
            aes_enc.BlockSize = 128;
            aes_enc.Key = encryptedKey;
            aes_enc.Padding = PaddingMode.PKCS7;
            aes_enc.GenerateIV();                    //for random IV  
            IV = aes_enc.IV;

            //STUB LINE : FOR VERIFICATION AND GRADING ONLY TODO: DELETE
            //Console.WriteLine("Original input IV {0}", Convert.ToBase64String(IV));

            //use memory stream / crypto stream to encrypt data
            var encryptor = aes_enc.CreateEncryptor(aes_enc.Key, aes_enc.IV);
            using (var msEncrypt = new MemoryStream())
            {
                using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    csEncrypt.Write(dataToEncrypt, 0, dataToEncrypt.Length);
                    csEncrypt.Close();
                }//end cryptostream
                encrypted = msEncrypt.ToArray();
            }//end memory stream
        }//end aes encrypt

        //Combine IV and encrypted bytes to compute hash
        var combinedIvEncrypted = new byte[IV.Length + encrypted.Length];
        Array.Copy(IV, 0, combinedIvEncrypted, 0, IV.Length);
        Array.Copy(encrypted, 0, combinedIvEncrypted, IV.Length, encrypted.Length);

        //get the HMAC of the IV and encrypted data
        byte[] mac = HMAC_Gen.HMAC_Signature(HMAC_key, combinedIvEncrypted);
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
       // Console.WriteLine("Encrypted Structure Created:\nMetadata length {0} HMAC length {1} IV length {2} Encrytped Data length {3}\nEncrypted File with .enc located in root folder.", metaData.Length, mac.Length, IV.Length, encrypted.Length);

        //Write encrypted structure to file
        File.WriteAllBytes(signedFile, dataStruct);

        // Return the encrypted bytes from the memory stream. 
        return dataStruct;
    }//end encrypt
}//end class

