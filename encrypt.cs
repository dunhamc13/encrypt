
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
        byte[] encrypted = new byte[dataToEncrypt.Length];
        byte[] IV;
        Console.WriteLine("Stubbing original input {0} length {1}", Convert.ToBase64String(dataToEncrypt), dataToEncrypt.Length);
        //Use AES to create encryption
        using (Aes aes_enc = Aes.Create())
        {
            aes_enc.Mode = CipherMode.CBC;           //for CBC mode
            aes_enc.Key = encryptedKey;
            aes_enc.Padding = PaddingMode.PKCS7;
            aes_enc.GenerateIV();                    //for random IV
            IV = aes_enc.IV;
            Console.WriteLine("Stubbing input IV {0}", Convert.ToBase64String(IV));
            aes_enc.Mode = CipherMode.CBC;           //for CBC mode
            var encryptor = aes_enc.CreateEncryptor(aes_enc.Key, aes_enc.IV);
            //use memory stream to encrypt data
            using (var msEncrypt = new MemoryStream())
            {
                using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    csEncrypt.Write(dataToEncrypt, 0, dataToEncrypt.Length);
                    csEncrypt.Close();
                    /*
                    using (var swEncrypt = new StreamWriter(csEncrypt))
                    {
                        //Write all data to the stream.
                        swEncrypt.Write(dataToEncrypt);
                    }//end write stream
                    
                    encrypted = msEncrypt.ToArray();
                    */
                }//end cryptostream

                encrypted = msEncrypt.ToArray();
            }//end memory stream
        }//end aes encrypt

        //Combine IV and encrypted bytes to compute hash
        var combinedIvEncrypted = new byte[IV.Length + encrypted.Length];
        Array.Copy(IV, 0, combinedIvEncrypted, 0, IV.Length);
        Array.Copy(encrypted, 0, combinedIvEncrypted, IV.Length, encrypted.Length);
        byte[] mac = HMAC_Gen.HMAC_Signature(HMAC_key, combinedIvEncrypted);
        Console.WriteLine("Stub Mac initial: {0}", Convert.ToBase64String(mac));
        Console.WriteLine("Stubbing output encryptedData {0}", Convert.ToBase64String(encrypted));

        /*
          * 4. Create HMAC of the IV and encrypted data
        */
        var dataStruct = new byte[metaData.Length + mac.Length + IV.Length + encrypted.Length];
        Array.Copy(metaData, 0, dataStruct, 0, metaData.Length);
        Array.Copy(mac, 0, dataStruct, metaData.Length, mac.Length);
        Array.Copy(IV, 0, dataStruct, metaData.Length + mac.Length, IV.Length);
        Array.Copy(encrypted, 0, dataStruct, metaData.Length + mac.Length + IV.Length, encrypted.Length);
        Console.WriteLine("metadata length {0} HMAC length {1} IV length {2} Encrytped length {3}", metaData.Length, mac.Length, IV.Length, encrypted.Length);

        //Write encrypted structure to file
        File.WriteAllBytes(signedFile, dataStruct);

        // Return the encrypted bytes from the memory stream. 
        return dataStruct;
    }//end encrypt



}//end class

