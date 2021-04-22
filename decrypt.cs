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
            byte[] decrypted = new byte[160];


            // Create an Aes object 
            // with the specified key and IV. 
            using (Aes decAlg = Aes.Create())
            {
                KeyGen keyGen_Master = new KeyGen(pwd1, salt1, myIterations);
                decAlg.Key = keyGen_Master.MasterKey;
                byte[] HMAC_Key = keyGen_Master.HMACKey;
                byte[] enc_Key = keyGen_Master.EncryptionKey;
                decAlg.Padding = PaddingMode.PKCS7;

                byte[] IV = new byte[decAlg.BlockSize / 8];
                byte[] encryptedData = new byte[160];
                byte[] storedHMAC = new byte[64];
                byte[] combinedIVEncrypted = new byte[176];

                Array.Copy(dataStructure, dataStructure.Length - 176, IV, 0, IV.Length);
                Array.Copy(dataStructure, dataStructure.Length - 160, encryptedData, 0, encryptedData.Length);
                Array.Copy(dataStructure, dataStructure.Length - 176, combinedIVEncrypted, 0, combinedIVEncrypted.Length);
                Array.Copy(dataStructure,11, storedHMAC, 0, storedHMAC.Length);


                //verify signature
                verifyHMAC(HMAC_Key, storedHMAC, combinedIVEncrypted);
                decAlg.IV = IV;
                decAlg.Mode = CipherMode.CBC;
                Console.WriteLine("Stubbing output IV {0}", Convert.ToBase64String(IV));
                Console.WriteLine("Stubbing output encryptedData {0}", Convert.ToBase64String(encryptedData));

           
              
                using (var decryptor = decAlg.CreateDecryptor(enc_Key, decAlg.IV))
                {
                    using (MemoryStream ms = new MemoryStream(encryptedData))
                    {
                        //was  var rigth there and mode.Read
                        using (var cryptoStream = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {

                            //cryptoStream.Write(encryptedData, 0, encryptedData.Length);
                            //cryptoStream.Close();

                            cryptoStream.Read(decrypted, 0, decrypted.Length);
                            cryptoStream.Close();
                            
                            
                            //var bytesRead = cryptoStream.Read(decrypted, 0, encryptedData.Length);
                            //decrypted = decrypted.Take(bytesRead).ToArray();
                            //Console.WriteLine("Stubbing output dencryptedData {0}", Convert.ToBase64String(decrypted));

                        }
                        ms.Close();
                        //decrypted = ms.ToArray();
                        //Console.WriteLine("Stubbing output dencryptedData {0}", Convert.ToBase64String(decrypted));

                    }
                    //decrypted = use_crypto(encryptedData, decryptor);
                }
            }
            byte[] trimmed = new byte[146];
            Array.Copy(decrypted, 0, trimmed, 0, trimmed.Length);
            return trimmed;
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
