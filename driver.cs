/* 
 * Notes About File
 * @File: driver.cs
 * @Name: Christian Dunham
 * @Number: 1978955
 * @Date: 12Apr2021
 * @Program Name:  encryption_utility
 *
 * Program Purpose:
 *    This program implements an encryption utility for a windows based system.
 *    This program is the driver.  
 *
 * Design Rational:  
 *    One decision was create separate classes for AES and 3DES to reduce code
 *    smells and make it more modular.
 *
 *******************************************************************************
 *******************************************************************************
 *
 *                        Special Cases Identified
 * : Picture files : 
 * : xlsx files    :
 *
 *******************************************************************************
 *
 *******************************************************************************
 *Product BackLog :
 *                 1) Picture files do not open (fixed)
 *                 2) 3DES implementation is not complete
 *                 3) 3DES is constrained to 192 bit key
 *                 4) Not sure if 3des is CBC????
 *                 5) xcel file do not open (fixed)
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

namespace encrypt_utility
{
    class driver
    {
        /* This driver does the following:
         1. Generate a master key || Km = KDF(password, iteration count, hashing alg, salt)
         2. Generate an encryption key || Ke = KDF(Km, iteration count = 1, hashing alg, “Encryption key”)
         3. Generate a HMAC key || Kh = KDF(Km, iteration count = 1, hashing alg, “HMAC key”)
         4. Generate a random IV(initialization vector)
         5. Encrypt your data with Ke and IV 
         6. Create an HMAC with Kh, covering both IV and encrypted data
       */
        private const string usageText = "Usage: RFC2898 [password] [key size(128,192,256)] [hash size(256, 512)] [iterations] [file to encrypt (in VS proj append ../../../file.ext)]\n";
        public static void Main(string[] args)
        {

            /* 
             * Implement timer for diagnostics
             * Code modified from https://docs.microsoft.com/en-us/dotnet/
             *         api/system.diagnostics.stopwatch.elapsed?view=net-5.0
            */
            Stopwatch stopWatch = new Stopwatch();
            stopWatch.Start();

            // Declare variables needed for data file to encrypt and output enctrypted file
            string dataFile;                       //file to encrypt
            string signedFile;                    //file location that is encrypted
            int keySize = 0;                      //for key algorithm size aes128, aes256, or 3des64
            int hash_algorithm = 0;               //for encryption hash sha256 or sha512
            byte[] encrypted_DataToDecrypt = null;  
            string pwd1 = null;                   //password
            byte[] salt1 = null;                  //salt for master
            int myIterations = 0;                 // master iterations
            int originalDataLength = 0;           //original data length
            int metaDataLength = 0;               //metadata data length
            int encryptedDataLength = 0;          //encrypted data length
            int IVLength = 0;                     //iv length
            int macLength = 0;                    //mac length


            //First get arguments for password encyrption algorithm, iterations, and file to encrypt
            //If 4 arguments are not present, write usage text.
            if (args.Length != 5)
            {
                Console.WriteLine(usageText);
            }//end if not 4 args

            //has 4 args, can continue
            else
            {
                //create vars for functions that create keys
                pwd1 = args[0];                       //password for master key
                keySize = Convert.ToInt32(args[1]);   // key size implies aes128, aes256, or 3des64
                hash_algorithm = Convert.ToInt32(args[2]);             //int 256 or 512 for sha256 and sha512 
                myIterations = Convert.ToInt32(args[3]); //number of iterations for master key
                dataFile = args[4];

                /* !USAGE
                 * file to output encrypted data
                 * if using VS this will place the enctrypted files in the main repo folder
                 * else change path to desired location
                */
                signedFile = @"" + dataFile + ".enc";


                // Application opening statement
                Console.WriteLine("+++++++++++++++++++++++++++++++++++++++++++");
                Console.WriteLine("+++++++++++ Encryption Utility ++++++++++++");
                Console.WriteLine("Opening File to Encrypt and Reading:");

                //Check if file exists to enctrypt, else exit
                if (File.Exists(dataFile))
                {
                    Console.WriteLine("The file exists.\n");
                }//end if file exists

                //file must not exist
                else
                {
                    Console.WriteLine("No file to encrypt, exiting\n Check if in VS proj to append ../../../file.ext to file.ext");
                    System.Environment.Exit(1);
                }//end if file doesn't exist

                //Create a byte array to hold the random value for master key salt - must be 8 bytes
                salt1 = new byte[8];

                //Use CryptoService to generate random bytes for salt
                using (RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider())
                {
                    // Fill the array with a random value.
                    rngCsp.GetBytes(salt1);
                }//end random salt creation

                //All conditions are set to begin attempt to encrypt data
                try
                {
                    if (keySize == 192)
                    {
                        byte[] dataToEncrypt = FileToByteArray(dataFile);
                        originalDataLength = dataToEncrypt.Length;
                        _3des.Apply3DES(dataToEncrypt, originalDataLength);
                        System.Environment.Exit(1);
                    }
                    else
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
                         *       system.security.cryptography.hashalgorithmname?view=net-5.0
                         *       For more information
                         * output: masteryKey_Bytes: a master key from arguments to create other keys
                        */
                        // Application key generation statement
                        Console.WriteLine("+++++++++++++++++++++++++++++++++++++++++++");
                    Console.WriteLine("++++++++++++ Generating Keys ++++++++++++++");
                    Console.WriteLine("Creating Master Key:");
                    KeyGen keyGen_Master = new KeyGen(pwd1, salt1, myIterations, keySize, hash_algorithm);
                    byte[] masterKey_Bytes = keyGen_Master.MasterKey;

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
                    Console.WriteLine("Creating Encryption Key:");
                    byte[] encryptionKey_Bytes = keyGen_Master.EncryptionKey;

                    //HMAC Key Creation
                    Console.WriteLine("Creating HMAC Key:\n");
                    byte[] HMACKey_Bytes = keyGen_Master.HMACKey;

                    /*
                     * 3. Encrypt data using CBC chaining mode
                     * Must work with 3DES, AES128, AES256
                     * Use random IV that is one block size
                     * Do not assume block size
                     * output: enctrypted : byte[] [metadata][hmac][iv][enctrypted data]
                     */
                    Console.WriteLine("+++++++++++++++++++++++++++++++++++++++++++");
                    Console.WriteLine("+++++++++ Encryption Processing +++++++++++");
                    Console.WriteLine("Initiating Enctryption:");
                    string EncAlg;
                    string kSize = keySize.ToString();
                    if (keySize == 192)
                        EncAlg = "3DES" + kSize;
                    else if (keySize == 128)
                        EncAlg = "AES" + kSize;
                    else EncAlg = "AES" + kSize;
                         
                    string metaData_string = EncAlg + "+" + hash_algorithm + "+" + myIterations;
                    byte[] metaData = Encoding.ASCII.GetBytes(metaData_string);
                    byte[] dataToEncrypt = FileToByteArray(dataFile);
                    originalDataLength = dataToEncrypt.Length;
                    //byte[] dataToEncrypt = System.IO.File.ReadAllBytes(dataFile);
                    //Console.WriteLine("Original Input (b-64 encode): {0} ", Convert.ToBase64String(dataToEncrypt));

                        Encryption_Util encrypted_Obj = new Encryption_Util(dataToEncrypt, encryptionKey_Bytes, metaData, HMACKey_Bytes, signedFile);
                        metaDataLength = encrypted_Obj.metaDataLength;
                        encryptedDataLength = encrypted_Obj.encryptedDataLength;
                        IVLength = encrypted_Obj.IVLength;
                        byte[] encrypted = encrypted_Obj.encryptedData;
                        encrypted_DataToDecrypt = encrypted;
                        // Encryption Complete Statement
                        Console.WriteLine("++++++++++ Encryption Complete ++++++++++++");
                        //Console.WriteLine("Encrypted Data Structure (b64-encode): {0}", Convert.ToBase64String(encrypted_DataToDecrypt));

                    }

                }//end try to encrypt

                //must have had an error
                catch (Exception e)
                {
                    Console.WriteLine("Error: {0}", e);
                }//end catch
            }//end had all 4 args

            // Timing Statement
            Console.WriteLine("\n+++++++++++++++++++++++++++++++++++++++++++");
            Console.WriteLine("++++++++++++ Calculating Time +++++++++++++");
            stopWatch.Stop();
            TimeSpan ts = stopWatch.Elapsed;
            string elapsedTime = String.Format("{0:00}:{1:00}:{2:00}.{3:00}",
                  ts.Hours, ts.Minutes, ts.Seconds, ts.Milliseconds);
            Console.WriteLine("RunTime " + stopWatch.Elapsed);

            // Decrypt
            Console.WriteLine("\n+++++++++++++++++++++++++++++++++++++++++++");
            Console.WriteLine("+++++++++++++++ Decryption ++++++++++++++++");
            Console.WriteLine("Sending encrypted data structure to parse..");
            Console.WriteLine("parsing structure...  Check for tampering..");
            byte[] dectrypted = decrypt.DecryptFromBytes(encrypted_DataToDecrypt, pwd1, salt1, myIterations, originalDataLength, metaDataLength, encryptedDataLength, IVLength, macLength, keySize, hash_algorithm);
            Console.WriteLine("+++++++++++++++++++++++++++++++++++++++++++");
            Console.WriteLine("+++++++++++ Decryption Complete +++++++++++");
            //Console.WriteLine("Decrypted Bytes (b64-encode): {0}",Convert.ToBase64String(dectrypted));
        }//end main

        public static byte[] FileToByteArray(string fileName)
        {
            byte[] fileData = null;

            using (FileStream fs = File.OpenRead(fileName))
            {
                using (BinaryReader binaryReader = new BinaryReader(fs))
                {
                    fileData = binaryReader.ReadBytes((int)fs.Length);
                }
            }
            return fileData;
        }
    }
}
