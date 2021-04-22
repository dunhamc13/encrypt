/* 
 * This code is largerly derived from the microsoft documentation on rfc2898
 * https://docs.microsoft.com/en-us/dotnet/api/
 *           system.security.cryptography.rfc2898derivebytes?view=net-5.0
 * 
 * Notes About File
 * @File: driver.cs
 * @Name: Christian Dunham
 * @Number: 1978955
 * @Date: 12Apr2021
 * @Program Name:  encryption_utility
 *
 * Program Purpose:
 *    This program implements an encryption utility for a windows based system
 *
 * Design Rational:  
 *    One decision was xyz.... because....  
 *
 * Dynamic Memory:
 *    Use of higher level language omitted memory maintainance
 *
 *******************************************************************************
 *******************************************************************************
 *
 *                        Special Cases Identified
 * : Jpg : 
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

namespace encrypt_utility
{
    class driver
    {
        /*
         1. Generate a master key || Km = KDF(password, iteration count, hashing alg, salt)
         2. Generate an encryption key || Ke = KDF(Km, iteration count = 1, hashing alg, “Encryption key”)
         3. Generate a HMAC key || Kh = KDF(Km, iteration count = 1, hashing alg, “HMAC key”)
         4. Generate a random IV(initialization vector)
         5. Encrypt your data with Ke and IV 
         6. Create an HMAC with Kh, covering both IV and encrypted data
       */
        private const string usageText = "Usage: RFC2898 [password] [algorithm] [iterations] [file to encrypt]\n";
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
            string dataFile;
            string signedFile;
            string hash_algorithm = null;
            byte[] encrypted_DataToDecrypt = null;
            string pwd1 = null;
            byte[] salt1 = null;
            int myIterations = 0;


            //First get arguments for password encyrption algorithm, iterations, and file to encrypt
            //If 4 arguments are not present, write usage text.
            if (args.Length != 4)
            {
                Console.WriteLine(usageText);
            }//end if not 4 args

            //has 4 args, can continue
            else
            {
                //create vars for functions that create keys
                pwd1 = args[0];                       //password for master key
                hash_algorithm = args[1];             //hash algorithm to use
                myIterations = Convert.ToInt32(args[2]); //number of iterations for master key
                dataFile = args[3];

                /* !USAGE
                 * file to output encrypted data
                 * if using VS this will place the enctrypted files in the main repo folder
                 * else change path to desired location
                */
                signedFile = @"..\..\..\" + dataFile + ".enc";


                // Application opening statement
                Console.WriteLine("+++++++++++++++++++++++++++++++++++++++++++");
                Console.WriteLine("+++++++++++ Encryption Utility ++++++++++++");
                Console.WriteLine("Opening File to Encrypt and Reading:");

                // Check if file exists to enctrypt, else exit
                if (File.Exists(dataFile))
                {
                    Console.WriteLine("The file exists.\n\n");
                }//end if file exists

                //file must not exist
                else
                {
                    Console.WriteLine("No file to encrypt, exiting\n\n");
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
                    KeyGen keyGen_Master = new KeyGen(pwd1, salt1, myIterations);
                    byte[] masterKey_Bytes = keyGen_Master.MasterKey;
                    /*
                    Rfc2898DeriveBytes masterKey_Obj = new Rfc2898DeriveBytes
                        (pwd1, salt1, myIterations, HashAlgorithmName.SHA256);
                    byte[] masterKey_Bytes = masterKey_Obj.GetBytes(32);
                    */
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
                    string metaData_string = hash_algorithm + "+" + myIterations;
                    byte[] metaData = Encoding.ASCII.GetBytes(metaData_string);
                    byte[] dataToEncrypt = FileToByteArray(dataFile);
                    //byte[] dataToEncrypt = System.IO.File.ReadAllBytes(dataFile);
                    Console.WriteLine("Original Input (b-64 encode): {0} ", Convert.ToBase64String(dataToEncrypt));
                    byte[] encrypted = rfc2898key.encrypt(dataToEncrypt, encryptionKey_Bytes, metaData, HMACKey_Bytes, signedFile);
                    encrypted_DataToDecrypt = encrypted;
                    // Encryption Complete Statement
                    Console.WriteLine("\n++++++++++ Encryption Complete ++++++++++++");
                    Console.WriteLine("Encrypted Data Structure (b64-encode): {0}", Convert.ToBase64String(encrypted_DataToDecrypt));
                }//end try to encrypt

                //must have had an error
                catch (Exception e)
                {
                    Console.WriteLine("Error: {0}", e);
                }//end catch
            }//end had all 4 args

            // Timing Statement
            Console.WriteLine("\n\n+++++++++++++++++++++++++++++++++++++++++++");
            Console.WriteLine("++++++++++++ Calculating Time +++++++++++++");
            stopWatch.Stop();
            TimeSpan ts = stopWatch.Elapsed;
            string elapsedTime = String.Format("{0:00}:{1:00}:{2:00}.{3:00}",
                  ts.Hours, ts.Minutes, ts.Seconds, ts.Milliseconds);
            Console.WriteLine("RunTime " + stopWatch.Elapsed);

            // Decrypt
            Console.WriteLine("\n\n+++++++++++++++++++++++++++++++++++++++++++");
            Console.WriteLine("++++++++++++ Decryption +++++++++++++");
            byte[] dectrypted = decrypt.DecryptFromBytes(encrypted_DataToDecrypt, pwd1, salt1, myIterations);

            Console.WriteLine("Decrypted Bytes (b64-encode): {0}",Convert.ToBase64String(dectrypted));
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
