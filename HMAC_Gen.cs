/* 
 * This code is largerly derived from the microsoft documentation on rfc2898
 * https://docs.microsoft.com/en-us/dotnet/api/
 *           system.security.cryptography.HMACsha512?view=net-5.0
 * 
 * Notes About File
 * @File: HMAC_Gen.cs
 * @Name: Christian Dunham
 * @Number: 1978955
 * @Date: 12Apr2021
 * @Program Name:  encryption_utility
 *
 * Program Purpose:
 *    This program implements an encryption utility for a windows based system.  
 *    The HMAC_Gen creates the HMAC signature from the IV and encrypted data.
 *    Uses SHA512
 *******************************************************************************
 *******************************************************************************
 *                        Included Libraries
 *******************************************************************************
 *******************************************************************************
*/
using System;
using System.IO;
using System.Security.Cryptography; //For HMAC
public class HMAC_Gen
{
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
        }//end using
        return hashValue;
    } // end HMAC_Signature
}