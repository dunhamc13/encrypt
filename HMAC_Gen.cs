using System;
using System.IO;
using System.Security.Cryptography; //For rfc2898
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
        }
        return hashValue;
    } // end HMAC_Signature
}