/* 
 * This code is largerly derived from the microsoft documentation on rfc2898
 * https://docs.microsoft.com/en-us/dotnet/api/
 *           system.security.cryptography.rfc2898derivebytes?view=net-5.0
 * 
 * Notes About File
 * @File: KeyGen.cs
 * @Name: Christian Dunham
 * @Number: 1978955
 * @Date: 12Apr2021
 * @Program Name:  encryption_utility
 *
 * Program Purpose:
 *    This program implements an encryption utility for a windows based system.  
 *    The KeyGen class is responsible for createing master, hmac, and encryption 
 *    for the utility.
 *
 * Design Rational:  
 *    One decision was to make this an object that could store all 3 keys
 *    to make ease of retrieval for decryption.
 *
 * Dynamic Memory:
 *    Use of higher level language omitted memory maintainance
 *
 *******************************************************************************
 *******************************************************************************
 *                        Special Cases Identified
 * : ??? : 
 *******************************************************************************
 *******************************************************************************
 *Product BackLog :
 *                 1) 
 *
 *******************************************************************************
 *******************************************************************************
 * Code Outline :        
 *                              : attributes :
 *                              : initializer :
 *                              : getMasterKey :
 *                              : getDerivedKey :
 ******************************************************************************* 
 *                        Included Libraries
 *******************************************************************************
 *******************************************************************************
*/
using System.Security.Cryptography; //For rfc2898
using System.Text;

public class KeyGen
{
    // Attributes of a KeyGen
    public byte[] MasterKey;
    public byte[] EncryptionKey;
    public byte[] HMACKey;
    public int derivedIterations = 1;  //Derived iterations are only 1
    string encryptionSalt_String = "I am the Encryption Key";  // Set Salt
    string HMAC_Salt_String = "I am the HMAC Key";             // Set Salt
    int keyBytes; //16bytes for aes128, 32bytes for 256, 24bytes for 192bit 3des (smaller keys no support)
    HashAlgorithmName han;

    /*
        * KeyGen(string pwd1, byte[] salt1, int myIterations)
        * 
        * pwd1 : the password from user
        * salt1 : salt for master random 8 bytes
        * output: keyGen Object with all 3 keys
    */
    public KeyGen(string pwd1, byte[] salt1, int myIterations, int keySize, int hash_algortihm )
    {
        setKey(keySize);
        setHashName(hash_algortihm);
        MasterKey = getMasterKey(pwd1, salt1, myIterations, keyBytes);
        byte[] salt2 = Encoding.ASCII.GetBytes(encryptionSalt_String);
        EncryptionKey = getDerivedKey(MasterKey, salt2, derivedIterations, keyBytes);
        byte[] salt3 = Encoding.ASCII.GetBytes(HMAC_Salt_String);
        HMACKey = getDerivedKey(MasterKey, salt3, derivedIterations, keyBytes);
    }//end KeyGen

    /*
     * getMasterKey(string pwd1, byte[] salt1, int myIterations)
     * 
     * pwd1 : the password from user
     * salt1 : salt for master random 8 bytes
     * myIterations : num of iterations from user
     * output: byte[] of master key
    */
    public byte[] getMasterKey(string pwd1, byte[] salt1, int myIterations, int keySize)
    {
        Rfc2898DeriveBytes masterKey_Obj = new Rfc2898DeriveBytes
                           (pwd1, salt1, myIterations, han);
        byte[] masterKey_Bytes = masterKey_Obj.GetBytes(keySize);
        return masterKey_Bytes;
    }//End getMasterKEy
    /*
     * getDerivedKey(byte[] pwd1, byte[] salt1, int Iterations)
     * 
     * pwd1 : the password from user
     * salt : salt for key 8 bytes
     * Iterations : num of iterations default
     * output: byte[] of derivedd key
    */
    public byte[] getDerivedKey(byte[] pwd1, byte[] salt, int Iterations, int keySize)
    {
        Rfc2898DeriveBytes masterKey_Obj = new Rfc2898DeriveBytes
                           (pwd1, salt, Iterations, han);
        byte[] masterKey_Bytes = masterKey_Obj.GetBytes(keySize);
        return masterKey_Bytes;
    }//end getDerivedKey

    /*
      * getDerivedKey(byte[] pwd1, byte[] salt1, int Iterations)
      * 
      * pwd1 : the password from user
      * salt : salt for key 8 bytes
      * Iterations : num of iterations default
      * output: byte[] of derivedd key
    */
    private void setKey(int keySize)
    {
        if (keySize == 192)
            this.keyBytes = 24;
        else if (keySize == 128)
            this.keyBytes = 16;
        else
            this.keyBytes = 32;

    }//end setKEy
    /*
  * getDerivedKey(byte[] pwd1, byte[] salt1, int Iterations)
  * 
  * pwd1 : the password from user
  * salt : salt for key 8 bytes
  * Iterations : num of iterations default
  * output: byte[] of derivedd key
*/
    private void setHashName(int hash_algorithm)
    {
        if (hash_algorithm == 256)
            this.han = HashAlgorithmName.SHA256;
        else
            this.han = HashAlgorithmName.SHA512;

    }//end getDerivedKey
}//end KeyGen class