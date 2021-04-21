/* 
 * This code is largerly derived from the microsoft documentation on rfc2898
 * https://docs.microsoft.com/en-us/dotnet/api/
 *           system.security.cryptography.rfc2898derivebytes?view=net-5.0
 * 
 */
using System.Security.Cryptography; //For rfc2898
using System.Text;

internal class KeyGen
{
    public byte[] MasterKey;
    public byte[] EncryptionKey;
    public byte[] HMACKey;
    public int derivedIterations = 1;
    string encryptionSalt_String = "I am the Encryption Key";
    string HMAC_Salt_String = "I am the HMAC Key";

    public KeyGen(string pwd1, byte[] salt1, int myIterations)
    {
        MasterKey = getMasterKey(pwd1, salt1, myIterations);
        byte[] salt2 = Encoding.ASCII.GetBytes(encryptionSalt_String);
        EncryptionKey = getDerivedKey(MasterKey, salt2, derivedIterations);
        byte[] salt3 = Encoding.ASCII.GetBytes(HMAC_Salt_String);
        HMACKey = getDerivedKey(MasterKey, salt3, derivedIterations);
    }
   
    public byte[] getMasterKey(string pwd1, byte[] salt1, int myIterations)
    {
        Rfc2898DeriveBytes masterKey_Obj = new Rfc2898DeriveBytes
                           (pwd1, salt1, myIterations, HashAlgorithmName.SHA256);
        byte[] masterKey_Bytes = masterKey_Obj.GetBytes(32);
        return masterKey_Bytes;
    }
    public byte[] getDerivedKey(byte[] pwd1, byte[] salt1, int Iterations)
    {
        Rfc2898DeriveBytes masterKey_Obj = new Rfc2898DeriveBytes
                           (pwd1, salt1, Iterations, HashAlgorithmName.SHA256);
        byte[] masterKey_Bytes = masterKey_Obj.GetBytes(32);
        return masterKey_Bytes;
    }
}