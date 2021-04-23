# Encryption Assignment For 577


## Running the applications

### Runtime: .NET 5.0

### File Structure is Visual Studio Project: 

### Configurations
Command Line Arguments:`

password : user created keep it to decrypt file

key size(128,192,256) : program supports AES128 AES256 and 3DES192, input just the keysize in bits 

hash size(256, 512) : hash algorithm is SHA256 or SHA512 only put in the bits 

iterations : number of iterations to hash master key 

file to encrypt : in VS proj append ../../../file.ext to place in folder with other files

### Current Description of Implementation
The progam uses a driver that checks command line arguments.  Once arguments are set it will first
enrypt a file to a byte array.  At this time, it will automatically decrypt that file to very 
that the master key and password along with the encrypted data structure will allow for 
parsing the metadata and IV to correctly decrypt. It removes extra padding at end of decrypt.

### Current Description of future Implementation
3DES needs more implemenation.  Current classes are heavily derived from examples.  Current 3DES
does not write encrypted data structure to a new file, but passes the structure directly to the 
decryptor.

Will move the driver to me user prompted to allow a user to start with decryption instead of encryption.

## Performance Discussions on PBKDF2
Key derivations are done using PBKDF2 provided in the [.NET 5.0](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.rfc2898derivebytes?view=net-5.0)
 library. Master key derivation was completed to examine creation times.

The six combinations of six cases are:
1. AES128 using SHA256 and SHA512
1. 3DES192 
1. AES256 using SHA256 and SHA512



Further into finding an optimal number of iterations between performance and security, three encryption tests were run on
files of three different sizes, encrypt using AES256 and SHA256 with 100,000 iterations in the KDF function, summarizing in the following table:

| File               | Size            | Time Encryption | Time Decryption
| :-----------------:| :-------------: | --------------: | ----------------
| Excel Workbook     |      9 kB      | 0.729825 secs   | 0.777776 secs
| PNG Image          |     175 kB      | 0.757357 secs   | 0.777106 secs
| TXT                |     1 KB      | 0.856867 secs   | 0.851239 secs

The numbers show that the KDF generation is not the bottleneck of the encryption. This program can make configure doing 
key derivation using 100,000 iterations, potentially higher if necessary.

