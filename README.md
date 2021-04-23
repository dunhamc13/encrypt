# Encryption Assignment For 577


## Running the applications

### Runtime: .NET 5.0

### File Structure is Visual Studio Project: 

### Configurations
Command Line Arguments:`

password : user created keep it to decrypt file must be 24 characters

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
3DES needs more modularaization.. needs to be separated out.

Will move the driver to me user prompted to allow a user to start with decryption instead of encryption.

## Performance Discussions on PBKDF2
Key derivations are done using PBKDF2 provided in the [.NET 5.0](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.rfc2898derivebytes?view=net-5.0)
 library. Master key derivation was completed to examine creation times.

The six combinations of six cases are:
1. AES128 using SHA256 and SHA512
1. 3DES192 
1. AES256 using SHA256 and SHA512

There was no significance in difference in encryption times.  Therefor the program defaults to AES256 with SHA512 for the best security.


Depending on the use of the program and the user will determine what is the balance between performance and security, 10,000,000 iterations can be completed on an average of 7 seconds.
1,000,000 iterations were completed on an average of 0.75 seconds in the KDF function.  Due to the low number of encryptions being 
performed the table below summarizes a balance of 5,000,000 iterations for the entire file encryption, not just key generation (please note these were ran on a 32 CPU core your performance may vary):

| File               | Size            | Time Encryption | 
| :-----------------:| :-------------: | --------------: | 
| Excel Workbook     |      9 kB       | 3.72 secs        | 
| PNG Image          |     175 kB      | 3.74 secs        | 
| TXT                |     1 KB        | 3.73 secs        |
| ISO                |     2.034GB     | 13.78 secs
 
The interprestion of what is seen is that the key generation iteration is not the bottleneck of the encryption. The size of the file to encrypt is
what creates the largest overhead.  I am personally comfortable with a 3 second wait time to encrypt a single file.

