# SGXCrypter

SGXCrypter is a novel approach on encryption based binary packing. SGXCrypter effectively removes the decryption key from the unpacking code (decryption stub) thereby eliminating the possibility of it getting compromised by static analysis/disassembly. This is achieved by retreiving the key from a remote server via _remote attestation_, a feature provided by Intel's SGX technology. By leveraging SGX, our crypter also isolates the key retreival and decryption process, thereby rendering runtime analysis impossible as well.

SGXCrypter is currently able to target Windows Portable Executable (PE) files and is compatible with SGX enabled processors. The project can be built via Microsoft Visual Studio 2012, having also installed Intel SGX SDK and SGX PSW [(download link)](https://software.intel.com/en-us/sgx-sdk/download).

Instructions on how to create an encrypted executable.

1. Pull the repository from github and open the project SGX_Stub (in main folder).

2. Build the project clicking Build->Build solution from the main menu (or hitting F7). The project works on Debug mode only.

3. Open a console and navigate to MyEncrypter/Release folder

4. Type MyEncrypter.exe [your_file.exe] to encrypt your file. There is already a number of encrypted .exe files.

5. Download and run ResourceTuner

6. Open the SGX_Stub executable present on SGX-Packer/Debug

7. Click on the green cross (add) to add a resource. Choose Resource Type : User-defined and type ENC to its adjacent field. Type 452 as the resource name. Click on Path to data and locate encrypted.dat in folder MyEncrypter/Release. Click OK.

8. Click Save File As (from the disk icon) and choose a name for your encrypted executable.

9. Done!

If you use the SGXCrypter application, please reference the following [paper](http://sites.nyuad.nyu.edu/moma/pdfs/sgxcrypter.pdf)

D. Tychalas, N.G. Tsoutsos and M. Maniatakos SGXCrypter: IP Protection for Portable Executables using Intel's SGX Technology 22nd Asia and South Pacific Design Automation Conference (ASPDAC) 2017 