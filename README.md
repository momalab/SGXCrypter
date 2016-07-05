# encrypter
Instructions on how to create an encrypted executable.

1. Pull the repository from github and open the project SGX_Stub (on main folder).

2. Build the project clicking Build->Build solution from the main menu (or hitting F7). The project works on Debug mode only.

3. Open a console and navigate to MyEncrypter/Release folder

4. Type MyEncrypter.exe [your_file.exe] to encrypt your file. There are already a number of encrypted .exe files.

5. Download and run ResourceTuner

6. Open the SGX_Stub executable present on SGX-Packer/Debug

7. Click on the green cross (add) to add a resource. Choose Resource Type : User-defined and type ENC to its adjacent field. Type 452 as the resource name. Click on Path to data and locate encrypted.dat in folder MyEncrypter/Release. Click OK.

8. Click Save File As (from the disk icon) and choose a name for your encrypted executable.

9. Done!

