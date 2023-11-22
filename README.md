# Assignment 5 Documentation

## Directions
1) Open up the command line in Ubuntu 22.04 (Linux) and make sure that the clang complier and git have been installed in your local device.
2) Make sure that the cse13s folder gets cloned to a designated folder in your local device.
3) Make sure that right files have been loaded, especially the header files, program files, and the Makefile.
4) Go to the "asgn5" folder and open up terminal.
5) Once you are in the "asgn5" directory, enter the command: $ make.
6) The commands in the Makefile will make compling the header and program files in the "asgn5" directory easier.
7) There are three main programs named keygen, encrypt, and decrypt.  In a nutshell, keygen produces the public and private keys to their respective files.  The encrypt program encrypts a standard input or an input file to the standard output or an output file. The decrypt program decrypts a standard input or an input file to the standard output or an output file. The program and header versions of rsa, randstate, and numtheory are needed in the directory to supply keygen, encrypt, and decrypt with the necessary functions so that they could work. 
8) To run keygen, type in ./keygen "command"
9) To run encrypt, type in ./encrypt "command"
10) To run decrypt, type in ./decrypt "command"
11) Note that only number inputs can be encrypted and decrypted, so no actual ASCII text like "I worship Ben as a tutor and god in CSE13S".
12) Also note that the number inputs should have no spaces between them.  Example: "69" and "420" are acceptable inputs while "6 9" and "4 20" are not.


## Command-line options for keygen.c
- -b: specifies the minimu bits for public modulus n (default: 1024)
- -i: specifies the number of Miller-Rabin iterations for testing primes (default: 50)
- -n pbfile: specifies the public key file (default rsa.pub)
- -d pvfile: specifies the private key file (default: rsa.priv)
- -s: specifies the random seed for random state initialization (default: the seconds since the UNIX epoch, given by time(NULL) )
- -v: enables verbose output
- -h: displays program synopsis and usage

## Command-line options for encrypt.c
- -i: specifies the input file to encrypt (default: stdin)
- -o: specifies the output file to encrypt (default: stdout)
- -n: speciifies the file containing the public key (default: rsa.pub)
- -v: enables verbose output
- -h: displays program synopsis and usage

## Command-line options for decrypt.c
- -i: specifies the input file to decrypt (default: stdin)
- -o: specifies the output file to decrypt (default: stdout)
- -n: speciifies the file containing the private key (default: rsa.priv)
- -v: enables verbose output
- -h: displays program synopsis and usage

## Deliverables 
- decrypt.c - Contains the implementation and main() function for the decrypt program
- encrypt.c - Contains the implementation and main() function for the encrypt program
- keygen.c - Contains the implementation and main() function for the keygen program
- numtheory.c - Contains the implementations of the number theory functions
- numtheory.h - Specifies the interface for the number theory functions
- randstate.c - Contains the implementation of the random state interface for the RSA library and number theory functions
- randstate.h - Specifies the interface for initializing and clearing random state
- rsa.c - Contains the implementation of the RSA library
- rsa.h - Specifies the interface for the RSA library


|Name|Email|
|----|-----|
|Nam Tran|natrtran@ucsc.edu|