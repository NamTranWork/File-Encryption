#include "numtheory.h"
#include "randstate.h"
#include "rsa.h"
#include <gmp.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define OPTIONS "i:o:n:vh"

int main(int argc, char **argv) {

  int opt = 0;
  int activation_options[6];

  char *input_file2 = "eageag";
  char *output_file = "eageag";
  char *public_key_file = "rsa.pub";
  char *username = calloc(10000, sizeof(char));

  FILE *in_file = NULL;
  FILE *out_file = NULL;
  FILE *pub_file = NULL;

  mpz_t n;
  mpz_t e;
  mpz_t s;
  mpz_t expected_s;

  mpz_init_set_ui(n, 0);
  mpz_init_set_ui(e, 0);
  mpz_init_set_ui(s, 0);
  mpz_init_set_ui(expected_s, 0);

  while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
    switch (opt) {
    case 'i':
      activation_options[0] = 1;
      input_file2 = optarg;
      break;
    case 'o':
      activation_options[1] = 1;
      output_file = optarg;
      break;
    case 'n':
      activation_options[2] = 1;
      public_key_file = optarg;
      break;
    case 'v':
      activation_options[3] = 1;
      break;
    case 'h':
      activation_options[4] = 1;
      fprintf(stderr, "Usage: %s [options]\n", argv[0]);
      fprintf(
          stderr,
          "  %s encrypts an input file using the specified public key file,\n",
          argv[0]);
      fprintf(stderr, "  writing the result to the specified output file.\n");
      fprintf(stderr, "    -i <infile> : Read input from <infile>. Default: "
                      "standard input.\n");
      fprintf(stderr, "    -o <outfile>: Write output to <outfile>. Default: "
                      "standard output.\n");
      fprintf(
          stderr,
          "    -n <keyfile>: Public key is in <keyfile>. Default: rsa.pub.\n");
      fprintf(stderr, "    -v          : Enable verbose output.\n");
      fprintf(stderr,
              "    -h          : Display program synopsis and usage.\n");
      return 0;
      break;
    default:
      fprintf(stderr, "Usage: %s [options]\n", argv[0]);
      fprintf(
          stderr,
          "  %s encrypts an input file using the specified public key file,\n",
          argv[0]);
      fprintf(stderr, "  writing the result to the specified output file.\n");
      fprintf(stderr, "    -i <infile> : Read input from <infile>. Default: "
                      "standard input.\n");
      fprintf(stderr, "    -o <outfile>: Write output to <outfile>. Default: "
                      "standard output.\n");
      fprintf(
          stderr,
          "    -n <keyfile>: Public key is in <keyfile>. Default: rsa.pub.\n");
      fprintf(stderr, "    -v          : Enable verbose output.\n");
      fprintf(stderr,
              "    -h          : Display program synopsis and usage.\n");
      return 1;
      break;
    }
  }

  if (activation_options[0] == 1) {
    in_file = fopen(input_file2, "r");

    /* Checks if the input file can be accessed*/
    if (in_file == NULL) {
      fprintf(stderr,
              "encrypt: Couldn't open %s to read plaintext: ", input_file2);
      fprintf(stderr, "No such file or directory\n");
      free(in_file);
      free(out_file);
      free(pub_file);
      activation_options[4] = 1;
    }
  }

  pub_file = fopen(public_key_file, "r");

  /* Checks if the public-key file can be accessed*/
  if (pub_file == NULL) {
    fprintf(stderr, "encrypt: Couldn't open %s to read public key\n",
            public_key_file);
    free(in_file);
    free(out_file);
    free(pub_file);
    activation_options[4] = 1;
  }

  /* Prints out help message and exits program if a numeric argument
   is out of range, a bad option was given, or if a file can't be
   accessed for some reason. */
  if (activation_options[4] == 1) {
    fprintf(stderr, "Usage: %s [options]\n", argv[0]);
    fprintf(
        stderr,
        "  %s encrypts an input file using the specified public key file,\n",
        argv[0]);
    fprintf(stderr, "  writing the result to the specified output file.\n");
    fprintf(stderr, "    -i <infile> : Read input from <infile>. Default: "
                    "standard input.\n");
    fprintf(stderr, "    -o <outfile>: Write output to <outfile>. Default: "
                    "standard output.\n");
    fprintf(
        stderr,
        "    -n <keyfile>: Public key is in <keyfile>. Default: rsa.pub.\n");
    fprintf(stderr, "    -v          : Enable verbose output.\n");
    fprintf(stderr, "    -h          : Display program synopsis and usage.\n");
    return 1;
  }

  rsa_read_pub(n, e, s, username, pub_file);

  mpz_set_str(expected_s, username, 62);

  /* Verifies if the signature is verified*/
  if (rsa_verify(expected_s, s, e, n) == false) {
    fprintf(stderr, "./encrpyt: Couldn't verify user signature!\n");
    return 1;
  }

  /* Prints out verbose output*/
  if (activation_options[3] == 1) {
    fprintf(stderr, "username: %s\n", username);
    fprintf(stderr, "user signature (%zu bits): ", mpz_sizeinbase(s, 2));
    gmp_printf("%Zd\n", s);
    fprintf(stderr, "n - modulus (%zu bits): ", mpz_sizeinbase(n, 2));
    gmp_printf("%Zd\n", n);
    fprintf(stderr, "e - public exponent (%zu bits): ", mpz_sizeinbase(e, 2));
    gmp_printf("%Zd\n", e);
  }

  /* Encrypts input file or stdin with the public key file and sends
  the output to either stdout or a given output file. */
  if (activation_options[1] == 0) {
    if (activation_options[0] == 0) {
      rsa_encrypt_file(stdin, stdout, n, e);
    } else {
      rsa_encrypt_file(in_file, stdout, n, e);
    }
  } else {
    out_file = fopen(output_file, "w+");
    uint64_t size = 0;

    if (activation_options[0] == 0) {
      rsa_encrypt_file(stdin, out_file, n, e);
      fseek(out_file, 0, SEEK_END);
      size = ftell(out_file);
      while (size == 0) {
        rsa_encrypt_file(stdin, out_file, n, e);
        fseek(out_file, 0, SEEK_END);
        size = ftell(out_file);

        if (size != 0) {
          break;
        }
      }
    } else {
      rsa_encrypt_file(in_file, out_file, n, e);
      fseek(out_file, 0, SEEK_END);
      size = ftell(out_file);
      while (size == 0) {
        rsa_encrypt_file(in_file, out_file, n, e);
        fseek(out_file, 0, SEEK_END);
        size = ftell(out_file);

        if (size != 0) {
          break;
        }
      }
    }
  }

  free(in_file);
  free(out_file);
  free(pub_file);
  free(username);

  mpz_clears(n, e, s, expected_s, NULL);
  return 0;
}
