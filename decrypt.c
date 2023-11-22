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
  char *private_key_file = "rsa.priv";

  FILE *in_file = NULL;
  FILE *out_file = NULL;
  FILE *pri_file = NULL;

  mpz_t n;
  mpz_t d;

  mpz_init_set_ui(n, 0);
  mpz_init_set_ui(d, 0);

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
      private_key_file = optarg;
      break;
    case 'v':
      activation_options[3] = 1;
      break;
    case 'h':
      activation_options[4] = 1;
      fprintf(stderr, "Usage: %s [options]\n", argv[0]);
      fprintf(
          stderr,
          "  %s decrypts an input file using the specified private key file,\n",
          argv[0]);
      fprintf(stderr, "  writing the result to the specified output file.\n");
      fprintf(stderr, "    -i <infile> : Read input from <infile>. Default: "
                      "standard input.\n");
      fprintf(stderr, "    -o <outfile>: Write output to <outfile>. Default: "
                      "standard output.\n");
      fprintf(stderr, "    -n <keyfile>: Private key is in <keyfile>. Default: "
                      "rsa.priv.\n");
      fprintf(stderr, "    -v          : Enable verbose output.\n");
      fprintf(stderr,
              "    -h          : Display program synopsis and usage.\n");
      return 0;
      break;
    default:
      fprintf(stderr, "Usage: %s [options]\n", argv[0]);
      fprintf(
          stderr,
          "  %s decrypts an input file using the specified private key file,\n",
          argv[0]);
      fprintf(stderr, "  writing the result to the specified output file.\n");
      fprintf(stderr, "    -i <infile> : Read input from <infile>. Default: "
                      "standard input.\n");
      fprintf(stderr, "    -o <outfile>: Write output to <outfile>. Default: "
                      "standard output.\n");
      fprintf(stderr, "    -n <keyfile>: Private key is in <keyfile>. Default: "
                      "rsa.priv.\n");
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
              "decrypt: Couldn't open %s to read plaintext: ", input_file2);
      fprintf(stderr, "No such file or directory\n");
      free(in_file);
      free(out_file);
      free(pri_file);
      activation_options[4] = 1;
    }
  }

  pri_file = fopen(private_key_file, "r+");

  /* Checks if the private-key file can be accessed*/
  if (pri_file == NULL) {
    fprintf(stderr, "./decrypt: Couldn't open %s to read private key\n",
            private_key_file);
    free(in_file);
    free(out_file);
    free(pri_file);
    activation_options[4] = 1;
  }

  /* Prints out help message and exits program if a numeric argument
   is out of range, a bad option was given, or if a file can't be
   accessed for some reason. */
  if (activation_options[4] == 1) {
    fprintf(stderr, "Usage: %s [options]\n", argv[0]);
    fprintf(
        stderr,
        "  %s decrypts an input file using the specified private key file,\n",
        argv[0]);
    fprintf(stderr, "  writing the result to the specified output file.\n");
    fprintf(stderr, "    -i <infile> : Read input from <infile>. Default: "
                    "standard input.\n");
    fprintf(stderr, "    -o <outfile>: Write output to <outfile>. Default: "
                    "standard output.\n");
    fprintf(
        stderr,
        "    -n <keyfile>: Private key is in <keyfile>. Default: rsa.priv.\n");
    fprintf(stderr, "    -v          : Enable verbose output.\n");
    fprintf(stderr, "    -h          : Display program synopsis and usage.\n");
    return 1;
  }
  rsa_read_priv(n, d, pri_file);

  /* Prints out verbose output*/
  if (activation_options[3] == 1) {
    fprintf(stderr, "n - modulus (%zu bits): ", mpz_sizeinbase(n, 2));
    gmp_printf("%Zd\n", n);
    fprintf(stderr, "d - private exponent (%zu bits): ", mpz_sizeinbase(d, 2));
    gmp_printf("%Zd\n", d);
  }

  /* Decrypts input file or stdin with the private key file and sends
  the output to either stdout or a given output file. */
  if (activation_options[1] == 0) {
    if (activation_options[0] == 0) {
      rsa_decrypt_file(stdin, stdout, n, d);
    } else {
      rsa_decrypt_file(in_file, stdout, n, d);
    }
  } else {
    out_file = fopen(output_file, "w+");
    uint64_t size = 0;

    if (activation_options[0] == 0) {
      rsa_decrypt_file(stdin, out_file, n, d);
      fseek(out_file, 0, SEEK_END);
      size = ftell(out_file);
      while (size == 0) {
        rsa_decrypt_file(stdin, out_file, n, d);
        fseek(out_file, 0, SEEK_END);
        size = ftell(out_file);

        if (size != 0) {
          break;
        }
      }
    } else {
      rsa_decrypt_file(in_file, out_file, n, d);
      fseek(out_file, 0, SEEK_END);
      size = ftell(out_file);
      while (size == 0) {
        rsa_decrypt_file(in_file, out_file, n, d);
        fseek(out_file, 0, SEEK_END);
        size = ftell(out_file);

        if (size != 0) {
          break;
        }
      }
    }
  }

  mpz_clears(n, d, NULL);
  free(in_file);
  free(out_file);
  free(pri_file);
  return 0;
}
