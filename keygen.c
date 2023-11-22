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

#define OPTIONS "b:i:n:d:s:vh"

int main(int argc, char **argv) {

  int opt = 0;
  int activation_options[8];
  uint64_t bits = 1024;
  uint64_t iterations = 50;
  char *public_key_file_name = "rsa.pub";
  char *private_key_file_name = "rsa.priv";
  char *username;
  uint64_t seed = time(NULL);

  FILE *pub_file;
  FILE *pri_file;

  mpz_t p;
  mpz_t q;
  mpz_t n;
  mpz_t d;
  mpz_t e;
  mpz_t s;
  mpz_t signature;
  mpz_init_set_ui(p, 0);
  mpz_init_set_ui(q, 0);
  mpz_init_set_ui(n, 0);
  mpz_init_set_ui(d, 0);
  mpz_init_set_ui(e, 0);
  mpz_init_set_ui(s, 0);
  mpz_init_set_ui(signature, 0);

  while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
    switch (opt) {
    case 'b':
      activation_options[0] = 1;

      if (atoi(optarg) < 50 || atoi(optarg) > 4096) {
        fprintf(stderr, "Number of bits must be 50-4096, not %d.\n",
                atoi(optarg));
        activation_options[6] = 1;
      } else {
        bits = atoi(optarg);
      }

      break;
    case 'i':
      activation_options[1] = 1;

      if (atoi(optarg) < 1 || atoi(optarg) > 500) {
        fprintf(stderr, "Number of iterations must be 1-500, not %d.\n",
                atoi(optarg));
        activation_options[6] = 1;
      } else {
        iterations = atoi(optarg);
      }
      break;
    case 'n':
      activation_options[2] = 1;
      public_key_file_name = optarg;
      break;
    case 'd':
      activation_options[3] = 1;
      private_key_file_name = optarg;
      break;
    case 's':
      activation_options[4] = 1;
      seed = strtoul(optarg, NULL, 10);
      break;
    case 'v':
      activation_options[5] = 1;
      break;
    case 'h':
      fprintf(stderr, "Usage: %s [options]\n", argv[0]);
      fprintf(stderr,
              "  %s generates a public / private key pair, placing the keys "
              "into the public and private\n",
              argv[0]);
      fprintf(stderr, "  key files as specified below. The keys have a modulus "
                      "(n) whose length is specified in\n");
      fprintf(stderr, "  the program options.\n");
      fprintf(stderr, "    -s <seed>   : Use <seed> as the random number seed. "
                      "Default: time()\n");
      fprintf(stderr, "    -b <bits>   : Public modulus n must have at least "
                      "<bits> bits. Default: 1024\n");
      fprintf(stderr, "    -i <iters>  : Run <iters> Miller-Rabin iterations "
                      "for primality testing. Default: 50\n");
      fprintf(
          stderr,
          "    -n <pbfile> : Public key file is <pbfile>. Default: rsa.pub\n");
      fprintf(stderr, "    -d <pvfile> : Private key file is <pvfile>. "
                      "Default: rsa.priv\n");
      fprintf(stderr, "    -v          : Enable verbose output.\n");
      fprintf(stderr,
              "    -h          : Display program synopsis and usage.\n");
      return 0;
      break;
    default:
      activation_options[6] = 1;
      activation_options[7] = 1;
      break;
    }
  }

  /* Prints out help message and exits program if a bad option was given
  or a numeric argument is out of range */
  if (activation_options[6] == 1) {
    fprintf(stderr, "Usage: %s [options]\n", argv[0]);
    fprintf(stderr,
            "  %s generates a public / private key pair, placing the keys into "
            "the public and private\n",
            argv[0]);
    fprintf(stderr, "  key files as specified below. The keys have a modulus "
                    "(n) whose length is specified in\n");
    fprintf(stderr, "  the program options.\n");
    fprintf(stderr, "    -s <seed>   : Use <seed> as the random number seed. "
                    "Default: time()\n");
    fprintf(stderr, "    -b <bits>   : Public modulus n must have at least "
                    "<bits> bits. Default: 1024\n");
    fprintf(stderr, "    -i <iters>  : Run <iters> Miller-Rabin iterations for "
                    "primality testing. Default: 50\n");
    fprintf(
        stderr,
        "    -n <pbfile> : Public key file is <pbfile>. Default: rsa.pub\n");
    fprintf(
        stderr,
        "    -d <pvfile> : Private key file is <pvfile>. Default: rsa.priv\n");
    fprintf(stderr, "    -v          : Enable verbose output.\n");
    fprintf(stderr, "    -h          : Display program synopsis and usage.\n");
    return 1;
  }

  pub_file = fopen(public_key_file_name, "w");
  pri_file = fopen(private_key_file_name, "w");

  /* Checks if public file can be accessed*/
  if (pub_file == NULL) {
    fprintf(stderr, "Error: Public file can't be accessed\n");
    free(pub_file);
    free(pri_file);
    return 1;
  }

  /* Checks if private file can be accessed*/
  if (pri_file == NULL) {
    fprintf(stderr, "Error: Private file can't be accessed\n");
    free(pub_file);
    free(pri_file);
    return 1;
  }

  fchmod(fileno(pri_file), 0600);

  randstate_init(seed);

  rsa_make_pub(p, q, n, e, bits, iterations);
  rsa_make_priv(d, e, p, q);
  username = getenv("USER");

  mpz_set_str(signature, username, 62);

  rsa_sign(s, signature, d, n);

  fclose(pub_file);
  fclose(pri_file);

  pub_file = fopen(public_key_file_name, "w+");
  rsa_write_pub(n, e, s, username, pub_file);
  fseek(pub_file, 0, SEEK_END);
  long size = ftell(pub_file);

  /* Writes public key to its designated file*/
  while (size == 0) {
    rsa_write_pub(n, e, s, username, pub_file);
    fseek(pub_file, 0, SEEK_END);
    size = ftell(pub_file);

    if (size != 0) {
      break;
    }
  }

  pri_file = fopen(private_key_file_name, "w+");
  rsa_write_priv(n, d, pri_file);
  fseek(pri_file, 0, SEEK_END);
  size = ftell(pri_file);

  /* Writes private key to its designated file*/
  while (size == 0) {
    rsa_write_priv(n, d, pri_file);
    fseek(pri_file, 0, SEEK_END);
    size = ftell(pri_file);

    if (size != 0) {
      break;
    }
  }

  /* Prints verbose output */
  if (activation_options[5] == 1) {
    fprintf(stderr, "username: %s\n", username);
    fprintf(stderr, "user signature (%zu bits): ", mpz_sizeinbase(s, 2));
    gmp_printf("%Zd\n", s);
    fprintf(stderr, "p (%zu bits): ", mpz_sizeinbase(p, 2));
    gmp_printf("%Zd\n", p);
    fprintf(stderr, "q (%zu bits): ", mpz_sizeinbase(q, 2));
    gmp_printf("%Zd\n", q);
    fprintf(stderr, "n - modulus (%zu bits): ", mpz_sizeinbase(n, 2));
    gmp_printf("%Zd\n", n);
    fprintf(stderr, "e - public exponent (%zu bits): ", mpz_sizeinbase(e, 2));
    gmp_printf("%Zd\n", e);
    fprintf(stderr, "d - private exponent (%zu bits): ", mpz_sizeinbase(d, 2));
    gmp_printf("%Zd\n", d);
  }

  mpz_clears(p, q, n, d, e, s, signature, NULL);
  free(pub_file);
  free(pri_file);
  randstate_clear();
  return 0;
}
