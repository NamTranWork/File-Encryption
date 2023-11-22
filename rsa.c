#include "rsa.h"
#include "numtheory.h"
#include "randstate.h"
#include <stdio.h>
#include <gmp.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/* Makes the public key*/
void rsa_make_pub(mpz_t p, mpz_t q, mpz_t n, mpz_t e, uint64_t nbits,
                  uint64_t iters) {

  mpz_t totient_p;
  mpz_t totient_q;
  mpz_t totient;
  mpz_t gcd_value;
  mpz_t lambda;
  mpz_t e_mod;
  mpz_t e1;

  mpz_init_set_ui(n, 0);
  mpz_init_set_ui(e, 0);
  mpz_init_set_ui(e1, 0);
  mpz_init_set_ui(e_mod, 0);
  mpz_init_set_ui(totient_p, 0);
  mpz_init_set_ui(totient_q, 0);
  mpz_init_set_ui(totient, 0);
  mpz_init_set_ui(gcd_value, 1);
  mpz_init_set_ui(lambda, 0);

  /* Generates a random number of bits for p in the range
  [nbits/4, (3 * nbits)/4]*/
  /* The left over bits go over to q*/
  srandom(3);
  uint64_t rand_num = random() % ((3 * nbits) / 4);

  while (rand_num < (nbits / 4) || rand_num >= ((3 * nbits) / 4)) {
    rand_num = random() % ((3 * nbits) / 4);
  }

  make_prime(p, rand_num, iters);
  make_prime(q, nbits - rand_num, iters);
  mpz_mul(n, p, q);

  /* Calculates the lambda value */
  mpz_sub_ui(totient_p, p, 1);
  mpz_sub_ui(totient_q, q, 1);
  mpz_mul(totient, totient_p, totient_q);
  gcd(gcd_value, totient_p, totient_q);
  mpz_fdiv_q(lambda, totient, gcd_value);

  /* Keeps generating the gcd() of each random number until a number
  coprime with lambda is founded. That value is e. */
  mpz_urandomb(e1, state, nbits);
  gcd(e_mod, e1, lambda);
  mpz_init_set(e, e1);

  while (mpz_cmp_ui(e1, 2) <= 0 || mpz_cmp(e1, n) >= 0 ||
         mpz_cmp_ui(e_mod, 1) != 0) {
    mpz_urandomb(e1, state, nbits);
    gcd(e_mod, e1, lambda);

    if (mpz_cmp_ui(e1, 2) > 0 && mpz_cmp(e1, n) < 0 &&
        mpz_cmp_ui(e_mod, 1) == 0) {
      mpz_init_set(e, e1);
      break;
    }
  }

  mpz_clears(totient_p, totient_q, totient, gcd_value, lambda, e1, e_mod, NULL);
}

/* Writes public key to file*/
void rsa_write_pub(mpz_t n, mpz_t e, mpz_t s, char username[], FILE *pbfile) {
  gmp_fprintf(pbfile, "%Zx\n", n);
  gmp_fprintf(pbfile, "%Zx\n", e);
  gmp_fprintf(pbfile, "%Zx\n", s);
  gmp_fprintf(pbfile, "%s\n", username);
}

/* Reads public key from file*/
void rsa_read_pub(mpz_t n, mpz_t e, mpz_t s, char username[], FILE *pbfile) {
  gmp_fscanf(pbfile, "%Zx\n", n);
  gmp_fscanf(pbfile, "%Zx\n", e);
  gmp_fscanf(pbfile, "%Zx\n", s);
  size_t array_size = 10000;
  getline(&username, &array_size, pbfile);
}

/* Generates private key*/
void rsa_make_priv(mpz_t d, mpz_t e, mpz_t p, mpz_t q) {
  mpz_t totient_p;
  mpz_t totient_q;
  mpz_t totient;
  mpz_t gcd_value;
  mpz_t lambda;

  mpz_init_set_ui(totient_p, 0);
  mpz_init_set_ui(totient_q, 0);
  mpz_init_set_ui(totient, 0);
  mpz_init_set_ui(gcd_value, 0);
  mpz_init_set_ui(lambda, 0);

  /* Calculates lambda */
  mpz_sub_ui(totient_p, p, 1);
  mpz_sub_ui(totient_q, q, 1);
  mpz_mul(totient, totient_p, totient_q);
  gcd(gcd_value, totient_p, totient_q);
  mpz_fdiv_q(lambda, totient, gcd_value);

  /* Calculates d by computing the inverse of (e)mod(lambda)*/
  mod_inverse(d, e, lambda);

  mpz_clears(totient_p, totient_q, totient, gcd_value, lambda, NULL);
}

/* Writes private key to file */
void rsa_write_priv(mpz_t n, mpz_t d, FILE *pvfile) {
  gmp_fprintf(pvfile, "%Zx\n", n);
  gmp_fprintf(pvfile, "%Zx\n", d);
}

/* Reads private key from file */
void rsa_read_priv(mpz_t n, mpz_t d, FILE *pvfile) {
  gmp_fscanf(pvfile, "%Zx\n", n);
  gmp_fscanf(pvfile, "%Zx\n", d);
}

/* Encrypts message m to ciphertext c */
void rsa_encrypt(mpz_t c, mpz_t m, mpz_t e, mpz_t n) { pow_mod(c, m, e, n); }

/* Encrypts the contents of infile to outfile */
void rsa_encrypt_file(FILE *infile, FILE *outfile, mpz_t n, mpz_t e) {
  mpz_t m;
  mpz_t c;
  mpz_t n1;
  mpz_init_set_ui(c, 0);
  mpz_init_set_ui(m, 0);
  mpz_init_set(n1, n);

  uint64_t k = -1;

  /* Calculates log2(n) by dividing n by half until n is not greater
  than 0 while keep k as a counter for each loop. */
  while (mpz_cmp_ui(n1, 0) > 0) {
    mpz_fdiv_q_ui(n1, n1, 2);
    k++;
  }
  k = (k - 1) / 8;

  size_t bytes_read = 0; /* Variable that holds the bytes read from file*/

  /* Allocates k amount of bytes to block */
  uint8_t *block = (uint8_t *)calloc(k, sizeof(uint8_t));
  block[0] = 255;

  /* Reads k - 1 bytes or less from infile and writes
  k - 1 bytes or less to outfile */
  while ((bytes_read = fread(block + 1, 1, k - 1, infile)) > 0) {

    if (bytes_read == k - 1) {
      mpz_import(m, k, 1, sizeof(block[0]), 1, 0, block);
      rsa_encrypt(c, m, e, n);
      gmp_fprintf(outfile, "%Zx\n", c);
    } else {
      bytes_read++;
      mpz_import(m, bytes_read, 1, sizeof(block[0]), 1, 0, block);
      rsa_encrypt(c, m, e, n);
      gmp_fprintf(outfile, "%Zx", c);
      gmp_fprintf(outfile, "\n");
    }
  }

  free(block);
  mpz_clear(c);
  mpz_clear(m);
  mpz_clear(n1);
}

/* Decrypts ciphertext to plaintext m*/
void rsa_decrypt(mpz_t m, mpz_t c, mpz_t d, mpz_t n) { pow_mod(m, c, d, n); }

/* Decrypts the contents of infile to outfile */
void rsa_decrypt_file(FILE *infile, FILE *outfile, mpz_t n, mpz_t d) {
  mpz_t m;
  mpz_t c;
  mpz_t n1;
  mpz_init_set_ui(c, 0);
  mpz_init_set_ui(m, 0);
  mpz_init_set(n1, n);

  uint64_t k = -1;

  /* Calculates log2(n) by dividing n by half until n is not greater
  than 0 while keep k as a counter for each loop. */
  while (mpz_cmp_ui(n1, 0) > 0) {
    mpz_fdiv_q_ui(n1, n1, 2);
    k++;
  }
  k = (k - 1) / 8;

  /* Allocates k amount of bytes to block */
  uint8_t *block = (uint8_t *)calloc(k, sizeof(uint8_t));

  int j = 0; /* Variable that holds the bytes read from file*/

  /* Scans a block of bytes from infile with a hex string and writes
  k - 1 bytes to outfile */
  while ((j = gmp_fscanf(infile, "%Zx\n", c)) > 0) {
    rsa_decrypt(m, c, d, n);
    mpz_export(block, &k, 1, sizeof(uint8_t), 1, 0, m);
    j = k;
    fwrite(block + 1, 1, j - 1, outfile);
  }

  free(block);
  mpz_clear(c);
  mpz_clear(m);
  mpz_clear(n1);
}

/* Calculates signature */
void rsa_sign(mpz_t s, mpz_t m, mpz_t d, mpz_t n) { pow_mod(s, m, d, n); }

/* Makes sure that message m equals to signature s*/
bool rsa_verify(mpz_t m, mpz_t s, mpz_t e, mpz_t n) {
  mpz_t t;
  mpz_init_set_ui(t, 0);

  pow_mod(t, s, e, n);

  if (mpz_cmp(t, m) == 0) {
    mpz_clear(t);
    return true;
  } else {
    mpz_clear(t);
    return false;
  }
}
