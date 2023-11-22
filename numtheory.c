#include "numtheory.h"
#include "randstate.h"
#include <gmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* Calculates o = (a^d)mod(n) */
void pow_mod(mpz_t o, mpz_t a, mpz_t d, mpz_t n) {
  mpz_t v;
  mpz_t p;
  mpz_t original_d;
  mpz_init_set(original_d, d); /* Keeps the original value of d*/
  mpz_init_set_ui(v, 1);
  mpz_init_set(p, a);

  while (mpz_cmp_ui(d, 0) > 0) {
    if (mpz_odd_p(d) != 0) {
      mpz_mul(v, v, p);
      mpz_mod(v, v, n);
    }
    mpz_mul(p, p, p);
    mpz_mod(p, p, n);

    mpz_fdiv_q_ui(d, d, 2);
  }

  mpz_init_set(o, v);          /* Return the value of v to o*/
  mpz_init_set(d, original_d); /* Returns the original value of d to d*/
  mpz_clears(v, p, original_d, NULL);
}

/* Uses the Miller-Rabin primality test to determine if a number is prime*/
bool is_prime(mpz_t n, uint64_t iters) {
  if (mpz_cmp_ui(n, 2) < 0) /* n cannot be less than 2*/
  {
    return false;
  }
  /* If n equals to 2 or 3, return true*/
  if (mpz_cmp_ui(n, 2) == 0 || mpz_cmp_ui(n, 3) == 0) {
    return true;
  }

  /* If n (n >= 4) is an even number, return false*/
  mpz_t c1;
  mpz_init_set_ui(c1, 0);
  mpz_mod_ui(c1, n, 2);
  if (mpz_cmp_ui(c1, 0) == 0) {
    mpz_clear(c1);
    return false;
  }
  mpz_clear(c1);

  uint32_t power_count = 0;

  mpz_t a;
  mpz_t r;
  mpz_t s;
  mpz_t y;
  mpz_t denominator;
  mpz_t n_minus_1;
  mpz_t n_minus_2;
  mpz_t s_minus_1;
  mpz_t temp_result;
  mpz_t temp_mod_result;
  mpz_t two_base;

  mpz_init_set_ui(a, 0);
  mpz_init_set_ui(r, 0);
  mpz_init_set_ui(s, 0);
  mpz_init_set_ui(y, 0);
  mpz_init_set_ui(denominator, 0);
  mpz_init_set_ui(n_minus_1, 0);
  mpz_init_set_ui(n_minus_2, 0);
  mpz_init_set_ui(s_minus_1, 0);
  mpz_init_set_ui(temp_result, 0);
  mpz_init_set_ui(temp_mod_result, 0);
  mpz_init_set_ui(two_base, 2);

  mpz_sub_ui(n_minus_1, n, 1);
  mpz_sub_ui(n_minus_2, n, 2);
  mpz_pow_ui(denominator, two_base, power_count);
  mpz_mod(temp_mod_result, n, denominator);
  mpz_fdiv_q(temp_result, n, denominator);

  /* Calculates s and r while satisfying (n - 1) = r*(2^s) */

  while (mpz_cmp_ui(temp_mod_result, 0) == 0) {
    power_count += 1;
    mpz_pow_ui(denominator, two_base, power_count);
    mpz_mod(temp_mod_result, n_minus_1, denominator);

    if (mpz_cmp_ui(temp_mod_result, 0) != 0) {
      power_count -= 1;
      mpz_pow_ui(denominator, two_base, power_count);
      mpz_fdiv_q(temp_result, n_minus_1, denominator);
      break;
    }
  }

  mpz_init_set_ui(s, power_count);
  mpz_init_set(r, temp_result);

  mpz_sub_ui(s_minus_1, s, 1);

  /* Start of the actual algorithm */
  for (uint64_t i = 1; i <= iters; i++) {
    mpz_urandomm(a, state, n);
    if (mpz_cmp_ui(a, 2) < 0 || mpz_cmp(a, n_minus_2) > 0) {
      i--;
      continue;
    }

    pow_mod(y, a, r, n);

    if (mpz_cmp_ui(y, 1) != 0 && mpz_cmp(y, n_minus_1) != 0) {

      mpz_t j;
      mpz_init_set_ui(j, 1);

      while (mpz_cmp(j, s_minus_1) <= 0 && mpz_cmp(y, n_minus_1) != 0) {
        mpz_t two;
        mpz_init_set_ui(two, 2);
        pow_mod(y, y, two, n);

        if (mpz_cmp_ui(y, 1) == 0) {

          mpz_clears(a, n_minus_2, n_minus_1, y, r, s, temp_mod_result,
                     temp_result, two_base, denominator, s_minus_1, j, two,
                     NULL);

          return false;
        }
        mpz_add_ui(j, j, 1);
        mpz_clear(two);
      }

      if (mpz_cmp(y, n_minus_1) != 0) {

        mpz_clears(a, n_minus_2, n_minus_1, y, r, s, temp_mod_result,
                   temp_result, two_base, denominator, s_minus_1, j, NULL);

        return false;
      }
      mpz_clear(j);
    }

    if (i == iters) {
      return true;
    }
  }

  mpz_clears(a, n_minus_2, n_minus_1, y, r, s, temp_mod_result, temp_result,
             two_base, denominator, s_minus_1, NULL);

  return true;
}

/* Makes a prime p with at least bits amount of bits with iters amount
of iterations*/
void make_prime(mpz_t p, uint64_t bits, uint64_t iters) {
  /* Calculates the minimum number with the least required amount of bits*/
  bits = bits - 1;
  mpz_ui_pow_ui(p, 2, bits);
  bits = bits + 1;

  /* If the number is not prime, keep adding one to the number until the
  number is prime */
  while (is_prime(p, iters) == false) {
    mpz_add_ui(p, p, 1);
  }
}

/* Calculates the modded inverse*/
void mod_inverse(mpz_t o, mpz_t a, mpz_t n) {
  mpz_t r;
  mpz_t r_inverse;
  mpz_t t;
  mpz_t t_inverse;

  mpz_t q;
  mpz_t r_inv_total;
  mpz_t t_inv_total;
  mpz_t temp_r;
  mpz_t temp_t;

  mpz_init_set(r, n);
  mpz_init_set(r_inverse, a);
  mpz_init_set_ui(t, 0);
  mpz_init_set_ui(t_inverse, 1);

  while (mpz_cmp_ui(r_inverse, 0) != 0) {
    mpz_init_set_ui(q, 0);
    mpz_init_set_ui(r_inv_total, 0);
    mpz_init_set_ui(t_inv_total, 0);
    mpz_init_set(temp_r, r);
    mpz_init_set(temp_t, t);

    mpz_fdiv_q(q, r, r_inverse);

    mpz_init_set(r, r_inverse);
    mpz_mul(r_inv_total, q, r_inverse);
    mpz_sub(r_inverse, temp_r, r_inv_total);

    mpz_init_set(t, t_inverse);
    mpz_mul(t_inv_total, q, t_inverse);
    mpz_sub(t_inverse, temp_t, t_inv_total);

    mpz_clears(q, r_inv_total, t_inv_total, temp_r, temp_t, NULL);
  }

  if (mpz_cmp_ui(r, 1) > 0) {
    mpz_init_set_ui(o, 0);
  } else {
    if (mpz_cmp_ui(t, 0) < 0) {
      mpz_add(t, t, n);
    }
    mpz_init_set(o, t);
  }
  mpz_clears(r, r_inverse, t, t_inverse, NULL);
}

/* Caluclates the greatest common denominator between a and b */
void gcd(mpz_t d, mpz_t a, mpz_t b) {
  mpz_t original_a;
  mpz_t original_b;
  mpz_t t;
  mpz_init_set(original_a, a); /* Keeps the original value of a */
  mpz_init_set(original_b, b); /* Keeps the original value of b */
  while (mpz_cmp_ui(b, 0) != 0) {

    mpz_init_set_ui(t, 0);
    mpz_init_set(t, b);
    mpz_mod(b, a, b);
    mpz_init_set(a, t);
    mpz_clear(t);
  }

  mpz_init_set(d, a);          /* Return the value of a to d*/
  mpz_init_set(a, original_a); /* Returns the original value of a to a*/
  mpz_init_set(b, original_b); /* Returns the original value of b to b */
  mpz_clears(original_b, original_a, NULL);
}
