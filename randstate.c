#include "randstate.h"
#include <gmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

gmp_randstate_t state; /* Global random state */

/* Initializes the global random state with Mersenne Twister*/
void randstate_init(uint64_t seed) {
  gmp_randinit_mt(state);
  gmp_randseed_ui(state, seed);
}

/* Frees memory used by the global random state*/
void randstate_clear(void) { gmp_randclear(state); }
