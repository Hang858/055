/* Each light-lattice shared library has its own DRNG state.  The adapter
 * initializes it from the OS RNG before the first operation. */
#include "drng.h"
DRNG_ctx drng_algorithm;
