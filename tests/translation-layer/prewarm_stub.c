#include "husk-tl-internal.h"
/* The standalone scanner has no host loader or prewarmed mappings. */
tl_dual_mapping *tl_find_stikdebug_prewarmed(void) { return NULL; }
