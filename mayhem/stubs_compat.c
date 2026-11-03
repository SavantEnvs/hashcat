/*
 * Shims for what upstream's tools/fuzz has not followed yet.
 *
 * hc_fclose: tools/fuzz/stubs.c once defined it void while the declaration became int (eabc764f6).
 * It is built with that definition renamed away and the int one provided here; where upstream has
 * fixed its stub the renamed copy is just an unused symbol.
 *
 * run_kernels_wanted: src/mpsp.c (mp_css_split_cnt) now calls it, and it lives in backend.c, which
 * a fuzz target does not link. The mask harness zeroes hashconfig, where the real function
 * returns false at its first check, so false is what it stands in with.
 */

#include "common.h"
#include "types.h"
#include "filehandling.h"

#define hc_fclose stubs_hc_fclose_unused

#include "../tools/fuzz/stubs.c"

#undef hc_fclose

int hc_fclose (HCFILE *fp)
{
  (void) fp;

  return 0;
}

bool run_kernels_wanted (hashcat_ctx_t *hashcat_ctx)
{
  (void) hashcat_ctx;

  return false;
}
