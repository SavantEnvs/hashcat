/*
 * tools/fuzz/stubs.c defines hc_fclose as void; upstream changed the declaration to int
 * (eabc764f6) without touching the stub, so the stub no longer compiles. Build it with that one
 * definition renamed away and provide the int one here. Once upstream fixes its stub the renamed
 * copy is just an unused symbol and this definition still stands.
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
