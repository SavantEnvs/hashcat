// Known-answer test of hashcat's CPU rule engine (src/rp_cpu.c), linked against the normally built
// libhashcat. Prints "PASS <rule>" / "FAIL <rule> ..." per case; mayhem/test.sh counts them.

#include "common.h"
#include "types.h"
#include "rp_cpu.h"

#include <stdio.h>
#include <string.h>

typedef struct
{
  const char *rule;
  const char *in;
  const char *out;   // NULL: the rule must reject the word
} kat_t;

static const kat_t kats[] =
{
  { ":",         "password", "password"         },
  { "l",         "PassWord", "password"         },
  { "u",         "password", "PASSWORD"         },
  { "c",         "password", "Password"         },
  { "C",         "PASSWORD", "pASSWORD"         },
  { "t",         "PassWord", "pASSwORD"         },
  { "T0",        "password", "Password"         },
  { "r",         "password", "drowssap"         },
  { "d",         "abc",      "abcabc"           },
  { "f",         "abc",      "abccba"           },
  { "{",         "abcd",     "bcda"             },
  { "}",         "abcd",     "dabc"             },
  { "$1$2$3",    "password", "password123"      },
  { "^1^2",      "password", "21password"       },
  { "[",         "password", "assword"          },
  { "]",         "password", "passwor"          },
  { "D3",        "password", "pasword"          },
  { "'4",        "password", "pass"             },
  { "sa@so0",    "password", "p@ssw0rd"         },
  { "@s",        "password", "paword"           },
  { "z2",        "abc",      "aaabc"            },
  { "Z2",        "abc",      "abccc"            },
  { "q",         "abc",      "aabbcc"           },
  { "c$1",       "password", "Password1"        },
  { "u$!",       "hashcat",  "HASHCAT!"         },
  { "<4",        "password", NULL               },
  { ">4",        "abc",      NULL               },
  { "!z",        "password", "password"         },
  { "/z",        "password", NULL               },
};

int main (void)
{
  const int cnt = (int) (sizeof (kats) / sizeof (kats[0]));

  int bad = 0;

  for (int i = 0; i < cnt; i++)
  {
    char in[RP_PASSWORD_SIZE]  = { 0 };
    char out[RP_PASSWORD_SIZE] = { 0 };

    strcpy (in, kats[i].in);

    const int rc = _old_apply_rule (kats[i].rule, (int) strlen (kats[i].rule), in, (int) strlen (in), out);

    if (kats[i].out == NULL)
    {
      if (rc == RULE_RC_REJECT_ERROR) { printf ("PASS %s\n", kats[i].rule); continue; }

      printf ("FAIL %s: expected reject, rc=%d\n", kats[i].rule, rc);
      bad++;
      continue;
    }

    if (rc >= 0 && (size_t) rc == strlen (kats[i].out) && memcmp (out, kats[i].out, (size_t) rc) == 0)
    {
      printf ("PASS %s\n", kats[i].rule);
      continue;
    }

    printf ("FAIL %s: %s -> rc=%d '%.*s', expected '%s'\n", kats[i].rule, kats[i].in, rc, rc > 0 ? rc : 0, out, kats[i].out);
    bad++;
  }

  return bad ? 1 : 0;
}
