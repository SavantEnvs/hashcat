#!/usr/bin/env bash
#
# mayhem/build.sh — builds hashcat's in-tree libFuzzer targets (tools/fuzz) sanitized, their
# -standalone reproducers, and (normal flags) the hashcat binary + rule selftest that test.sh runs.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export CC CXX

cd "$SRC"

# Parser targets: one per hash mode (tools/fuzz/build.sh links one module per binary).
MODES="07400 17225 22000 40056"
TARGETS="fuzz_rule fuzz_tokenizer fuzz_recipe fuzz_mask"
for m in $MODES; do TARGETS="$TARGETS fuzz_parse_$((10#$m))"; done

STAGE="${TMPDIR:-/tmp}/hashcat-fuzz-stage"
rm -rf "$STAGE"; mkdir -p "$STAGE"

# Leak detection off (SPEC §6.2 item 15), compiled with the sanitizer flags, linked into every binary.
# shellcheck disable=SC2086
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$STAGE/lsan_off.o"
# shellcheck disable=SC2086
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$STAGE/standalone_main.o"

# The source list and the include/define set are tools/fuzz/build.sh's (upstream's own recipe, which
# compiles serially: ~13 min here), so a change upstream makes to its target set is followed.
# What differs is only parallelism and the flags.
eval "$(sed -n '/^CORE="/{:a;p;/"$/q;n;ba}' tools/fuzz/build.sh)"
[ -n "${CORE:-}" ] || { echo "could not read CORE from tools/fuzz/build.sh" >&2; exit 1; }
CORE="$CORE $(ls src/emu_*.c)"
CORE="${CORE//tools\/fuzz\/stubs.c/mayhem\/stubs_compat.c}"
INCLUDES="-Iinclude/ -IOpenCL/ -Ideps/OpenCL-Headers -Itools/asan"
ABI=$(sed -n 's/^MODULE_INTERFACE_VERSION *:*= *\([0-9]*\).*/\1/p' src/Makefile | head -1)
[ -n "$ABI" ] || { echo "no MODULE_INTERFACE_VERSION in src/Makefile" >&2; exit 1; }
DEFINES="-DWITH_BRAIN -DWITH_HWMON -DHC_PLUGIN_ABI_VERSION=${ABI} -DMODULE_INTERFACE_VERSION_CURRENT=${ABI}"

# build_variant <name> <compile flags> <link input>   -> $STAGE/<name>/<target>
build_variant() {
  local v="$1" cflags="$2" engine="$3" w="$STAGE/$1" t m n objs="" jobs="$STAGE/$1.jobs"
  mkdir -p "$w"; : > "$jobs"
  for f in $CORE; do
    [ -f "$f" ] || continue
    echo "$CC $cflags -std=gnu99 $INCLUDES $DEFINES -c $f -o $w/$(basename "$f" .c).o" >> "$jobs"
    objs="$objs $w/$(basename "$f" .c).o"
  done
  for t in rule tokenizer recipe mask; do
    echo "$CC $cflags -std=gnu99 $INCLUDES $DEFINES -c tools/fuzz/fuzz_$t.c -o $w/fuzz_$t.o" >> "$jobs"
  done
  echo "$CC $cflags -std=gnu99 $INCLUDES $DEFINES -DHC_CORE_BUILD -c src/mpsp.c -o $w/mpsp.o" >> "$jobs"
  for m in $MODES; do
    n=$((10#$m))
    echo "$CC $cflags -std=gnu99 $INCLUDES $DEFINES -DFUZZ_HASH_MODE=$n -c tools/fuzz/fuzz_parse.c -o $w/fuzz_parse_$n.o" >> "$jobs"
    echo "$CC $cflags -std=gnu99 $INCLUDES $DEFINES -c src/modules/module_$m.c -o $w/module_$m.o" >> "$jobs"
  done
  xargs -P "$MAYHEM_JOBS" -I{} sh -c '{}' < "$jobs"

  : > "$jobs"
  for t in rule tokenizer recipe; do
    echo "$CXX $cflags $w/fuzz_$t.o $objs $engine -o $w/fuzz_$t" >> "$jobs"
  done
  echo "$CXX $cflags $w/fuzz_mask.o $w/mpsp.o $objs $engine -o $w/fuzz_mask" >> "$jobs"
  for m in $MODES; do
    n=$((10#$m))
    echo "$CXX $cflags $w/fuzz_parse_$n.o $w/module_$m.o $objs $engine -o $w/fuzz_parse_$n" >> "$jobs"
  done
  xargs -P "$MAYHEM_JOBS" -I{} sh -c '{}' < "$jobs"
}

# 1) libFuzzer binaries. The project is compiled with $SANITIZER_FLAGS + DWARF<=3, plus SanCov
#    instrumentation (fuzzer-no-link) so the library code has edges.
build_variant fuzz "$SANITIZER_FLAGS -O1 -fsanitize=fuzzer-no-link $DEBUG_FLAGS" \
  "$LIB_FUZZING_ENGINE $STAGE/lsan_off.o"

# 2) standalone (run-once) reproducers: same sources, the LLVM standalone driver instead of libFuzzer.
build_variant sa "$SANITIZER_FLAGS -O1 $DEBUG_FLAGS" "$STAGE/standalone_main.o $STAGE/lsan_off.o"

for t in $TARGETS; do
  cp "$STAGE/fuzz/$t" "$SRC/$t"
  cp "$STAGE/sa/$t" "$SRC/$t-standalone"
done
rm -rf "$STAGE"

# 3) The functional oracle, with the project's NORMAL flags (the Makefile's own gcc build, portable
#    -march): the hashcat binary, the few plugins test.sh drives, and a rule-engine selftest.
env -u CFLAGS -u LDFLAGS -u CC -u CXX make -j"$MAYHEM_JOBS" MARCH_NATIVE= hashcat \
  modules/module_00000.so modules/module_00100.so modules/module_01000.so \
  modules/module_01400.so modules/module_07400.so feeds/feed_wordlist.so
ABI=$(sed -n 's/^MODULE_INTERFACE_VERSION *:*= *\([0-9]*\).*/\1/p' src/Makefile | head -1)
# shellcheck disable=SC2086
gcc -O2 $COVERAGE_FLAGS -Iinclude -IOpenCL -Ideps/OpenCL-Headers -DHC_PLUGIN_ABI_VERSION="$ABI" \
  mayhem/rule_selftest.c libhashcat.so.8 -Wl,-rpath,"$SRC" -o "$SRC/rule_selftest"
