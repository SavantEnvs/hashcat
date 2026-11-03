#!/usr/bin/env bash
#
# mayhem/test.sh — RUNS known-answer checks against what mayhem/build.sh built with normal flags:
#   * rule_selftest: the CPU rule engine (src/rp_cpu.c) applied to known words -> known results
#   * the hashcat CLI, which needs no OpenCL/CUDA device for these: mask keyspace, wordlist keyspace,
#     potfile --show/--left (hash line parsing), --hash-info (module metadata), --example-hashes
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

for f in hashcat rule_selftest libhashcat.so.8 modules/module_00000.so feeds/feed_wordlist.so; do
  [ -e "$SRC/$f" ] || { echo "missing $f: mayhem/build.sh did not build it" >&2; emit_ctrf hashcat-kat 0 1; exit 1; }
done

pass=0; fail=0
check() {  # check <name> <expected> <actual>
  if [ "$2" = "$3" ]; then pass=$((pass+1)); echo "PASS $1"
  else fail=$((fail+1)); echo "FAIL $1: expected [$2] got [$3]"; fi
}

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
H=("$SRC/hashcat" --quiet)

# rule engine
RULE_OUT="$("$SRC/rule_selftest" 2>&1)"
while IFS= read -r line; do
  case "$line" in
    PASS*) pass=$((pass+1)); echo "$line" ;;
    FAIL*) fail=$((fail+1)); echo "$line" ;;
  esac
done <<< "$RULE_OUT"
[ "$(grep -c '^PASS' <<< "$RULE_OUT")" -ge 29 ] || { fail=$((fail+1)); echo "FAIL rule_selftest ran fewer than 29 cases"; }

# mask keyspace: the mask parser and custom charsets
check "keyspace ?d?d?d"            "100"      "$("${H[@]}" --keyspace -a 3 -m 0 '?d?d?d' 2>&1)"
check "keyspace ?l?l?d"            "260"      "$("${H[@]}" --keyspace -a 3 -m 0 '?l?l?d' 2>&1)"
check "keyspace -1 ab ?1?1?1?d"    "40"       "$("${H[@]}" --keyspace -a 3 -m 0 -1 ab '?1?1?1?d' 2>&1)"
check "keyspace ?a x6"             "81450625" "$("${H[@]}" --keyspace -a 3 -m 0 '?a?a?a?a?a?a' 2>&1)"

# wordlist keyspace
printf 'a\nb\nc\n' > "$T/w.txt"
check "keyspace wordlist of 3"     "3"        "$("${H[@]}" --keyspace -a 0 -m 0 "$T/w.txt" 2>&1)"

# hash line parsing + potfile: md5 of "password" is cracked, the other line is not, "nothex" is rejected
printf '5f4dcc3b5aa765d61d8327deb882cf99\n8743b52063cd84097a65d1633f5c74f5\n' > "$T/h.txt"
printf '5f4dcc3b5aa765d61d8327deb882cf99:password\n' > "$T/p.pot"
check "--show cracked line"        "5f4dcc3b5aa765d61d8327deb882cf99:password" \
      "$("${H[@]}" -m 0 --show --potfile-path "$T/p.pot" "$T/h.txt" 2>/dev/null)"
check "--left remaining line"      "8743b52063cd84097a65d1633f5c74f5" \
      "$("${H[@]}" -m 0 --left --potfile-path "$T/p.pot" "$T/h.txt" 2>/dev/null)"
printf 'nothex\n' > "$T/bad.txt"
case "$("${H[@]}" -m 0 --show --potfile-path "$T/p.pot" "$T/bad.txt" 2>&1)" in
  *"Token length exception"*) pass=$((pass+1)); echo "PASS malformed hash rejected" ;;
  *) fail=$((fail+1)); echo "FAIL malformed hash not rejected" ;;
esac
printf 'bob:b4b9b02e6f09a9bd760f388b67351e2b\n' > "$T/n.txt"
printf 'b4b9b02e6f09a9bd760f388b67351e2b:password\n' > "$T/n.pot"
check "--show NTLM --username"      "bob:b4b9b02e6f09a9bd760f388b67351e2b:password" \
      "$("${H[@]}" -m 1000 --username --show --potfile-path "$T/n.pot" "$T/n.txt" 2>/dev/null)"

# module metadata
for m in "0 MD5" "100 SHA1" "1000 NTLM" "1400 SHA2-256" "7400 sha256crypt"; do
  set -- $m
  got="$("${H[@]}" --hash-info -m "$1" 2>&1 | sed -n 's/^  Name\.*: //p')"
  case "$got" in
    *"$2"*) pass=$((pass+1)); echo "PASS hash-info -m $1" ;;
    *)      fail=$((fail+1)); echo "FAIL hash-info -m $1: name [$got] lacks [$2]" ;;
  esac
done
check "example-hashes -m 0 hash"   "8743b52063cd84097a65d1633f5c74f5" \
      "$("${H[@]}" --example-hashes -m 0 2>&1 | sed -n 's/^  Example\.Hash\.*: //p')"
check "example-hashes -m 0 pass"   "hashcat" \
      "$("${H[@]}" --example-hashes -m 0 2>&1 | sed -n 's/^  Example\.Pass\.*: //p')"

emit_ctrf hashcat-kat "$pass" "$fail"
