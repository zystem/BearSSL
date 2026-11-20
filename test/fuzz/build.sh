#!/bin/sh
# Build the fuzzing targets with clang and libFuzzer (AddressSanitizer and
# UndefinedBehaviorSanitizer, which aborts on a finding; the alignment check
# is off because BearSSL does some unaligned reads on purpose on x86, and the
# function-type check is off because the vtables of BearSSL are filled with
# casts of function pointers by design). Usage, from the root of the
# repository:
#   sh test/fuzz/build.sh [outdir]
# Produces outdir/fuzz_client and outdir/fuzz_server (default: build-fuzz).
# CC selects the compiler (default: clang, or clang-18 if that is all there is).
set -e
OUT=${1:-build-fuzz}
if [ -z "$CC" ]; then
	if command -v clang >/dev/null; then CC=clang; else CC=clang-18; fi
fi
mkdir -p "$OUT/obj"
export CC OUT
FL="-g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined,fuzzer-no-link -fno-sanitize=alignment,function -fno-sanitize-recover=undefined -DBR_TLS13_FUZZ -Isrc -Iinc"
export FL
find src -name '*.c' | xargs -P 16 -I{} sh -c '
	f={}
	o="$OUT/obj/$(echo "$f" | tr / _ | sed "s/\.c\$/.o/")"
	if [ ! -f "$o" ] || [ "$f" -nt "$o" ] || [ -n "$(find inc src -name "*.h" -newer "$o" | head -1)" ]; then $CC $FL -c "$f" -o "$o"; fi'
for t in client server; do
	T=$(echo $t | tr a-z A-Z)
	$CC $FL -fsanitize=fuzzer -DFUZZ_$T -Itest/fuzz test/fuzz/fuzz_tls13.c "$OUT"/obj/*.o -static-libstdc++ -static-libgcc -o "$OUT/fuzz_$t"
done
