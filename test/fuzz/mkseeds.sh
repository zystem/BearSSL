#!/bin/sh
# Make the seed corpus of the fuzzing targets: a client engine and a server
# engine run against each other and the records they exchange are written to
# OUTDIR/client/seed-* and OUTDIR/server/seed-* (see seedgen.c). The seeds are
# generated, not stored in the repository. Needs a built tree (make).
#   sh test/fuzz/mkseeds.sh [outdir]      (default: build/seeds)
set -e
OUT=${1:-build/seeds}
CC=${CC:-cc}
mkdir -p "$OUT/client" "$OUT/server"
$CC -O1 -Iinc -Isrc -Itest/fuzz test/fuzz/seedgen.c build/libbearssl.a -o build/seedgen
build/seedgen "$OUT"
