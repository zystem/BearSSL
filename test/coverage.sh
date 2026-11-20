#!/bin/sh
# Line coverage of src/ (gcov) by the tests that need nothing but a C compiler
# and openssl: testcrypto, testx509 and the OpenSSL interoperability script.
# Usage: sh test/coverage.sh        (MIN=80 is the lowest accepted percentage)
# Builds in build-cov/ (ignored by git), prints the total, exits 1 below MIN.
set -e
export LC_ALL=C
MIN=${MIN:-80}
cd "$(dirname "$0")/.."
rm -rf build-cov
make BUILD=build-cov CFLAGS="-W -Wall -O0 -fPIC --coverage" \
	LDFLAGS="--coverage" >/dev/null
build-cov/testcrypto all >/dev/null
build-cov/testx509 >/dev/null
sh test/interop_openssl13.sh build-cov/brssl >/dev/null
cd build-cov/obj
gcov -n *.gcda 2>/dev/null | awk -v min="$MIN" '
	/^File/ { f = $2 }
	/^Lines executed/ {
		split($2, a, ":"); p = substr(a[2], 1, length(a[2]) - 1) + 0
		n = $4 + 0
		if (f ~ /src\//) { tot += n; ex += n * p / 100 }
	}
	END {
		pc = 100 * ex / tot
		printf "src/: %d lines, %.0f run, %.1f%%\n", tot, ex, pc
		exit (pc < min)
	}'
