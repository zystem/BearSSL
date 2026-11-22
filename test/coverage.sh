#!/bin/sh
# Coverage of src/ (gcov) by testcrypto, testx509 and the interoperability
# scripts (the peers that are installed: openssl, and gnutls and go if there).
# Usage: sh test/coverage.sh
#   MIN=80      lowest accepted percentage of the lines of the whole of src/
#   MIN13=90    lowest accepted percentage of the lines of the TLS 1.3 C files
#   MINB13=65   lowest accepted percentage of the branches of the TLS 1.3 C files
# The TLS 1.3 C code is src/ssl/ssl_tls13_*.c and src/ssl/ssl_rec13_*.c; a
# branch counts when it was taken at least once. The handshake itself is
# written in T0 and compiled to a table that gcov cannot see into: the
# handshake paths are covered by the tests (loopback, tamper, session, HRR)
# and by the interop scripts, not by a number.
# Builds in build-cov/ (ignored by git), prints the numbers, exits 1 below a
# floor.
set -e
export LC_ALL=C
MIN=${MIN:-80}
MIN13=${MIN13:-90}
MINB13=${MINB13:-65}
cd "$(dirname "$0")/.."
rm -rf build-cov
make BUILD=build-cov CFLAGS="-W -Wall -O0 -fPIC --coverage" \
	LDFLAGS="--coverage" >/dev/null
build-cov/testcrypto all >/dev/null
build-cov/testx509 >/dev/null
sh test/interop_openssl13.sh build-cov/brssl >/dev/null
sh test/interop_server13.sh build-cov/brssl >/dev/null
cd build-cov/obj
gcov -b -n *.gcda 2>/dev/null | awk -v min="$MIN" -v min13="$MIN13" \
	-v minb13="$MINB13" '
	/^File/ { f = $2; gsub(/\047/, "", f) }
	/^Lines executed/ {
		split($2, a, ":"); p = substr(a[2], 1, length(a[2]) - 1) + 0
		n = $4 + 0
		if (f ~ /^src\//) { tot += n; ex += n * p / 100 }
		if (f ~ /ssl_tls13_|ssl_rec13_/) {
			l13 += n; e13 += n * p / 100
			c13[f] = p; n13[f] = n
		}
	}
	/^Taken at least once/ {
		split($0, a, ":"); split(a[2], q, "%"); p = q[1] + 0
		n = $NF + 0
		if (f ~ /ssl_tls13_|ssl_rec13_/) {
			bt += n; be += n * p / 100
			b13[f] = p
		}
	}
	END {
		pc = 100 * ex / tot
		printf "src/: %d lines, %.0f run, %.1f%%\n", tot, ex, pc
		for (f in c13) {
			printf "  %-28s lines %5.1f%% of %d, branches %5.1f%%\n", f, c13[f], n13[f], b13[f]
		}
		p13 = 100 * e13 / l13
		pb = 100 * be / bt
		printf "TLS 1.3 C files: %d lines, %.1f%%\n", l13, p13
		printf "TLS 1.3 C files: %.1f%% of %d branches taken at least once\n", pb, bt
		bad = 0
		if (pc < min) { print "FAIL: lines of src/ below " min "%"; bad = 1 }
		if (p13 < min13) { print "FAIL: lines of the TLS 1.3 code below " min13 "%"; bad = 1 }
		if (pb < minb13) { print "FAIL: branches of the TLS 1.3 C files below " minb13 "%"; bad = 1 }
		exit bad
	}'
