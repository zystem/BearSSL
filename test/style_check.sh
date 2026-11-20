#!/bin/sh
# The coding standard (CONTRIBUTING.md) for the C files this fork added: tabs
# for indentation (a space is allowed only before the "*" of a comment), no
# trailing white space, no line over 100 columns once a tab counts 8.
# The files taken from upstream are not checked: they have 326 files with
# trailing white space and upstream never enforced it.
# Usage: sh test/style_check.sh      exit 0 if all is well
cd "$(dirname "$0")/.." || exit 2
FILES="inc/bearssl_tls13.h src/ssl/ssl_rec13_*.c \
src/ssl/ssl_tls13_*.c test/fuzz/*.c test/resume_client.c test/bench_handshake.c"
fail=0
for f in $FILES; do
	[ -f "$f" ] || { echo "missing: $f"; fail=1; continue; }
	if grep -n -E '^ +[^ *]' "$f" | head -3 | grep .; then
		echo "$f: indented with spaces"; fail=1
	fi
	if grep -n -E '[ 	]+$' "$f" | head -3 | grep .; then
		echo "$f: trailing white space"; fail=1
	fi
	if expand "$f" | awk 'length($0) > 100 { print FILENAME ":" NR; bad = 1 } END { exit bad }' | head -3 | grep .; then
		echo "$f: line longer than 100 columns"; fail=1
	fi
done
[ $fail -eq 0 ] && echo "style: ok"
exit $fail
