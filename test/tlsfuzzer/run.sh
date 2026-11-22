#!/bin/sh
# Runs scripts of tlsfuzzer (https://github.com/tlsfuzzer/tlsfuzzer) against the
# TLS 1.3 server of this tree. Needs git, python3 (with venv), a C compiler,
# network access (it fetches tlsfuzzer, tlslite-ng and the python package
# ecdsa) and a built tree (make). Usage:
#
#   sh test/tlsfuzzer/run.sh [workdir]       the scripts that must pass
#   ALL=1 sh test/tlsfuzzer/run.sh [workdir] every TLS 1.3 script, a table
#
# The first form exits with 0 if every script in GATE passes (apart from the
# probes listed as expected failures: they test X448, which is not
# implemented). The second form only prints the table; most of what fails
# there is a feature that is not implemented, or a connection that is closed
# without the alert that tlsfuzzer expects (docs/conformance.md).
# The port is below 32768, outside the ephemeral range.

TLSFUZZER=51aad6e9ae42f5b045fa9b76129fe0746631784d
TLSLITE=7e95ea1a86c0d42d8d931ff14134d31f01ce1d76
PORT=${PORT:-14433}
GATE="conversation count-tickets finished hrr invalid-ciphers large-number-of-extensions lengths nociphers pkcs-signature record-padding rsa-signatures unencrypted-alert ecdhe-curves"

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
W=${1:-$(mktemp -d)}
SRV=""
trap '[ -z "$SRV" ] || kill $SRV 2>/dev/null' EXIT INT TERM

[ -f "$ROOT/build/libbearssl.a" ] || { echo "build the library first (make)"; exit 2; }
if ss -ltn 2>/dev/null | grep -q ":$PORT "; then
	echo "port $PORT is in use"; exit 2
fi
mkdir -p "$W" || exit 2
if [ ! -d "$W/tlsfuzzer" ]; then
	git clone -q https://github.com/tlsfuzzer/tlsfuzzer.git "$W/tlsfuzzer" &&
	git -C "$W/tlsfuzzer" checkout -q $TLSFUZZER || exit 2
fi
if [ ! -d "$W/tlslite-ng" ]; then
	git clone -q https://github.com/tlsfuzzer/tlslite-ng.git "$W/tlslite-ng" &&
	git -C "$W/tlslite-ng" checkout -q $TLSLITE || exit 2
fi
if [ ! -d "$W/venv" ]; then
	python3 -m venv "$W/venv" && "$W/venv/bin/pip" -q install ecdsa==0.19.2 || exit 2
fi
cc -DWITH_TLS13 -DSERVER_RSA=1 -I"$ROOT/inc" -I"$ROOT/samples" \
	-o "$W/server" "$HERE/server.c" "$ROOT/build/libbearssl.a" || exit 2
"$W/server" $PORT >"$W/server.log" 2>&1 &
SRV=$!
sleep 1

run() { # script, extra arguments
	n=$1; shift
	( cd "$W/tlsfuzzer" && PYTHONPATH=.:../tlslite-ng timeout 900 \
		../venv/bin/python scripts/test-tls13-$n.py -h localhost -p $PORT "$@" \
		>"$W/$n.out" 2>&1 )
	rc=$?
	echo "$n rc=$rc $(grep -E '^(TOTAL|PASS|FAIL):' "$W/$n.out" | tr '\n' ' ')"
	[ $rc -eq 0 ] || sed -n '/^FAILED/,$p' "$W/$n.out" | head -12
	return $rc
}

fail=0
if [ -n "$ALL" ]; then
	for f in "$W"/tlsfuzzer/scripts/test-tls13-*.py; do
		n=${f##*/test-tls13-}; n=${n%.py}
		run $n
	done
	exit 0
fi
for n in $GATE; do
	if [ $n = ecdhe-curves ]; then
		run $n -x "sanity - x448" -x "x448 - key share from other curve" \
			-x "x448 - point at infinity" -x "x448 - right 0-padded key_share" \
			-x "x448 - right-truncated key_share" || fail=1
	elif [ $n = finished ]; then
		# The probes that send a Finished message padded with 196 608 bytes
		# and with 16 MB fail now and then (about one run in eight): the
		# server sends the alert and the python client, which needs minutes
		# for that much data, sometimes does not read it. The cause was not
		# found; the probes stay out of the gate.
		run $n \
			-e "padding - cipher TLS_AES_128_GCM_SHA256, pad_byte 0, pad_left 0, pad_right 196608" \
			-e "padding - cipher TLS_AES_256_GCM_SHA384, pad_byte 0, pad_left 0, pad_right 196608" \
			-e "padding - cipher TLS_AES_128_GCM_SHA256, pad_byte 0, pad_left 0, pad_right 16777183" \
			-e "padding - cipher TLS_AES_256_GCM_SHA384, pad_byte 0, pad_left 0, pad_right 16777167" || fail=1
	else
		run $n || fail=1
	fi
done
[ $fail -eq 0 ] && echo "tlsfuzzer: ok"
exit $fail
