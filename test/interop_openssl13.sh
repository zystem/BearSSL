#!/bin/sh
# Interoperability check of the TLS 1.3 client (build/brssl) against
# "openssl s_server". Needs openssl (3.x) and a built tree. Usage:
#   sh test/interop_openssl13.sh [path/to/brssl]
# Prints one line per case and exits with 0 if all pass.
# The port is below 32768 (outside the ephemeral range), see the notes in
# TLS13-PLAN.md.

BRSSL=${1:-build/brssl}
PORT=${PORT:-14443}
DIR=$(mktemp -d)
SRV=""
trap 'kill $SRV 2>/dev/null; [ -n "$KEEP" ] || rm -rf "$DIR"; [ -z "$KEEP" ] || echo "kept $DIR"' EXIT INT TERM
fail=0

mk() { # name, key spec...
	n=$1; shift
	openssl req -x509 -newkey "$@" -nodes -keyout "$DIR/$n.key" \
		-out "$DIR/$n.crt" -days 2 -subj /CN=localhost \
		-addext subjectAltName=DNS:localhost 2>/dev/null
}
mk ec ec -pkeyopt ec_paramgen_curve:prime256v1
mk p384 ec -pkeyopt ec_paramgen_curve:secp384r1
mk rsa rsa:2048
head -c 200000 /dev/urandom | base64 -w0 | head -c 200000 > "$DIR/big.txt"

# case NAME CERT SUITE ALPN SERVER-GROUPS
case_() {
	grp=""
	[ -n "$5" ] && grp="-groups $5"
	( cd "$DIR" && exec openssl s_server -accept $PORT -cert $2.crt \
		-key $2.key -WWW -quiet -alpn h2,http/1.1 $grp \
		>srv.log 2>&1 ) &
	SRV=$!
	sleep 1
	opts="-vmax tls13 -sni localhost -CA $DIR/$2.crt"
	[ -n "$3" ] && opts="$opts -cs $3"
	[ -n "$4" ] && opts="$opts -alpn $4"
	( printf 'GET /big.txt HTTP/1.0\r\n\r\n'; sleep 2 ) | \
		timeout 30 "$BRSSL" client 127.0.0.1:$PORT $opts \
		> "$DIR/out.txt" 2>&1
	ok=1
	grep -q "version:  *TLS 1.3" "$DIR/out.txt" || ok=0
	python3 - "$DIR" <<'PY' || ok=0
import sys
d = open(sys.argv[1] + "/out.txt", "rb").read()
want = open(sys.argv[1] + "/big.txt", "rb").read()
sys.exit(0 if want in d else 1)
PY
	if [ -n "$4" ]; then
		grep -q "ALPN): *$4" "$DIR/out.txt" || ok=0
	fi
	if [ $ok = 1 ]; then echo "ok    $1"; else echo "FAIL  $1"; fail=1; fi
	kill $SRV 2>/dev/null
	sleep 1
}

case_ "ecdsa-p256 aes128" ec TLS13_AES_128_GCM_SHA256 ""
case_ "ecdsa-p256 aes256" ec TLS13_AES_256_GCM_SHA384 ""
case_ "ecdsa-p256 chacha" ec TLS13_CHACHA20_POLY1305_SHA256 ""
case_ "ecdsa-p384 aes128" p384 TLS13_AES_128_GCM_SHA256 ""
case_ "rsa-pss aes128" rsa TLS13_AES_128_GCM_SHA256 ""
case_ "rsa-pss aes256" rsa TLS13_AES_256_GCM_SHA384 ""
case_ "alpn h2" ec "" h2
# HelloRetryRequest: the server accepts neither of our first share (X25519)
case_ "hello retry P-256" ec "" "" P-256
case_ "hello retry P-384" ec "" "" P-384
case_ "hello retry P-521" ec "" "" P-521
exit $fail
