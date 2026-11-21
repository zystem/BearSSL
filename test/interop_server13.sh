#!/bin/sh
# Interoperability of the TLS 1.3 server and client (build/brssl) with
# other implementations: OpenSSL (s_client, s_server), GnuTLS (gnutls-cli,
# gnutls-serv) and Go (programs in test/interop_go). A peer that is not
# installed is skipped (and the script says so), unless it is named in
# REQUIRE (for example REQUIRE="openssl gnutls go"): then it is a failure.
# A Go program that is installed but does not build is always a failure.
# EXPECT=n makes the script fail if it did not run exactly n cases.
# Usage: sh test/interop_server13.sh [path/to/brssl]
# Ports are below 32768 (outside the ephemeral range). The script stops only
# the processes that it started (by their process id).

BRSSL=${1:-build/brssl}
HERE=$(cd "$(dirname "$0")" && pwd)
PORT=${PORT:-14445}
PORT2=$((PORT + 1))
DIR=$(mktemp -d)
trap 'pkill -P $$ 2>/dev/null; rm -rf "$DIR"' EXIT INT TERM
fail=0
cases=0
skipped=""
SRV=""
BG=""
PRI="NORMAL:-VERS-ALL:+VERS-TLS1.3"

mk() {
	n=$1; shift
	openssl req -x509 -newkey "$@" -nodes -keyout "$DIR/$n.key" \
		-out "$DIR/$n.crt" -days 2 -subj /CN=localhost \
		-addext subjectAltName=DNS:localhost 2>/dev/null
}
mk ec ec -pkeyopt ec_paramgen_curve:prime256v1
mk p384 ec -pkeyopt ec_paramgen_curve:secp384r1
mk rsa rsa:2048
mk p521 ec -pkeyopt ec_paramgen_curve:secp521r1
mk cp521 ec -pkeyopt ec_paramgen_curve:secp521r1
mk cec ec -pkeyopt ec_paramgen_curve:prime256v1
mk crsa rsa:2048

report() { # name ok
	cases=$((cases + 1))
	if [ "$2" = 1 ]; then echo "ok    $1"; else echo "FAIL  $1"; fail=1; fi
}

# A peer is missing: a failure if it is required, else a note at the end.
missing() { # name
	case " $REQUIRE " in
	*" $1 "*) echo "FAIL  $1 is required and not installed"; fail=1;;
	*) skipped="$skipped $1";;
	esac
}
command -v openssl >/dev/null || missing openssl
command -v gnutls-cli >/dev/null && command -v gnutls-serv >/dev/null || missing gnutls
command -v go >/dev/null || missing go

# Our server, started with a stdin that stays open and ends with a reply.
start_server() { # server args
	( sleep 4; echo "pong-from-bear" ) 2>/dev/null | "$BRSSL" \
		server -p $PORT -vmax tls13 "$@" >"$DIR/bs.log" 2>&1 &
	SRV=$!
	sleep 1
}
stop_server() { kill $SRV >/dev/null 2>&1; { wait; } 2>/dev/null; sleep 1; }

# Client of another implementation against our server: the client sends
# "ping" and must receive "pong-from-bear"; the server must print the ping.
check_server_run() { # name client-output-file
	ok=1
	grep -q "ping-from-peer" "$DIR/bs.log" || ok=0
	grep -q "pong-from-bear" "$2" || ok=0
	report "$1" $ok
}

if command -v openssl >/dev/null; then
	for c in "ecdsa-p256|ec|" "ecdsa-p384|p384|" "rsa-pss|rsa|" \
		"mTLS ecdsa|ec|-cert $DIR/cec.crt -key $DIR/cec.key" \
		"mTLS rsa-pss|ec|-cert $DIR/crsa.crt -key $DIR/crsa.key"; do
		name=${c%%|*}; rest=${c#*|}; cert=${rest%%|*}; cl=${rest#*|}
		ca=""
		case "$name" in
		"mTLS ecdsa") ca="-CA $DIR/cec.crt";;
		"mTLS rsa-pss") ca="-CA $DIR/crsa.crt";;
		esac
		start_server -cert "$DIR/$cert.crt" -key "$DIR/$cert.key" $ca
		( sleep 0.4; echo ping-from-peer; sleep 3.3 ) | timeout 15 \
			openssl s_client -connect 127.0.0.1:$PORT -tls1_3 -brief \
			-CAfile "$DIR/$cert.crt" $cl >"$DIR/p.log" 2>&1
		check_server_run "openssl client -> bear server, $name" "$DIR/p.log"
		stop_server
	done
	# HelloRetryRequest from our server: the client offers X448 first
	start_server -cert "$DIR/ec.crt" -key "$DIR/ec.key"
	( sleep 0.4; echo ping-from-peer; sleep 3.3 ) | timeout 15 \
		openssl s_client -connect 127.0.0.1:$PORT -tls1_3 -brief \
		-CAfile "$DIR/ec.crt" -groups X448:P-256 >"$DIR/p.log" 2>&1
	check_server_run "openssl client -> bear server, HelloRetryRequest" "$DIR/p.log"
	stop_server
fi

if command -v gnutls-cli >/dev/null; then
	for c in "ecdsa-p256|ec|" "rsa-pss|rsa|" \
		"mTLS ecdsa|ec|--x509certfile $DIR/cec.crt --x509keyfile $DIR/cec.key" \
		"mTLS rsa-pss|ec|--x509certfile $DIR/crsa.crt --x509keyfile $DIR/crsa.key"; do
		name=${c%%|*}; rest=${c#*|}; cert=${rest%%|*}; cl=${rest#*|}
		ca=""
		case "$name" in
		"mTLS ecdsa") ca="-CA $DIR/cec.crt";;
		"mTLS rsa-pss") ca="-CA $DIR/crsa.crt";;
		esac
		start_server -cert "$DIR/$cert.crt" -key "$DIR/$cert.key" $ca
		( sleep 0.4; echo ping-from-peer; sleep 3.3 ) | timeout 15 \
			gnutls-cli --priority "$PRI" -p $PORT localhost \
			--x509cafile "$DIR/$cert.crt" $cl >"$DIR/p.log" 2>&1
		check_server_run "gnutls client -> bear server, $name" "$DIR/p.log"
		stop_server
	done
fi

if command -v go >/dev/null; then
	( cd "$HERE/interop_go" && go build -o "$DIR/goclient" ./goclient \
		&& go build -o "$DIR/goserver" ./goserver ) \
		|| { echo "FAIL  go is installed and the programs do not build"; fail=1; }
fi
if [ -x "$DIR/goclient" ]; then
	for c in "ecdsa-p256|ec|" "ecdsa-p384|p384|" "rsa-pss|rsa|" \
		"mTLS ecdsa|ec|-cert $DIR/cec.crt -key $DIR/cec.key" \
		"mTLS rsa-pss|ec|-cert $DIR/crsa.crt -key $DIR/crsa.key"; do
		name=${c%%|*}; rest=${c#*|}; cert=${rest%%|*}; cl=${rest#*|}
		ca=""
		case "$name" in
		"mTLS ecdsa") ca="-CA $DIR/cec.crt";;
		"mTLS rsa-pss") ca="-CA $DIR/crsa.crt";;
		esac
		start_server -cert "$DIR/$cert.crt" -key "$DIR/$cert.key" $ca
		"$DIR/goclient" -addr 127.0.0.1:$PORT -ca "$DIR/$cert.crt" $cl \
			>"$DIR/p.log" 2>&1
		ok=1
		grep -q "version=304" "$DIR/p.log" || ok=0
		grep -q 'received "pong-from-bear' "$DIR/p.log" || ok=0
		grep -q "ping-from-go" "$DIR/bs.log" || ok=0
		report "go client -> bear server, $name" $ok
		stop_server
	done
	# Our client against the Go server
	for c in "ecdsa-p256|ec||" "rsa-pss cert|rsa||" \
		"HelloRetryRequest to P-384|ec|-curve p384|" \
		"mTLS ecdsa|ec||cec" "mTLS rsa-pss|ec||crsa" \
		"mTLS after HelloRetryRequest|ec|-curve p384|cec"; do
		name=${c%%|*}; rest=${c#*|}; cert=${rest%%|*}; rest=${rest#*|}
		extra=${rest%%|*}; cc=${rest#*|}
		sa=""; ca=""
		if [ -n "$cc" ]; then
			sa="-ca $DIR/$cc.crt"
			ca="-cert $DIR/$cc.crt -key $DIR/$cc.key"
		fi
		"$DIR/goserver" -addr 127.0.0.1:$PORT2 -cert "$DIR/$cert.crt" \
			-key "$DIR/$cert.key" $extra $sa >"$DIR/gs.log" 2>&1 &
		BG=$!
		sleep 1
		( echo ping-from-bear; sleep 1.5 ) | timeout 15 "$BRSSL" client \
			127.0.0.1:$PORT2 -sni localhost -vmax tls13 \
			-CA "$DIR/$cert.crt" $ca >"$DIR/p.log" 2>&1
		ok=1
		grep -q "TLS 1.3" "$DIR/p.log" || ok=0
		grep -q "ping-from-bear" "$DIR/p.log" || ok=0
		report "bear client -> go server, $name" $ok
		kill $BG >/dev/null 2>&1; { wait; } 2>/dev/null; sleep 0.5
	done
fi

if command -v gnutls-serv >/dev/null; then
	for c in "ecdsa-p256|ec|" "rsa-pss cert|rsa|" "mTLS ecdsa|ec|cec" \
		"mTLS rsa-pss|ec|crsa"; do
		name=${c%%|*}; rest=${c#*|}; cert=${rest%%|*}; cc=${rest#*|}
		sa=""; ca=""
		if [ -n "$cc" ]; then
			sa="--require-client-cert --x509cafile $DIR/$cc.crt"
			ca="-cert $DIR/$cc.crt -key $DIR/$cc.key"
		fi
		gnutls-serv --port $PORT2 --priority "$PRI" \
			--x509certfile "$DIR/$cert.crt" \
			--x509keyfile "$DIR/$cert.key" $sa >"$DIR/gu.log" 2>&1 &
		BG=$!
		sleep 3
		( echo ping-from-bear; sleep 1.5 ) | timeout 15 "$BRSSL" client \
			127.0.0.1:$PORT2 -sni localhost -vmax tls13 \
			-CA "$DIR/$cert.crt" $ca >"$DIR/p.log" 2>&1
		ok=1
		grep -q "TLS 1.3" "$DIR/p.log" || ok=0
		report "bear client -> gnutls server, $name" $ok
		kill $BG >/dev/null 2>&1; { wait; } 2>/dev/null; sleep 1
	done
fi

# Session resumption (TLS 1.3 tickets): the client connects twice.
if command -v openssl >/dev/null; then
	start_server -cert "$DIR/ec.crt" -key "$DIR/ec.key" -cache 8192
	( sleep 0.4; echo hi; sleep 1 ) | timeout 15 openssl s_client \
		-connect 127.0.0.1:$PORT -tls1_3 -CAfile "$DIR/ec.crt" \
		-sess_out "$DIR/sess.pem" >"$DIR/p1.log" 2>&1
	( sleep 0.4; echo hi; sleep 1 ) | timeout 15 openssl s_client \
		-connect 127.0.0.1:$PORT -tls1_3 -CAfile "$DIR/ec.crt" \
		-sess_in "$DIR/sess.pem" >"$DIR/p2.log" 2>&1
	ok=1
	grep -q "^New, TLSv1.3" "$DIR/p1.log" || ok=0
	grep -q "^Reused, TLSv1.3" "$DIR/p2.log" || ok=0
	report "openssl client resumes a session of the bear server" $ok
	stop_server
fi
if [ -x "$DIR/goclient" ]; then
	start_server -cert "$DIR/ec.crt" -key "$DIR/ec.key" -cache 8192
	"$DIR/goclient" -addr 127.0.0.1:$PORT -ca "$DIR/ec.crt" -resume \
		>"$DIR/p.log" 2>&1
	ok=1
	grep -q "connection 2: .*resumed=true" "$DIR/p.log" || ok=0
	report "go client resumes a session of the bear server" $ok
	stop_server
fi
if command -v gnutls-cli >/dev/null; then
	start_server -cert "$DIR/ec.crt" -key "$DIR/ec.key" -cache 8192
	( sleep 0.4; echo hi; sleep 3 ) | timeout 15 gnutls-cli \
		--priority "$PRI" -p $PORT localhost --x509cafile "$DIR/ec.crt" \
		--resume >"$DIR/p.log" 2>&1
	ok=1
	grep -q "Resume Handshake was completed" "$DIR/p.log" || ok=0
	report "gnutls client resumes a session of the bear server" $ok
	stop_server
fi

# KeyUpdate: our engine changes its sending key every 2 records (-ku 2); the
# peer must read all the lines that follow the updates.
if command -v openssl >/dev/null; then
	( sleep 1; for i in 1 2 3 4 5 6 7 8; do echo "ku-line-$i"; sleep 0.3; done; \
		sleep 2 ) 2>/dev/null | "$BRSSL" server -p $PORT -vmax tls13 -ku 2 \
		-cert "$DIR/ec.crt" -key "$DIR/ec.key" >"$DIR/bs.log" 2>&1 &
	SRV=$!
	sleep 1
	( sleep 6 ) | timeout 15 openssl s_client -connect 127.0.0.1:$PORT \
		-tls1_3 -CAfile "$DIR/ec.crt" >"$DIR/p.log" 2>&1
	ok=1
	for i in 1 2 3 4 5 6 7 8; do grep -q "^ku-line-$i" "$DIR/p.log" || ok=0; done
	report "bear server changes its key every 2 records, openssl client reads on" $ok
	stop_server
	( cd "$DIR" && exec openssl s_server -accept $PORT2 -cert ec.crt \
		-key ec.key -quiet -rev >srv.log 2>&1 ) &
	BG=$!
	sleep 1
	( sleep 0.5; for i in 1 2 3 4 5 6 7 8; do echo "ku-line-$i"; sleep 0.3; done; \
		sleep 1 ) | timeout 15 "$BRSSL" client 127.0.0.1:$PORT2 -sni localhost \
		-vmax tls13 -ku 2 -CA "$DIR/ec.crt" >"$DIR/p.log" 2>&1
	ok=1
	# s_server -rev sends each line back, reversed
	for i in 1 2 3 4 5 6 7 8; do grep -q "$i-enil-uk" "$DIR/p.log" || ok=0; done
	report "bear client changes its key every 2 records, openssl server reads on" $ok
	kill $BG >/dev/null 2>&1; { wait; } 2>/dev/null
fi
if command -v gnutls-cli >/dev/null; then
	( sleep 1; for i in 1 2 3 4 5 6 7 8; do echo "ku-line-$i"; sleep 0.3; done; \
		sleep 2 ) 2>/dev/null | "$BRSSL" server -p $PORT -vmax tls13 -ku 2 \
		-cert "$DIR/ec.crt" -key "$DIR/ec.key" >"$DIR/bs.log" 2>&1 &
	SRV=$!
	sleep 1
	( sleep 6 ) | timeout 15 gnutls-cli --priority "$PRI" -p $PORT localhost \
		--x509cafile "$DIR/ec.crt" >"$DIR/p.log" 2>&1
	ok=1
	for i in 1 2 3 4 5 6 7 8; do grep -q "ku-line-$i" "$DIR/p.log" || ok=0; done
	report "bear server changes its key every 2 records, gnutls client reads on" $ok
	stop_server
fi

# The schemes with SHA-512 (ECDSA P-521, RSA-PSS), in the three roles that
# verify or make a signature: our server signs, our client verifies the
# server, our server verifies a client certificate.
if command -v openssl >/dev/null; then
	start_server -cert "$DIR/p521.crt" -key "$DIR/p521.key"
	( sleep 0.4; echo ping-from-peer; sleep 3.3 ) | timeout 15 openssl s_client \
		-connect 127.0.0.1:$PORT -tls1_3 -brief -CAfile "$DIR/p521.crt" \
		-sigalgs ecdsa_secp521r1_sha512 >"$DIR/p.log" 2>&1
	check_server_run "openssl client -> bear server, ecdsa-p521 (sha512)" "$DIR/p.log"
	stop_server
	start_server -cert "$DIR/rsa.crt" -key "$DIR/rsa.key"
	( sleep 0.4; echo ping-from-peer; sleep 3.3 ) | timeout 15 openssl s_client \
		-connect 127.0.0.1:$PORT -tls1_3 -brief -CAfile "$DIR/rsa.crt" \
		-sigalgs rsa_pss_rsae_sha512 >"$DIR/p.log" 2>&1
	check_server_run "openssl client -> bear server, rsa-pss sha512" "$DIR/p.log"
	stop_server
	start_server -cert "$DIR/ec.crt" -key "$DIR/ec.key" -CA "$DIR/cp521.crt"
	( sleep 0.4; echo ping-from-peer; sleep 3.3 ) | timeout 15 openssl s_client \
		-connect 127.0.0.1:$PORT -tls1_3 -brief -CAfile "$DIR/ec.crt" \
		-cert "$DIR/cp521.crt" -key "$DIR/cp521.key" \
		-client_sigalgs ecdsa_secp521r1_sha512 >"$DIR/p.log" 2>&1
	check_server_run "openssl client -> bear server, client ecdsa-p521 (sha512)" "$DIR/p.log"
	stop_server
	( cd "$DIR" && exec openssl s_server -accept $PORT2 -cert ec.crt \
		-key ec.key -www -quiet -Verify 1 -CAfile cp521.crt \
		-verify_return_error >srv.log 2>&1 ) &
	BG=$!
	sleep 1
	( echo ping-from-bear; sleep 1.5 ) | timeout 15 "$BRSSL" client \
		127.0.0.1:$PORT2 -sni localhost -vmax tls13 -CA "$DIR/ec.crt" \
		-cert "$DIR/cp521.crt" -key "$DIR/cp521.key" >"$DIR/p.log" 2>&1
	ok=1
	grep -q "TLS 1.3" "$DIR/p.log" || ok=0
	report "bear client -> openssl server, client ecdsa-p521 (sha512)" $ok
	kill $BG >/dev/null 2>&1; { wait; } 2>/dev/null
	for c in "ecdsa-p521|p521|ecdsa_secp521r1_sha512" "rsa-pss sha512|rsa|rsa_pss_rsae_sha512"; do
		name=${c%%|*}; rest=${c#*|}; cert=${rest%%|*}; alg=${rest#*|}
		( cd "$DIR" && exec openssl s_server -accept $PORT2 -cert $cert.crt \
			-key $cert.key -www -quiet -sigalgs $alg >srv.log 2>&1 ) &
		BG=$!
		sleep 1
		( echo ping-from-bear; sleep 1.5 ) | timeout 15 "$BRSSL" client \
			127.0.0.1:$PORT2 -sni localhost -vmax tls13 \
			-CA "$DIR/$cert.crt" >"$DIR/p.log" 2>&1
		ok=1
		grep -q "TLS 1.3" "$DIR/p.log" || ok=0
		report "bear client -> openssl server, $name" $ok
		kill $BG >/dev/null 2>&1; { wait; } 2>/dev/null
	done
fi

# Our client resumes a session of other servers.
if [ -f build/libbearssl.a ] && cc -O1 -Isrc -Iinc "$HERE/resume_client.c" \
	build/libbearssl.a -o "$DIR/resume_client" 2>/dev/null; then
	if command -v openssl >/dev/null; then
		( cd "$DIR" && exec openssl s_server -accept $PORT2 \
			-cert ec.crt -key ec.key -www -quiet >srv.log 2>&1 ) &
		BG=$!
		sleep 1
		"$DIR/resume_client" 127.0.0.1 $PORT2 >"$DIR/p.log" 2>&1
		report "bear client resumes a session of the openssl server" $((1 - $?))
		kill $BG >/dev/null 2>&1; { wait; } 2>/dev/null
	fi
	if [ -x "$DIR/goserver" ]; then
		"$DIR/goserver" -addr 127.0.0.1:$PORT2 -cert "$DIR/ec.crt" \
			-key "$DIR/ec.key" >"$DIR/gs.log" 2>&1 &
		BG=$!
		sleep 1
		"$DIR/resume_client" 127.0.0.1 $PORT2 >"$DIR/p.log" 2>&1
		report "bear client resumes a session of the go server" $((1 - $?))
		kill $BG >/dev/null 2>&1; { wait; } 2>/dev/null
	fi
	if command -v gnutls-serv >/dev/null; then
		gnutls-serv --port $PORT2 --priority "$PRI" \
			--x509certfile "$DIR/ec.crt" --x509keyfile "$DIR/ec.key" \
			>"$DIR/gu.log" 2>&1 &
		BG=$!
		sleep 3
		"$DIR/resume_client" 127.0.0.1 $PORT2 >"$DIR/p.log" 2>&1
		report "bear client resumes a session of the gnutls server" $((1 - $?))
		kill $BG >/dev/null 2>&1; { wait; } 2>/dev/null
	fi
fi
echo "cases run: $cases${skipped:+; peers not installed:$skipped}"
if [ -n "$EXPECT" ] && [ "$cases" != "$EXPECT" ]; then
	echo "FAIL  expected $EXPECT cases"; fail=1
fi
exit $fail
