#!/bin/sh
# Interoperability of the TLS 1.3 server and client (build/brssl) with
# other implementations: OpenSSL (s_client, s_server), GnuTLS (gnutls-cli,
# gnutls-serv) and Go (programs in test/interop_go). A peer that is not
# installed is skipped. Usage: sh test/interop_server13.sh [path/to/brssl]
# Ports are below 32768 (outside the ephemeral range).

BRSSL=${1:-build/brssl}
HERE=$(cd "$(dirname "$0")" && pwd)
PORT=${PORT:-14445}
PORT2=$((PORT + 1))
DIR=$(mktemp -d)
trap 'pkill -P $$ 2>/dev/null; rm -rf "$DIR"' EXIT INT TERM
fail=0
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
mk cec ec -pkeyopt ec_paramgen_curve:prime256v1
mk crsa rsa:2048

report() { # name ok
	if [ "$2" = 1 ]; then echo "ok    $1"; else echo "FAIL  $1"; fail=1; fi
}

# Our server, started with a stdin that stays open and ends with a reply.
start_server() { # server args
	( ( sleep 4; echo "pong-from-bear" ) 2>/dev/null | "$BRSSL" \
		server -p $PORT -vmax tls13 "$@" >"$DIR/bs.log" 2>&1 ) 2>/dev/null &
	sleep 1
}
stop_server() { pkill -x brssl >/dev/null 2>&1; { wait; } 2>/dev/null; sleep 1; }

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
		&& go build -o "$DIR/goserver" ./goserver ) || echo "go build failed"
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
		sleep 1
		( echo ping-from-bear; sleep 1.5 ) | timeout 15 "$BRSSL" client \
			127.0.0.1:$PORT2 -sni localhost -vmax tls13 \
			-CA "$DIR/$cert.crt" $ca >"$DIR/p.log" 2>&1
		ok=1
		grep -q "TLS 1.3" "$DIR/p.log" || ok=0
		grep -q "ping-from-bear" "$DIR/p.log" || ok=0
		report "bear client -> go server, $name" $ok
		pkill -x goserver >/dev/null 2>&1; { wait; } 2>/dev/null; sleep 0.5
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
		sleep 3
		( echo ping-from-bear; sleep 1.5 ) | timeout 15 "$BRSSL" client \
			127.0.0.1:$PORT2 -sni localhost -vmax tls13 \
			-CA "$DIR/$cert.crt" $ca >"$DIR/p.log" 2>&1
		ok=1
		grep -q "TLS 1.3" "$DIR/p.log" || ok=0
		report "bear client -> gnutls server, $name" $ok
		pkill -x gnutls-serv >/dev/null 2>&1; { wait; } 2>/dev/null; sleep 1
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

# Our client resumes a session of other servers.
if [ -f build/libbearssl.a ] && cc -O1 -Isrc -Iinc "$HERE/resume_client.c" \
	build/libbearssl.a -o "$DIR/resume_client" 2>/dev/null; then
	if command -v openssl >/dev/null; then
		( cd "$DIR" && exec openssl s_server -accept $PORT2 \
			-cert ec.crt -key ec.key -www -quiet >srv.log 2>&1 ) &
		sleep 1
		"$DIR/resume_client" 127.0.0.1 $PORT2 >"$DIR/p.log" 2>&1
		report "bear client resumes a session of the openssl server" $((1 - $?))
		pkill -x openssl >/dev/null 2>&1; { wait; } 2>/dev/null
	fi
	if [ -x "$DIR/goserver" ]; then
		"$DIR/goserver" -addr 127.0.0.1:$PORT2 -cert "$DIR/ec.crt" \
			-key "$DIR/ec.key" >"$DIR/gs.log" 2>&1 &
		sleep 1
		"$DIR/resume_client" 127.0.0.1 $PORT2 >"$DIR/p.log" 2>&1
		report "bear client resumes a session of the go server" $((1 - $?))
		pkill -x goserver >/dev/null 2>&1; { wait; } 2>/dev/null
	fi
	if command -v gnutls-serv >/dev/null; then
		gnutls-serv --port $PORT2 --priority "$PRI" \
			--x509certfile "$DIR/ec.crt" --x509keyfile "$DIR/ec.key" \
			>"$DIR/gu.log" 2>&1 &
		sleep 3
		"$DIR/resume_client" 127.0.0.1 $PORT2 >"$DIR/p.log" 2>&1
		report "bear client resumes a session of the gnutls server" $((1 - $?))
		pkill -x gnutls-serv >/dev/null 2>&1; { wait; } 2>/dev/null
	fi
fi
exit $fail
