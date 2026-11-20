// TLS 1.3 echo server for the interoperability checks of the BearSSL fork.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:14446", "listen address")
	cert := flag.String("cert", "", "certificate")
	key := flag.String("key", "", "key")
	ca := flag.String("ca", "", "client CA file")
	curves := flag.String("curve", "", "single curve: x25519,p256,p384,p521")
	flag.Parse()
	c, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{c}, MinVersion: tls.VersionTLS13}
	if kl := os.Getenv("KEYLOG"); kl != "" {
		f, _ := os.OpenFile(kl, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		cfg.KeyLogWriter = f
	}
	if *ca != "" {
		pool := x509.NewCertPool()
		pem, _ := os.ReadFile(*ca)
		pool.AppendCertsFromPEM(pem)
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	switch *curves {
	case "p256":
		cfg.CurvePreferences = []tls.CurveID{tls.CurveP256}
	case "p384":
		cfg.CurvePreferences = []tls.CurveID{tls.CurveP384}
	}
	l, err := tls.Listen("tcp", *addr, cfg)
	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}
	fmt.Println("listening")
	for {
		conn, err := l.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer conn.Close()
			tc := conn.(*tls.Conn)
			if err := tc.Handshake(); err != nil {
				fmt.Println("HANDSHAKE ERROR:", err)
				return
			}
			st := tc.ConnectionState()
			fmt.Printf("version=%x suite=%s peercerts=%d\n", st.Version, tls.CipherSuiteName(st.CipherSuite), len(st.PeerCertificates))
			io.Copy(conn, conn)
		}()
	}
}
