// TLS 1.3 client for the interoperability checks of the BearSSL fork.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:14445", "server address")
	ca := flag.String("ca", "", "CA file (PEM)")
	cert := flag.String("cert", "", "client certificate")
	key := flag.String("key", "", "client key")
	alpn := flag.String("alpn", "", "ALPN protocol")
	curves := flag.String("curve", "", "single curve: x25519,p256,p384,p521")
	suite := flag.String("suite", "", "aes128|aes256|chacha")
	resume := flag.Bool("resume", false, "connect twice and check that the second connection resumes")
	flag.Parse()
	pool := x509.NewCertPool()
	pem, err := os.ReadFile(*ca)
	if err != nil || !pool.AppendCertsFromPEM(pem) {
		fmt.Println("bad CA", err)
		os.Exit(2)
	}
	cfg := &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS13}
	if *cert != "" {
		c, err := tls.LoadX509KeyPair(*cert, *key)
		if err != nil {
			fmt.Println("bad client cert", err)
			os.Exit(2)
		}
		cfg.Certificates = []tls.Certificate{c}
	}
	if *alpn != "" {
		cfg.NextProtos = []string{*alpn}
	}
	switch *curves {
	case "x25519":
		cfg.CurvePreferences = []tls.CurveID{tls.X25519}
	case "p256":
		cfg.CurvePreferences = []tls.CurveID{tls.CurveP256}
	case "p384":
		cfg.CurvePreferences = []tls.CurveID{tls.CurveP384}
	case "p521":
		cfg.CurvePreferences = []tls.CurveID{tls.CurveP521}
	}
	_ = suite // Go does not let a client choose TLS 1.3 suites
	if *resume {
		cfg.ClientSessionCache = tls.NewLRUClientSessionCache(4)
		for i := 0; i < 2; i++ {
			c, err := tls.Dial("tcp", *addr, cfg)
			if err != nil {
				fmt.Println("DIAL ERROR:", err)
				os.Exit(1)
			}
			c.Write([]byte("ping-from-go\n"))
			c.SetReadDeadline(time.Now().Add(3 * time.Second))
			buf := make([]byte, 100)
			io.ReadAtLeast(c, buf, 5) // the session ticket is processed with the first read
			st := c.ConnectionState()
			fmt.Printf("connection %d: version=%x suite=%s resumed=%v\n", i+1, st.Version, tls.CipherSuiteName(st.CipherSuite), st.DidResume)
			c.Close()
			if i == 1 && !st.DidResume {
				os.Exit(1)
			}
		}
		return
	}
	conn, err := tls.Dial("tcp", *addr, cfg)
	if err != nil {
		fmt.Println("DIAL ERROR:", err)
		os.Exit(1)
	}
	defer conn.Close()
	st := conn.ConnectionState()
	fmt.Printf("version=%x suite=%s alpn=%q\n", st.Version, tls.CipherSuiteName(st.CipherSuite), st.NegotiatedProtocol)
	if _, err := conn.Write([]byte("ping-from-go\n")); err != nil {
		fmt.Println("WRITE ERROR:", err)
		os.Exit(1)
	}
	conn.SetReadDeadline(time.Now().Add(4 * time.Second))
	buf := make([]byte, 100)
	n, err := io.ReadAtLeast(conn, buf, 5)
	fmt.Printf("received %q err=%v\n", buf[:n], err)
}
