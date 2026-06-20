package tunnel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"time"
)

// makeTLSConfig builds a TLS server config. If certFile and keyFile are both
// provided it loads them; otherwise it generates a self-signed certificate on
// the fly (clients must connect with -k in that case).
func makeTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	var cert tls.Certificate
	var err error

	if certFile != "" && keyFile != "" {
		cert, err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load TLS cert: %w", err)
		}
		log.Printf("TLS cert loaded from %s", certFile)
	} else {
		cert, err = generateSelfSignedCert()
		if err != nil {
			return nil, fmt.Errorf("generate self-signed cert: %w", err)
		}
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP384,
		},
	}, nil
}

// LoadTLSConfigForHTTPS returns a tls.Config suitable for the public HTTPS
// listener. It uses GetCertificate (SNI-aware) so the same cert is served for
// all subdomains — essential when using a wildcard cert such as
// *.gotunnel.rgptv.site. Without this, Go's default TLS stack only matches
// the cert's exact SAN entries and hangs/rejects subdomain connections.
func LoadTLSConfigForHTTPS(certFile, keyFile string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("cert and key files are required for the HTTPS listener")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load HTTPS TLS cert: %w", err)
	}
	log.Printf("HTTPS TLS cert loaded from %s", certFile)
	return &tls.Config{
		// GetCertificate is called for every TLS handshake with the client's
		// SNI hostname. Returning the same cert regardless of ServerName means
		// a wildcard cert (e.g. *.gotunnel.rgptv.site) is served correctly
		// for any subdomain without needing an entry per subdomain.
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return &cert, nil
		},
		MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP384,
		},
	}, nil
}

// generateSelfSignedCert creates an in-memory ECDSA P-256 certificate valid
// for one year.
func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"gotunnel (self-signed)"}},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create cert: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// runGenKey prints a 256-bit random hex token suitable for use as -token.
func RunGenKey() {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("rand.Read: %v", err)
	}
	fmt.Println(hex.EncodeToString(b))
}
