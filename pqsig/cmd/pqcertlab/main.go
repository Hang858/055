// pqcertlab generates the RSA certificate chain used by the KEMTLS TLS lab.
// The server leaf carries the raw PQ signature public key in extension .1.1
// and the algorithm OID in extension .1.3.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	pqsig "pqsig"
)

var (
	oidPQPublic    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 54321, 1, 1}
	oidPQAlgorithm = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 54321, 1, 3}
)

func main() {
	algName := flag.String("alg", "SLH-DSA-SHA2-128s", "PQ signature algorithm")
	pubPath := flag.String("pub", "", "raw PQ public key file for the server leaf")
	out := flag.String("out", "", "output directory")
	flag.Parse()
	if *out == "" || *pubPath == "" {
		fmt.Fprintln(os.Stderr, "FAIL: -out and -pub are required")
		os.Exit(2)
	}
	alg, ok := pqsig.ByName(*algName)
	if !ok {
		fmt.Fprintf(os.Stderr, "FAIL: unknown algorithm %q\n", *algName)
		os.Exit(2)
	}
	pub, err := os.ReadFile(*pubPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(*out, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fatal(err)
	}
	now := time.Now()
	root := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "KEMTLS Lab Root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		fatal(err)
	}
	writePEM(filepath.Join(*out, "root.crt"), "CERTIFICATE", rootDER)
	writeKey(filepath.Join(*out, "root.key"), rootKey)

	algDER, err := asn1.Marshal(alg.OID())
	if err != nil {
		fatal(err)
	}
	server := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "quantum-secure.example.com"},
		DNSNames:     []string{"quantum-secure.example.com"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ExtraExtensions: []pkix.Extension{
			{Id: oidPQPublic, Value: pub},
			{Id: oidPQAlgorithm, Value: algDER},
		},
	}
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fatal(err)
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, server, root, &serverKey.PublicKey, rootKey)
	if err != nil {
		fatal(err)
	}
	writePEM(filepath.Join(*out, "server.crt"), "CERTIFICATE", serverDER)
	writeKey(filepath.Join(*out, "server.key"), serverKey)

	client := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "KEMTLS Lab Client"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fatal(err)
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, client, root, &clientKey.PublicKey, rootKey)
	if err != nil {
		fatal(err)
	}
	writePEM(filepath.Join(*out, "client.crt"), "CERTIFICATE", clientDER)
	writeKey(filepath.Join(*out, "client.key"), clientKey)
	fmt.Printf("wrote %s for %s (pub=%d)\n", *out, alg.Name(), len(pub))
}

func writePEM(path, kind string, der []byte) {
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0644); err != nil {
		fatal(err)
	}
}

func writeKey(path string, key *rsa.PrivateKey) {
	der := x509.MarshalPKCS1PrivateKey(key)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}), 0600); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
	os.Exit(1)
}
