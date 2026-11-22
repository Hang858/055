// lightcert generates the lab certificate chain for BiT and PolarLAC.
// It only uses the pqc registry, so it does not link vendor code directly.
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

	"pqc"
)

var (
	oidPQPublic       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 54321, 1, 1}
	oidPQAlgorithm    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 54321, 1, 3}
	oidPQKEMPublic    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 54321, 1, 0}
	oidPQKEMAlgorithm = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 54321, 1, 4}
)

func main() {
	algName := flag.String("alg", "BiT-128", "server/client signature algorithm")
	kemAlg := flag.String("kem-alg", "", "optional KEM algorithm for leaf .1.0")
	out := flag.String("out", "", "output directory")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "FAIL: -out is required")
		os.Exit(2)
	}
	sigAlg, err := pqc.Lookup(*algName)
	if err != nil || sigAlg.Kind() != pqc.KindSig {
		fmt.Fprintf(os.Stderr, "FAIL: signature algorithm %q: %v\n", *algName, err)
		os.Exit(2)
	}
	serverSig, err := sigAlg.GenerateKey()
	if err != nil {
		fatal(err)
	}
	clientSig, err := sigAlg.GenerateKey()
	if err != nil {
		fatal(err)
	}
	var kem *pqc.Algorithm
	var serverKEM, clientKEM *pqc.KeyPair
	if *kemAlg != "" {
		kem, err = pqc.Lookup(*kemAlg)
		if err != nil || kem.Kind() != pqc.KindKEM {
			fmt.Fprintf(os.Stderr, "FAIL: KEM algorithm %q: %v\n", *kemAlg, err)
			os.Exit(2)
		}
		serverKEM, err = kem.GenerateKey()
		if err != nil {
			fatal(err)
		}
		clientKEM, err = kem.GenerateKey()
		if err != nil {
			fatal(err)
		}
	}
	sigOID, err := asn1.Marshal(sigAlg.OID())
	if err != nil {
		fatal(err)
	}
	var kemOID []byte
	if kem != nil {
		kemOID, err = asn1.Marshal(kem.OID())
		if err != nil {
			fatal(err)
		}
	}

	if err := os.MkdirAll(*out, 0755); err != nil {
		fatal(err)
	}
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fatal(err)
	}
	now := time.Now()
	root := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "light-lattice Lab Root"},
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
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		fatal(err)
	}
	writePEM(filepath.Join(*out, "root.crt"), "CERTIFICATE", rootDER)
	writeKey(filepath.Join(*out, "root.key"), rootKey)

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fatal(err)
	}
	serverExt := []pkix.Extension{
		{Id: oidPQPublic, Value: serverSig.Public.Raw},
		{Id: oidPQAlgorithm, Value: sigOID},
	}
	if serverKEM != nil {
		serverExt = append(serverExt,
			pkix.Extension{Id: oidPQKEMPublic, Value: serverKEM.Public.Raw},
			pkix.Extension{Id: oidPQKEMAlgorithm, Value: kemOID})
	}
	server := &x509.Certificate{
		SerialNumber:    big.NewInt(2),
		Subject:         pkix.Name{CommonName: "quantum-secure.example.com"},
		DNSNames:        []string{"quantum-secure.example.com"},
		IPAddresses:     []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:       now.Add(-time.Hour),
		NotAfter:        now.AddDate(1, 0, 0),
		KeyUsage:        x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ExtraExtensions: serverExt,
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, server, rootCert, &serverKey.PublicKey, rootKey)
	if err != nil {
		fatal(err)
	}
	writePEM(filepath.Join(*out, "server.crt"), "CERTIFICATE", serverDER)
	writeKey(filepath.Join(*out, "server.key"), serverKey)

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fatal(err)
	}
	clientExt := []pkix.Extension{
		{Id: oidPQPublic, Value: clientSig.Public.Raw},
		{Id: oidPQAlgorithm, Value: sigOID},
	}
	if clientKEM != nil {
		clientExt = append(clientExt,
			pkix.Extension{Id: oidPQKEMPublic, Value: clientKEM.Public.Raw},
			pkix.Extension{Id: oidPQKEMAlgorithm, Value: kemOID})
	}
	client := &x509.Certificate{
		SerialNumber:    big.NewInt(3),
		Subject:         pkix.Name{CommonName: "light-lattice Lab Client"},
		NotBefore:       now.Add(-time.Hour),
		NotAfter:        now.AddDate(1, 0, 0),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: clientExt,
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, client, rootCert, &clientKey.PublicKey, rootKey)
	if err != nil {
		fatal(err)
	}
	writePEM(filepath.Join(*out, "client.crt"), "CERTIFICATE", clientDER)
	writeKey(filepath.Join(*out, "client.key"), clientKey)

	writeRaw(filepath.Join(*out, "sig.priv"), serverSig.Private.Raw)
	writeRaw(filepath.Join(*out, "sig.pub"), serverSig.Public.Raw)
	writeRaw(filepath.Join(*out, "client-sig.priv"), clientSig.Private.Raw)
	writeRaw(filepath.Join(*out, "client-sig.pub"), clientSig.Public.Raw)
	if serverKEM != nil {
		writeRaw(filepath.Join(*out, "srv-kem.priv"), serverKEM.Private.Raw)
		writeRaw(filepath.Join(*out, "srv-kem.pub"), serverKEM.Public.Raw)
		writeRaw(filepath.Join(*out, "cli-kem.priv"), clientKEM.Private.Raw)
		writeRaw(filepath.Join(*out, "cli-kem.pub"), clientKEM.Public.Raw)
	}
	fmt.Printf("wrote %s for %s\n", *out, sigAlg.Name())
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
func writeRaw(path string, data []byte) {
	if err := os.WriteFile(path, data, 0600); err != nil {
		fatal(err)
	}
}
func fatal(err error) {
	fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
	os.Exit(1)
}
