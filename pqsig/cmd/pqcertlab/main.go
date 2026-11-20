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
	"strconv"
	"strings"
	"time"

	pqsig "pqsig"
)

var (
	oidPQPublic       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 54321, 1, 1}
	oidPQAlgorithm    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 54321, 1, 3}
	oidPQKEMPublic    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 54321, 1, 0}
	oidPQKEMAlgorithm = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 54321, 1, 4}
	oidPQSignature    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 54321, 1, 2}
)

func main() {
	algName := flag.String("alg", "SLH-DSA-SHA2-128s", "PQ signature algorithm")
	pubPath := flag.String("pub", "", "raw PQ public key file for the server leaf")
	clientPubPath := flag.String("client-pub", "", "raw PQ public key file for the client leaf")
	kemPubPath := flag.String("kem-pub", "", "raw KEM public key for the server leaf")
	clientKemPubPath := flag.String("client-kem-pub", "", "raw KEM public key for the client leaf")
	kemOID := flag.String("kem-oid", "", "KEM algorithm OID (dotted), required with -kem-pub")
	badPQ := flag.Bool("bad-pq", false, "sign leaf PQ certificates with a throwaway key (negative test)")
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
	rootPQKey, err := alg.GenerateKey()
	if err != nil {
		fatal(err)
	}
	leafPQKey := rootPQKey
	if *badPQ {
		leafPQKey, err = alg.GenerateKey()
		if err != nil {
			fatal(err)
		}
	}
	pub, err := os.ReadFile(*pubPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
	var clientPub []byte
	if *clientPubPath != "" {
		clientPub, err = os.ReadFile(*clientPubPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
			os.Exit(1)
		}
	}
	var kemPub, clientKemPub []byte
	var kemOIDParsed asn1.ObjectIdentifier
	if *kemPubPath != "" || *kemOID != "" {
		if *kemPubPath == "" || *kemOID == "" {
			fmt.Fprintln(os.Stderr, "FAIL: -kem-pub and -kem-oid must be set together")
			os.Exit(2)
		}
		kemPub, err = os.ReadFile(*kemPubPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
			os.Exit(1)
		}
		kemOIDParsed, err = parseOID(*kemOID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
			os.Exit(1)
		}
	}
	if *clientKemPubPath != "" {
		if *kemOID == "" {
			fmt.Fprintln(os.Stderr, "FAIL: -client-kem-pub requires -kem-oid")
			os.Exit(2)
		}
		clientKemPub, err = os.ReadFile(*clientKemPubPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
			os.Exit(1)
		}
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
	algDER, err := asn1.Marshal(alg.OID())
	if err != nil {
		fatal(err)
	}
	root := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "KEMTLS Lab Root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtraExtensions: []pkix.Extension{
			{Id: oidPQPublic, Value: rootPQKey.Public.Raw},
			{Id: oidPQAlgorithm, Value: algDER},
		},
	}
	rootDER, err := createDualSigned(root, root, &rootKey.PublicKey, rootKey, rootPQKey.Private, alg)
	if err != nil {
		fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		fatal(err)
	}
	writePEM(filepath.Join(*out, "root.crt"), "CERTIFICATE", rootDER)
	writeKey(filepath.Join(*out, "root.key"), rootKey)
	writeRaw(filepath.Join(*out, "root-pq.pub"), rootPQKey.Public.Raw)
	serverExtensions := []pkix.Extension{
		{Id: oidPQPublic, Value: pub},
		{Id: oidPQAlgorithm, Value: algDER},
	}
	if len(kemPub) != 0 {
		kemOIDDER, err := asn1.Marshal(kemOIDParsed)
		if err != nil {
			fatal(err)
		}
		serverExtensions = append(serverExtensions,
			pkix.Extension{Id: oidPQKEMPublic, Value: kemPub},
			pkix.Extension{Id: oidPQKEMAlgorithm, Value: kemOIDDER})
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
		ExtraExtensions: serverExtensions,
	}
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fatal(err)
	}
	serverDER, err := createDualSigned(server, rootCert, &serverKey.PublicKey, rootKey, leafPQKey.Private, alg)
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
	if len(clientPub) != 0 {
		client.ExtraExtensions = []pkix.Extension{
			{Id: oidPQPublic, Value: clientPub},
			{Id: oidPQAlgorithm, Value: algDER},
		}
	}
	if len(clientKemPub) != 0 {
		kemOIDDER, err := asn1.Marshal(kemOIDParsed)
		if err != nil {
			fatal(err)
		}
		client.ExtraExtensions = append(client.ExtraExtensions,
			pkix.Extension{Id: oidPQKEMPublic, Value: clientKemPub},
			pkix.Extension{Id: oidPQKEMAlgorithm, Value: kemOIDDER})
	}
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fatal(err)
	}
	var clientDER []byte
	if len(clientPub) == 0 {
		clientDER, err = x509.CreateCertificate(rand.Reader, client, rootCert, &clientKey.PublicKey, rootKey)
	} else {
		clientDER, err = createDualSigned(client, rootCert, &clientKey.PublicKey, rootKey, leafPQKey.Private, alg)
	}
	if err != nil {
		fatal(err)
	}
	writePEM(filepath.Join(*out, "client.crt"), "CERTIFICATE", clientDER)
	writeKey(filepath.Join(*out, "client.key"), clientKey)
	fmt.Printf("wrote %s for %s (pub=%d)\n", *out, alg.Name(), len(pub))
}

// pqSigningExtension 是 CSI 中的一个扩展项，必须与 crypto/myx509 的编码一致。
type pqSigningExtension struct {
	OID      asn1.ObjectIdentifier
	Critical bool
	Value    []byte
}

// pqSigningInput 与 crypto/myx509.CertificateSigningInput 使用同一 ASN.1 结构，
// 生成和验证两侧都排除 .1.2（PQ 签名本身）。
type pqSigningInput struct {
	Version              int
	SerialNumber         *big.Int
	SignatureAlgorithm   int
	Issuer               []byte
	Subject              []byte
	NotBefore            string
	NotAfter             string
	SubjectPublicKeyInfo []byte
	Extensions           []pqSigningExtension
}

func certificateSigningInput(cert *x509.Certificate) ([]byte, error) {
	in := pqSigningInput{
		Version:              cert.Version,
		SerialNumber:         cert.SerialNumber,
		SignatureAlgorithm:   int(cert.SignatureAlgorithm),
		Issuer:               append([]byte(nil), cert.RawIssuer...),
		Subject:              append([]byte(nil), cert.RawSubject...),
		NotBefore:            cert.NotBefore.UTC().Format(time.RFC3339Nano),
		NotAfter:             cert.NotAfter.UTC().Format(time.RFC3339Nano),
		SubjectPublicKeyInfo: append([]byte(nil), cert.RawSubjectPublicKeyInfo...),
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidPQSignature) {
			continue
		}
		in.Extensions = append(in.Extensions, pqSigningExtension{
			OID:      ext.Id,
			Critical: ext.Critical,
			Value:    append([]byte(nil), ext.Value...),
		})
	}
	return asn1.Marshal(in)
}

// createDualSigned 生成经典签名 + PQ 签名的证书。PQ 签名覆盖不含 .1.2 的
// 原型证书 CSI，因此验证方重算 CSI 即可验证，不会形成循环。
func createDualSigned(template, parent *x509.Certificate, pub *rsa.PublicKey, parentPriv *rsa.PrivateKey, pqPriv *pqsig.PrivateKey, alg pqsig.Algorithm) ([]byte, error) {
	protoDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentPriv)
	if err != nil {
		return nil, err
	}
	proto, err := x509.ParseCertificate(protoDER)
	if err != nil {
		return nil, err
	}
	csi, err := certificateSigningInput(proto)
	if err != nil {
		return nil, err
	}
	sig, err := alg.Sign(pqPriv, csi)
	if err != nil {
		return nil, err
	}
	template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{Id: oidPQSignature, Value: sig})
	return x509.CreateCertificate(rand.Reader, template, parent, pub, parentPriv)
}

func writeRaw(path string, data []byte) {
	if err := os.WriteFile(path, data, 0644); err != nil {
		fatal(err)
	}
}

func parseOID(s string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(s, ".")
	oid := make(asn1.ObjectIdentifier, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid OID %q", s)
		}
		oid = append(oid, n)
	}
	if len(oid) < 2 {
		return nil, fmt.Errorf("OID %q has too few components", s)
	}
	return oid, nil
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
