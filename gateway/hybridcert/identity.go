// Package hybridcert independently validates the SM2 and ML-DSA parts of
// certificate-tool identities before they are used for TLS authentication.
package hybridcert

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	"crypto/x509/pkix"
	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/tjfoc/gmsm/sm2"
	gx "github.com/tjfoc/gmsm/x509"

	"pqc-gateway/hybridsig"
)

type Purpose string

const (
	Server Purpose = "server"
	Client Purpose = "client"
)

type Identity struct {
	SM2Private *sm2.PrivateKey
	PQPrivate  sign.PrivateKey
	SM2Public  *sm2.PublicKey
	PQPublic   sign.PublicKey
	LeafDER    []byte
}

type algorithmID struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}
type validity struct{ NotBefore, NotAfter time.Time }
type publicKeyInfo struct {
	Algorithm algorithmID
	PublicKey asn1.BitString
}
type tbsCertificate struct {
	Raw             asn1.RawContent
	Version         int `asn1:"optional,explicit,tag:0"`
	SerialNumber    *big.Int
	Signature       algorithmID
	Issuer          asn1.RawValue
	Validity        validity
	Subject         asn1.RawValue
	PublicKey       publicKeyInfo
	IssuerUniqueID  asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueID asn1.BitString   `asn1:"optional,tag:2"`
	Extensions      []pkix.Extension `asn1:"optional,explicit,tag:3"`
}
type certificate struct {
	TBS                tbsCertificate
	SignatureAlgorithm algorithmID
	Signature          asn1.BitString
}
type pqValue struct {
	Algorithm asn1.ObjectIdentifier
	Data      []byte
}

var oidPQPublic = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 54321, 1, 1}
var oidPQSignature = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 54321, 1, 2}
var oidMLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
var oidMLDSA87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}

func schemeFor(level hybridsig.Level) (sign.Scheme, asn1.ObjectIdentifier, error) {
	switch level {
	case hybridsig.Level128:
		return mldsa44.Scheme(), oidMLDSA44, nil
	case hybridsig.Level256:
		return mldsa87.Scheme(), oidMLDSA87, nil
	default:
		return nil, nil, fmt.Errorf("unsupported identity level: %d", level)
	}
}

func readPEM(path, kind string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1024*1024 {
		return nil, fmt.Errorf("invalid file: %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != kind || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("invalid %s PEM: %s", kind, path)
	}
	return block.Bytes, nil
}

func parseCertificate(der []byte) (*certificate, *gx.Certificate, error) {
	var raw certificate
	rest, err := asn1.Unmarshal(der, &raw)
	if err != nil || len(rest) != 0 {
		return nil, nil, errors.New("invalid certificate DER")
	}
	parsed, err := gx.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	if len(parsed.UnhandledCriticalExtensions) != 0 {
		return nil, nil, errors.New("unhandled critical certificate extension")
	}
	return &raw, parsed, nil
}

func extension(c *certificate, oid asn1.ObjectIdentifier) (pqValue, error) {
	var found pqValue
	count := 0
	for _, ext := range c.TBS.Extensions {
		if ext.Id.Equal(oid) {
			count++
			rest, err := asn1.Unmarshal(ext.Value, &found)
			if err != nil || len(rest) != 0 {
				return pqValue{}, errors.New("invalid PQ certificate extension")
			}
		}
	}
	if count != 1 {
		return pqValue{}, fmt.Errorf("expected one PQ extension %s", oid)
	}
	return found, nil
}

func pqPublic(c *certificate, scheme sign.Scheme, oid asn1.ObjectIdentifier) (sign.PublicKey, error) {
	value, err := extension(c, oidPQPublic)
	if err != nil {
		return nil, err
	}
	if !value.Algorithm.Equal(oid) {
		return nil, errors.New("PQ public key algorithm mismatch")
	}
	return scheme.UnmarshalBinaryPublicKey(value.Data)
}

func verifyPQSignature(c *certificate, issuer sign.PublicKey, scheme sign.Scheme, oid asn1.ObjectIdentifier) error {
	value, err := extension(c, oidPQSignature)
	if err != nil {
		return err
	}
	if !value.Algorithm.Equal(oid) || len(value.Data) != scheme.SignatureSize() {
		return errors.New("PQ signature algorithm or size mismatch")
	}
	tbs := c.TBS
	tbs.Raw = nil
	tbs.Extensions = nil
	for _, ext := range c.TBS.Extensions {
		if !ext.Id.Equal(oidPQSignature) {
			tbs.Extensions = append(tbs.Extensions, ext)
		}
	}
	unsigned, err := asn1.Marshal(tbs)
	if err != nil {
		return err
	}
	if !scheme.Verify(issuer, unsigned, value.Data, nil) {
		return errors.New("PQ certificate signature verification failed")
	}
	return nil
}

// Load validates a directly issued leaf and its two private keys.
func Load(rootPath, leafPath, sm2KeyPath, pqKeyPath string, level hybridsig.Level, purpose Purpose, dnsName string, now time.Time) (*Identity, error) {
	return LoadChain(rootPath, nil, leafPath, sm2KeyPath, pqKeyPath, level, purpose, dnsName, now)
}

// LoadChain validates a root-to-leaf hybrid chain and both leaf private keys.
// Intermediate paths are ordered from root to leaf. The root is explicitly trusted by the caller.
func LoadChain(rootPath string, intermediatePaths []string, leafPath, sm2KeyPath, pqKeyPath string, level hybridsig.Level, purpose Purpose, serverName string, now time.Time) (*Identity, error) {
	if len(intermediatePaths) > 4 {
		return nil, errors.New("too many intermediate certificates")
	}
	scheme, oid, err := schemeFor(level)
	if err != nil {
		return nil, err
	}
	rootDER, err := readPEM(rootPath, "CERTIFICATE")
	if err != nil {
		return nil, err
	}
	rootRaw, root, err := parseCertificate(rootDER)
	if err != nil {
		return nil, err
	}
	chainRaw := []*certificate{rootRaw}
	chain := []*gx.Certificate{root}
	for _, path := range intermediatePaths {
		der, err := readPEM(path, "CERTIFICATE")
		if err != nil {
			return nil, err
		}
		raw, cert, err := parseCertificate(der)
		if err != nil {
			return nil, err
		}
		chainRaw = append(chainRaw, raw)
		chain = append(chain, cert)
	}
	leafDER, err := readPEM(leafPath, "CERTIFICATE")
	if err != nil {
		return nil, err
	}
	leafRaw, leaf, err := parseCertificate(leafDER)
	if err != nil {
		return nil, err
	}
	chainRaw = append(chainRaw, leafRaw)
	chain = append(chain, leaf)
	for _, c := range chain {
		if now.Before(c.NotBefore) || !now.Before(c.NotAfter) {
			return nil, errors.New("certificate outside validity period")
		}
		if c.SignatureAlgorithm != gx.SM2WithSM3 {
			return nil, errors.New("certificate is not signed with SM2/SM3")
		}
	}
	if err := root.CheckSignatureFrom(root); err != nil {
		return nil, fmt.Errorf("root SM2 signature: %w", err)
	}
	var issuerPQ sign.PublicKey
	var leafPQ sign.PublicKey
	for i, cert := range chain {
		if i < len(chain)-1 {
			if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&gx.KeyUsageCertSign == 0 {
				return nil, errors.New("certificate CA or key usage mismatch")
			}
			remaining := len(chain) - 2 - i
			if (cert.MaxPathLenZero && remaining != 0) || (!cert.MaxPathLenZero && cert.MaxPathLen >= 0 && remaining > cert.MaxPathLen) {
				return nil, errors.New("CA path length exceeded")
			}
		} else if cert.IsCA || cert.KeyUsage&gx.KeyUsageDigitalSignature == 0 {
			return nil, errors.New("leaf CA or key usage mismatch")
		}
		public, err := pqPublic(chainRaw[i], scheme, oid)
		if err != nil {
			return nil, fmt.Errorf("certificate %d PQ key: %w", i, err)
		}
		if i == 0 {
			issuerPQ = public
		} else {
			if !bytes.Equal(cert.RawIssuer, chain[i-1].RawSubject) {
				return nil, errors.New("certificate issuer mismatch")
			}
			if err := cert.CheckSignatureFrom(chain[i-1]); err != nil {
				return nil, fmt.Errorf("certificate %d SM2 signature: %w", i, err)
			}
		}
		if err := verifyPQSignature(chainRaw[i], issuerPQ, scheme, oid); err != nil {
			return nil, fmt.Errorf("certificate %d: %w", i, err)
		}
		issuerPQ = public
		leafPQ = public
	}
	wantUsage := gx.ExtKeyUsageServerAuth
	switch purpose {
	case Server:
		if serverName == "" {
			return nil, errors.New("server name required")
		}
		match := false
		if ip := net.ParseIP(serverName); ip != nil {
			for _, address := range leaf.IPAddresses {
				if address.Equal(ip) {
					match = true
				}
			}
		} else {
			for _, name := range leaf.DNSNames {
				if name == serverName {
					match = true
				}
			}
		}
		if !match {
			return nil, errors.New("server SAN mismatch")
		}
	case Client:
		wantUsage = gx.ExtKeyUsageClientAuth
	default:
		return nil, errors.New("unknown identity purpose")
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != wantUsage {
		return nil, errors.New("certificate TLS purpose mismatch")
	}
	sm2DER, err := readPEM(sm2KeyPath, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	sm2Private, err := gx.ParsePKCS8UnecryptedPrivateKey(sm2DER)
	if err != nil {
		return nil, err
	}
	sm2Public, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || sm2Public.Curve != sm2.P256Sm2() || sm2Private.X.Cmp(sm2Public.X) != 0 || sm2Private.Y.Cmp(sm2Public.Y) != 0 {
		return nil, errors.New("SM2 private key does not match certificate")
	}
	pqDER, err := readPEM(pqKeyPath, "PQC PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	pqPrivate, err := scheme.UnmarshalBinaryPrivateKey(pqDER)
	if err != nil {
		return nil, err
	}
	pqPrivatePublic, ok := pqPrivate.Public().(sign.PublicKey)
	if !ok {
		return nil, errors.New("invalid ML-DSA private key public component")
	}
	pubBytes, err := pqPrivatePublic.MarshalBinary()
	if err != nil {
		return nil, err
	}
	wantBytes, err := leafPQ.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(pubBytes, wantBytes) {
		return nil, errors.New("ML-DSA private key does not match certificate")
	}
	return &Identity{sm2Private, pqPrivate, &sm2Private.PublicKey, leafPQ, leafDER}, nil
}
