// Package pqsig provides a small algorithm registry and key/signature objects
// shared by the TLS integration, the KEMTLS lab and the certificate tool.
//
// The important rule is that callers never assert a concrete CIRCL type.  They
// look up an Algorithm, generate or parse keys through it, and call Sign/Verify.
// Adding a new signature family is therefore one provider registration, not a
// new branch in every TLS handshake function.
package pqsig

import (
	"crypto"
	"encoding/asn1"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/dilithium/mode2"
	"github.com/cloudflare/circl/sign/slhdsa"
)

type Family string

const (
	FamilyDilithium Family = "dilithium"
	FamilySLHDSA    Family = "slhdsa"
)

// Algorithm is the interface TLS, certificate generation and tests should use.
type Algorithm interface {
	Name() string
	Family() Family
	Level() int
	OID() asn1.ObjectIdentifier
	Scheme() sign.Scheme

	PublicKeySize() int
	PrivateKeySize() int
	SignatureSize() int

	GenerateKey() (*KeyPair, error)
	Sign(priv *PrivateKey, message []byte) ([]byte, error)
	Verify(pub *PublicKey, message, signature []byte) error

	ParsePublicKey(raw []byte) (*PublicKey, error)
	ParsePrivateKey(raw []byte) (*PrivateKey, error)
}

type algorithm struct {
	name   string
	family Family
	level  int
	oid    asn1.ObjectIdentifier
	scheme sign.Scheme
}

func (a *algorithm) Name() string               { return a.name }
func (a *algorithm) Family() Family             { return a.family }
func (a *algorithm) Level() int                 { return a.level }
func (a *algorithm) OID() asn1.ObjectIdentifier { return a.oid }
func (a *algorithm) Scheme() sign.Scheme        { return a.scheme }
func (a *algorithm) PublicKeySize() int         { return a.scheme.PublicKeySize() }
func (a *algorithm) PrivateKeySize() int        { return a.scheme.PrivateKeySize() }
func (a *algorithm) SignatureSize() int         { return a.scheme.SignatureSize() }

type KeyPair struct {
	Public  *PublicKey
	Private *PrivateKey
}

type PublicKey struct {
	Algorithm Algorithm
	Raw       []byte
	key       sign.PublicKey
}

type PrivateKey struct {
	Algorithm Algorithm
	Raw       []byte
	key       sign.PrivateKey
}

func (k *PublicKey) CryptoPublicKey() crypto.PublicKey { return k.key }
func (k *PrivateKey) CryptoSigner() crypto.Signer      { return k.key }

func (a *algorithm) GenerateKey() (*KeyPair, error) {
	pub, priv, err := a.scheme.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("%s key generation: %w", a.name, err)
	}
	pubRaw, err := pub.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("%s public key marshal: %w", a.name, err)
	}
	privRaw, err := priv.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("%s private key marshal: %w", a.name, err)
	}
	return &KeyPair{
		Public:  &PublicKey{Algorithm: a, Raw: append([]byte(nil), pubRaw...), key: pub},
		Private: &PrivateKey{Algorithm: a, Raw: append([]byte(nil), privRaw...), key: priv},
	}, nil
}

func (a *algorithm) Sign(priv *PrivateKey, message []byte) ([]byte, error) {
	if priv == nil || priv.Algorithm == nil || priv.Algorithm.Name() != a.name {
		return nil, fmt.Errorf("%s sign: key does not belong to this algorithm", a.name)
	}
	sig := a.scheme.Sign(priv.key, message, nil)
	if len(sig) != a.SignatureSize() {
		return nil, fmt.Errorf("%s sign: unexpected signature length %d", a.name, len(sig))
	}
	return append([]byte(nil), sig...), nil
}

func (a *algorithm) Verify(pub *PublicKey, message, signature []byte) error {
	if pub == nil || pub.Algorithm == nil || pub.Algorithm.Name() != a.name {
		return fmt.Errorf("%s verify: key does not belong to this algorithm", a.name)
	}
	if len(signature) != a.SignatureSize() {
		return fmt.Errorf("%s verify: signature length %d, want %d", a.name, len(signature), a.SignatureSize())
	}
	if !a.scheme.Verify(pub.key, message, signature, nil) {
		return errors.New(a.name + " verify: invalid signature")
	}
	return nil
}

func (a *algorithm) ParsePublicKey(raw []byte) (*PublicKey, error) {
	key, err := a.scheme.UnmarshalBinaryPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("%s public key parse: %w", a.name, err)
	}
	return &PublicKey{Algorithm: a, Raw: append([]byte(nil), raw...), key: key}, nil
}

func (a *algorithm) ParsePrivateKey(raw []byte) (*PrivateKey, error) {
	key, err := a.scheme.UnmarshalBinaryPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("%s private key parse: %w", a.name, err)
	}
	return &PrivateKey{Algorithm: a, Raw: append([]byte(nil), raw...), key: key}, nil
}

var (
	registry = make(map[string]Algorithm)
	oidIndex = make(map[string]Algorithm)
	order    []string
)

func register(a Algorithm) {
	name := a.Name()
	if _, ok := registry[name]; ok {
		panic("pqsig: duplicate algorithm " + name)
	}
	registry[name] = a
	oidIndex[a.OID().String()] = a
	order = append(order, name)
}

// OIDs: SLH-DSA uses the RFC 9909 assignments; Dilithium2 uses the project's
// legacy private OID until the certificate extension carries an algorithm tag.
var (
	oidDilithium2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 54321, 21, 1}
	// OIDAlgorithmExtension is the certificate extension carrying the PQ
	// signature algorithm. Existing hybrid certificates use private extensions
	// .1.0/.1.1/.1.2 for raw keys and signatures; without .1.3 a verifier cannot
	// distinguish Dilithium2 from any SLH-DSA parameter set.
	OIDAlgorithmExtension = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 54321, 1, 3}
	slhdsaOIDs            = map[string]asn1.ObjectIdentifier{
		"SLH-DSA-SHA2-128s": {2, 16, 840, 1, 101, 3, 4, 3, 20},
		"SLH-DSA-SHA2-128f": {2, 16, 840, 1, 101, 3, 4, 3, 21},
		"SLH-DSA-SHA2-192s": {2, 16, 840, 1, 101, 3, 4, 3, 22},
		"SLH-DSA-SHA2-192f": {2, 16, 840, 1, 101, 3, 4, 3, 23},
		"SLH-DSA-SHA2-256s": {2, 16, 840, 1, 101, 3, 4, 3, 24},
		"SLH-DSA-SHA2-256f": {2, 16, 840, 1, 101, 3, 4, 3, 25},
	}
)

func init() {
	register(&algorithm{
		name:   "Dilithium2",
		family: FamilyDilithium,
		level:  128,
		oid:    oidDilithium2,
		scheme: mode2.Scheme(),
	})
	for _, name := range []string{
		"SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
		"SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
		"SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f",
	} {
		id, err := slhdsa.IDByName(name)
		if err != nil {
			panic("pqsig: " + name + ": " + err.Error())
		}
		level := 128
		if strings.Contains(name, "192") {
			level = 192
		} else if strings.Contains(name, "256") {
			level = 256
		}
		register(&algorithm{
			name:   name,
			family: FamilySLHDSA,
			level:  level,
			oid:    slhdsaOIDs[name],
			scheme: id.Scheme(),
		})
	}
}

// EncodeAlgorithmExtension returns the DER value for OIDAlgorithmExtension.
func EncodeAlgorithmExtension(a Algorithm) ([]byte, error) {
	if a == nil {
		return nil, errors.New("pqsig: nil algorithm")
	}
	return asn1.Marshal(a.OID())
}

// DecodeAlgorithmExtension parses the DER value of OIDAlgorithmExtension.
func DecodeAlgorithmExtension(der []byte) (Algorithm, error) {
	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(der, &oid)
	if err != nil {
		return nil, fmt.Errorf("pqsig: algorithm extension: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("pqsig: algorithm extension has trailing data")
	}
	a, ok := ByOID(oid)
	if !ok {
		return nil, fmt.Errorf("pqsig: unknown algorithm OID %s", oid)
	}
	return a, nil
}

func ByOID(oid asn1.ObjectIdentifier) (Algorithm, bool) {
	a, ok := oidIndex[oid.String()]
	return a, ok
}

func ByName(name string) (Algorithm, bool) {
	if a, ok := registry[name]; ok {
		return a, true
	}
	for key, a := range registry {
		if strings.EqualFold(key, name) {
			return a, true
		}
	}
	return nil, false
}

func All() []Algorithm {
	out := make([]Algorithm, 0, len(order))
	for _, name := range order {
		out = append(out, registry[name])
	}
	return out
}

func Names() []string {
	out := append([]string(nil), order...)
	sort.Strings(out)
	return out
}
