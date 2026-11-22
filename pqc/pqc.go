// Package pqc is the single Go entry point for C-implemented PQ algorithms.
//
// The C side owns algorithm implementations and the registry; this package
// only exposes pq_alg_lookup() and the pq_alg descriptor to Go.  Callers do
// not switch on algorithm names: they call Lookup(name) and use the returned
// Signer/KEM methods.
package pqc

/*
#cgo CFLAGS: -I${SRCDIR}/include -std=c11
#include "pq_alg.h"
#include <stdlib.h>

static int pqc_call_keygen(const pq_alg *a, uint8_t *pk, uint8_t *sk) {
    if (a == NULL || a->keygen == NULL) return PQ_ERR_NOTIMPL;
    return a->keygen(pk, sk);
}
static int pqc_call_pub_from_sk(const pq_alg *a, const uint8_t *sk, uint8_t *pk) {
    if (a == NULL || a->pub_from_sk == NULL) return PQ_ERR_NOTIMPL;
    return a->pub_from_sk(sk, pk);
}
static int pqc_call_sign(const pq_alg *a, const uint8_t *sk,
                         const uint8_t *msg, size_t msg_len,
                         uint8_t *sig, size_t sig_cap) {
    if (a == NULL || a->sign == NULL) return PQ_ERR_NOTIMPL;
    return a->sign(sk, msg, msg_len, sig, sig_cap);
}
static int pqc_call_verify(const pq_alg *a, const uint8_t *pk,
                           const uint8_t *msg, size_t msg_len,
                           const uint8_t *sig, size_t sig_len) {
    if (a == NULL || a->verify == NULL) return PQ_ERR_NOTIMPL;
    return a->verify(pk, msg, msg_len, sig, sig_len);
}
static int pqc_call_encaps(const pq_alg *a, const uint8_t *pk,
                           uint8_t *ct, size_t ct_cap,
                           uint8_t *ss, size_t ss_cap) {
    if (a == NULL || a->encaps == NULL) return PQ_ERR_NOTIMPL;
    return a->encaps(pk, ct, ct_cap, ss, ss_cap);
}
static int pqc_call_decaps(const pq_alg *a, const uint8_t *sk,
                           const uint8_t *ct, size_t ct_len,
                           uint8_t *ss, size_t ss_cap) {
    if (a == NULL || a->decaps == NULL) return PQ_ERR_NOTIMPL;
    return a->decaps(sk, ct, ct_len, ss, ss_cap);
}
*/
import "C"

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unsafe"
)

type Kind uint32

const (
	KindSig Kind = 1
	KindKEM Kind = 2
)

type Input uint32

const (
	InputMessage Input = 0
	InputDigest  Input = 1
)

var (
	ErrNotFound       = errors.New("pqc: algorithm not found")
	ErrNotImplemented = errors.New("pqc: algorithm is a placeholder or not linked")
	ErrKind           = errors.New("pqc: wrong algorithm kind")
	ErrInvalidKey     = errors.New("pqc: key does not belong to algorithm")
	ErrLength         = errors.New("pqc: invalid key or signature length")
)

// Algorithm is a view of a C pq_alg descriptor.  The descriptor is static (or
// owned by a plugin for the process lifetime); no Go finalizer is needed.
type Algorithm struct {
	p     *C.pq_alg
	goKEM *goKEMBackend
}

func wrap(p *C.pq_alg) *Algorithm {
	if p == nil {
		return nil
	}
	return &Algorithm{p: p}
}

// Lookup is the single registration entry.  It returns placeholders too:
// call Available to distinguish "known but not linked" from "usable".
func Lookup(name string) (*Algorithm, error) {
	if a := lookupGoKEM(name); a != nil {
		return a, nil
	}
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	a := wrap(C.pq_alg_lookup(cname))
	if a == nil {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	return a, nil
}

func ByTLSCode(code uint16) (*Algorithm, error) {
	for _, a := range All() {
		if a.TLSCode() == code {
			return a, nil
		}
	}
	return nil, fmt.Errorf("%w: tls code 0x%04x", ErrNotFound, code)
}

func All() []*Algorithm {
	n := int(C.pq_alg_count())
	out := make([]*Algorithm, 0, n+len(goKEMAlgorithms))
	for i := 0; i < n; i++ {
		if a := wrap(C.pq_alg_at(C.size_t(i))); a != nil {
			out = append(out, a)
		}
	}
	out = append(out, allGoKEM()...)
	return out
}

// ByOID resolves the algorithm OID stored in a certificate extension.
func ByOID(oid asn1.ObjectIdentifier) (*Algorithm, error) {
	for _, a := range All() {
		if a.OID().Equal(oid) {
			return a, nil
		}
	}
	return nil, fmt.Errorf("%w: oid %s", ErrNotFound, oid.String())
}

func (a *Algorithm) Name() string {
	if a.goKEM != nil {
		return a.goKEM.name
	}
	return C.GoString(a.p.name)
}
func (a *Algorithm) Version() string {
	if a.goKEM != nil {
		return a.goKEM.version
	}
	return C.GoString(a.p.version)
}
func (a *Algorithm) TLSCode() uint16 {
	if a.goKEM != nil {
		return 0
	}
	return uint16(a.p.tls_code)
}
func (a *Algorithm) Kind() Kind {
	if a.goKEM != nil {
		return KindKEM
	}
	return Kind(a.p.kind)
}
func (a *Algorithm) Input() Input {
	if a.goKEM != nil {
		return InputMessage
	}
	return Input(a.p.input)
}
func (a *Algorithm) IsPlaceholder() bool {
	if a.goKEM != nil {
		return false
	}
	return a.p.flags&C.uint32_t(1) != 0
}
func (a *Algorithm) Available() bool {
	if a.goKEM != nil {
		return true
	}
	return C.pq_alg_available(a.p) != 0
}
func (a *Algorithm) PublicKeySize() int {
	if a.goKEM != nil {
		return a.goKEM.publicKeySize()
	}
	return int(a.p.pk_len)
}
func (a *Algorithm) PrivateKeySize() int {
	if a.goKEM != nil {
		return a.goKEM.privateKeySize()
	}
	return int(a.p.sk_len)
}
func (a *Algorithm) SignatureSize() int {
	if a.goKEM != nil {
		return 0
	}
	return int(a.p.sig_len)
}
func (a *Algorithm) CiphertextSize() int {
	if a.goKEM != nil {
		return a.goKEM.ciphertextSize()
	}
	return int(a.p.ct_len)
}
func (a *Algorithm) SharedSecretSize() int {
	if a.goKEM != nil {
		return a.goKEM.sharedSecretSize()
	}
	return int(a.p.ss_len)
}

func (a *Algorithm) OID() asn1.ObjectIdentifier {
	if a.goKEM != nil {
		return a.goKEM.oid
	}
	oid, err := parseOID(C.GoString(a.p.oid))
	if err != nil {
		return nil
	}
	return oid
}

func (a *Algorithm) TLSName() string {
	if a.TLSCode() == 0 {
		return a.Name()
	}
	return fmt.Sprintf("%s(0x%04x)", a.Name(), a.TLSCode())
}

func (a *Algorithm) String() string {
	oid := a.OID()
	oidStr := ""
	if oid != nil {
		oidStr = oid.String()
	}
	return fmt.Sprintf("%s kind=%d tls=0x%04x oid=%s avail=%t",
		a.Name(), a.Kind(), a.TLSCode(), oidStr, a.Available())
}

type KeyPair struct {
	Public  *PublicKey
	Private *PrivateKey
}

type PublicKey struct {
	Algorithm *Algorithm
	Raw       []byte
}

type PrivateKey struct {
	Algorithm *Algorithm
	Raw       []byte
}

func (a *Algorithm) GenerateKey() (*KeyPair, error) {
	if !a.Available() {
		return nil, ErrNotImplemented
	}
	if a.goKEM != nil {
		pk, sk, err := a.goKEM.generateKey()
		if err != nil {
			return nil, err
		}
		return &KeyPair{
			Public:  &PublicKey{Algorithm: a, Raw: pk},
			Private: &PrivateKey{Algorithm: a, Raw: sk},
		}, nil
	}
	pkLen, skLen := a.PublicKeySize(), a.PrivateKeySize()
	if pkLen <= 0 || skLen <= 0 {
		return nil, fmt.Errorf("pqc: %s has no key sizes", a.Name())
	}
	pk := make([]byte, pkLen)
	sk := make([]byte, skLen)
	if st := C.pqc_call_keygen(a.p, cptr(pk), cptr(sk)); st != C.PQ_OK {
		return nil, statusErr("keygen", st)
	}
	return &KeyPair{
		Public:  &PublicKey{Algorithm: a, Raw: pk},
		Private: &PrivateKey{Algorithm: a, Raw: sk},
	}, nil
}

// DerivePublic calls the C pub_from_sk hook; keys must be deterministic bytes.
func (a *Algorithm) DerivePublic(priv *PrivateKey) (*PublicKey, error) {
	if err := a.checkPrivate(priv); err != nil {
		return nil, err
	}
	if a.goKEM != nil {
		pk, err := a.goKEM.derivePublic(priv.Raw)
		if err != nil {
			return nil, err
		}
		return &PublicKey{Algorithm: a, Raw: pk}, nil
	}
	pk := make([]byte, a.PublicKeySize())
	if st := C.pqc_call_pub_from_sk(a.p, cptr(priv.Raw), cptr(pk)); st != C.PQ_OK {
		return nil, statusErr("pub_from_sk", st)
	}
	return &PublicKey{Algorithm: a, Raw: pk}, nil
}

func (a *Algorithm) ParsePublicKey(raw []byte) (*PublicKey, error) {
	if a.Kind() != KindSig && a.Kind() != KindKEM {
		return nil, ErrKind
	}
	if len(raw) != a.PublicKeySize() {
		return nil, fmt.Errorf("%w: public key %d != %d", ErrLength, len(raw), a.PublicKeySize())
	}
	return &PublicKey{Algorithm: a, Raw: append([]byte(nil), raw...)}, nil
}

func (a *Algorithm) ParsePrivateKey(raw []byte) (*PrivateKey, error) {
	if len(raw) != a.PrivateKeySize() {
		return nil, fmt.Errorf("%w: private key %d != %d", ErrLength, len(raw), a.PrivateKeySize())
	}
	return &PrivateKey{Algorithm: a, Raw: append([]byte(nil), raw...)}, nil
}

// Sign signs digest exactly as passed.  The TLS stack passes the SHA-512
// CertificateVerify digest; the C implementation must not hash it again.
func (a *Algorithm) Sign(priv *PrivateKey, digest []byte) ([]byte, error) {
	if a.goKEM != nil {
		return nil, ErrKind
	}
	if a.Kind() != KindSig {
		return nil, ErrKind
	}
	if !a.Available() {
		return nil, ErrNotImplemented
	}
	if err := a.checkPrivate(priv); err != nil {
		return nil, err
	}
	sig := make([]byte, a.SignatureSize())
	if st := C.pqc_call_sign(a.p, cptr(priv.Raw), cptr(digest),
		C.size_t(len(digest)), cptr(sig), C.size_t(len(sig))); st != C.PQ_OK {
		return nil, statusErr("sign", st)
	}
	return sig, nil
}

func (a *Algorithm) Verify(pub *PublicKey, digest, sig []byte) error {
	if a.goKEM != nil {
		return ErrKind
	}
	if a.Kind() != KindSig {
		return ErrKind
	}
	if !a.Available() {
		return ErrNotImplemented
	}
	if pub == nil || pub.Algorithm == nil || pub.Algorithm.Name() != a.Name() ||
		len(pub.Raw) != a.PublicKeySize() {
		return ErrInvalidKey
	}
	if len(sig) != a.SignatureSize() {
		return fmt.Errorf("%w: signature %d != %d", ErrLength, len(sig), a.SignatureSize())
	}
	if st := C.pqc_call_verify(a.p, cptr(pub.Raw), cptr(digest),
		C.size_t(len(digest)), cptr(sig), C.size_t(len(sig))); st != C.PQ_OK {
		return statusErr("verify", st)
	}
	return nil
}

func (a *Algorithm) Encapsulate(pub *PublicKey) (ct, ss []byte, err error) {
	if a.goKEM != nil {
		if pub == nil || pub.Algorithm == nil || pub.Algorithm.Name() != a.Name() ||
			len(pub.Raw) != a.PublicKeySize() {
			return nil, nil, ErrInvalidKey
		}
		return a.goKEM.encapsulate(pub.Raw)
	}
	if a.Kind() != KindKEM {
		return nil, nil, ErrKind
	}
	if !a.Available() {
		return nil, nil, ErrNotImplemented
	}
	if pub == nil || pub.Algorithm == nil || pub.Algorithm.Name() != a.Name() ||
		len(pub.Raw) != a.PublicKeySize() {
		return nil, nil, ErrInvalidKey
	}
	ct = make([]byte, a.CiphertextSize())
	ss = make([]byte, a.SharedSecretSize())
	if st := C.pqc_call_encaps(a.p, cptr(pub.Raw),
		cptr(ct), C.size_t(len(ct)), cptr(ss), C.size_t(len(ss))); st != C.PQ_OK {
		return nil, nil, statusErr("encaps", st)
	}
	return ct, ss, nil
}

func (a *Algorithm) Decapsulate(priv *PrivateKey, ct []byte) ([]byte, error) {
	if a.goKEM != nil {
		if err := a.checkPrivate(priv); err != nil {
			return nil, err
		}
		return a.goKEM.decapsulate(priv.Raw, ct)
	}
	if a.Kind() != KindKEM {
		return nil, ErrKind
	}
	if !a.Available() {
		return nil, ErrNotImplemented
	}
	if err := a.checkPrivate(priv); err != nil {
		return nil, err
	}
	if len(ct) != a.CiphertextSize() {
		return nil, fmt.Errorf("%w: ciphertext %d != %d", ErrLength, len(ct), a.CiphertextSize())
	}
	ss := make([]byte, a.SharedSecretSize())
	if st := C.pqc_call_decaps(a.p, cptr(priv.Raw), cptr(ct),
		C.size_t(len(ct)), cptr(ss), C.size_t(len(ss))); st != C.PQ_OK {
		return nil, statusErr("decaps", st)
	}
	return ss, nil
}

func (a *Algorithm) checkPrivate(priv *PrivateKey) error {
	if priv == nil || priv.Algorithm == nil || priv.Algorithm.Name() != a.Name() ||
		len(priv.Raw) != a.PrivateKeySize() {
		return ErrInvalidKey
	}
	return nil
}

func cptr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

func statusErr(op string, st C.int) error {
	switch st {
	case C.PQ_OK:
		return nil
	case C.PQ_ERR_NOTIMPL:
		return fmt.Errorf("%s: %w", op, ErrNotImplemented)
	case C.PQ_ERR_VERIFY:
		return fmt.Errorf("%s: verification failed", op)
	default:
		return fmt.Errorf("%s: %s (%d)", op, C.GoString(C.pq_status_string(st)), int(st))
	}
}

func parseOID(s string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(s, ".")
	oid := make(asn1.ObjectIdentifier, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			return nil, fmt.Errorf("pqc: empty OID component in %q", s)
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("pqc: invalid OID %q", s)
		}
		oid = append(oid, n)
	}
	if len(oid) < 2 {
		return nil, fmt.Errorf("pqc: OID %q has too few components", s)
	}
	return oid, nil
}
