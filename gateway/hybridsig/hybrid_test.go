package hybridsig

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/tjfoc/gmsm/sm2"
)

func TestHybridSignatureRequiresBothComponents(t *testing.T) {
	for _, tc := range []struct {
		name   string
		level  Level
		scheme sign.Scheme
	}{
		{"128", Level128, mldsa44.Scheme()},
		{"256", Level256, mldsa87.Scheme()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			classical, err := sm2.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			pqPublic, pqPrivate, err := tc.scheme.GenerateKey()
			if err != nil {
				t.Fatal(err)
			}
			message := []byte("TLS 1.3 CertificateVerify transcript input")
			sig, err := Sign(tc.level, classical, pqPrivate, message)
			if err != nil {
				t.Fatal(err)
			}
			if err := Verify(tc.level, &classical.PublicKey, pqPublic, message, sig); err != nil {
				t.Fatalf("valid hybrid signature: %v", err)
			}
			modified := append([]byte(nil), sig...)
			modified[len(modified)-1] ^= 1
			modifiedSM2 := append([]byte(nil), sig...)
			modifiedSM2[8] ^= 1
			for name, candidate := range map[string][]byte{
				"missing PQ signature":   sig[:len(sig)-tc.scheme.SignatureSize()],
				"modified PQ signature":  modified,
				"modified SM2 signature": modifiedSM2,
			} {
				if err := Verify(tc.level, &classical.PublicKey, pqPublic, message, candidate); err == nil {
					t.Errorf("accepted %s", name)
				}
			}
			if err := Verify(tc.level, &classical.PublicKey, pqPublic, []byte("different transcript"), sig); err == nil {
				t.Error("accepted different message")
			}
		})
	}
}

func TestHybridSignatureRejectsWrongParameterSet(t *testing.T) {
	classical, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, pqPrivate, err := mldsa44.Scheme().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Sign(Level256, classical, pqPrivate, []byte("message")); err == nil {
		t.Fatal("accepted ML-DSA-44 key for 256-bit profile")
	}
}

func TestHybridSignatureRejectsWrongPublicKeysAndEncoding(t *testing.T) {
	classical, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherClassical, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pqPublic, pqPrivate, err := mldsa44.Scheme().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	otherPQ, _, err := mldsa44.Scheme().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("CertificateVerify input")
	signature, err := Sign(Level128, classical, pqPrivate, message)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		classical *sm2.PublicKey
		pq        sign.PublicKey
		signature []byte
	}{
		{"wrong SM2 public key", &otherClassical.PublicKey, pqPublic, signature},
		{"wrong ML-DSA public key", &classical.PublicKey, otherPQ, signature},
		{"one byte before DER", &classical.PublicKey, pqPublic, append([]byte{0}, signature...)},
		{"truncated PQ tail", &classical.PublicKey, pqPublic, signature[:len(signature)-1]},
		{"extra trailing byte", &classical.PublicKey, pqPublic, append(bytes.Clone(signature), 0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := Verify(Level128, tc.classical, tc.pq, message, tc.signature); err == nil {
				t.Fatal("accepted a signature with the wrong public key or encoding")
			}
		})
	}
}

func FuzzHybridSignatureRejectsMalformedInput(f *testing.F) {
	classical, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	pqPublic, pqPrivate, err := mldsa44.Scheme().GenerateKey()
	if err != nil {
		f.Fatal(err)
	}
	message := []byte("CertificateVerify input")
	valid, err := Sign(Level128, classical, pqPrivate, message)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x00})
	f.Fuzz(func(t *testing.T, candidate []byte) {
		err := Verify(Level128, &classical.PublicKey, pqPublic, message, candidate)
		if bytes.Equal(candidate, valid) {
			if err != nil {
				t.Fatalf("valid signature rejected: %v", err)
			}
		} else if err == nil {
			t.Fatal("malformed signature accepted")
		}
	})
}
