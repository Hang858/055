package pqc

import (
	"bytes"
	"errors"
	"testing"
)

func TestRegistryAndPlaceholder(t *testing.T) {
	all := All()
	if len(all) < 4 {
		t.Fatalf("All() = %d algorithms, want at least 4", len(all))
	}
	bit, err := Lookup("BiT")
	if err != nil {
		t.Fatal(err)
	}
	if bit.Kind() != KindSig || bit.TLSCode() != 0xFE20 {
		t.Fatalf("BiT metadata: kind=%v tls=0x%04x", bit.Kind(), bit.TLSCode())
	}
	if bit.Available() || !bit.IsPlaceholder() {
		t.Fatal("BiT placeholder must be visible but unavailable")
	}
	if _, err := bit.GenerateKey(); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("BiT GenerateKey error = %v, want ErrNotImplemented", err)
	}
	byCode, err := ByTLSCode(0xFE20)
	if err != nil || byCode.Name() != "BiT" {
		t.Fatalf("ByTLSCode: %v %v", byCode, err)
	}
	if _, err := Lookup("does-not-exist"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown lookup error = %v", err)
	}
}

func TestPlaceholderSignature(t *testing.T) {
	alg, err := Lookup("PLACEHOLDER-SIG")
	if err != nil {
		t.Fatal(err)
	}
	if !alg.Available() {
		t.Fatal("placeholder signature should be available for tests")
	}
	if alg.Input() != InputDigest {
		t.Fatalf("placeholder signature input = %v, want digest", alg.Input())
	}
	if alg.PublicKeySize() != 32 || alg.PrivateKeySize() != 32 || alg.SignatureSize() != 64 {
		t.Fatalf("unexpected sizes: %d/%d/%d", alg.PublicKeySize(), alg.PrivateKeySize(), alg.SignatureSize())
	}
	kp, err := alg.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	digest := bytes.Repeat([]byte{0x42}, 64)
	sig, err := alg.Sign(kp.Private, digest)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != alg.SignatureSize() {
		t.Fatalf("signature len = %d", len(sig))
	}
	if err := alg.Verify(kp.Public, digest, sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
	bad := append([]byte(nil), sig...)
	bad[0] ^= 0x01
	if err := alg.Verify(kp.Public, digest, bad); err == nil {
		t.Fatal("tampered signature accepted")
	}
	if err := alg.Verify(kp.Public, []byte("different digest"), sig); err == nil {
		t.Fatal("different digest accepted")
	}
	derived, err := alg.DerivePublic(kp.Private)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(derived.Raw, kp.Public.Raw) {
		t.Fatal("derived public key mismatch")
	}
	parsed, err := alg.ParsePrivateKey(kp.Private.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alg.Sign(parsed, digest); err != nil {
		t.Fatalf("sign with parsed key: %v", err)
	}
}

func TestByOID(t *testing.T) {
	alg, err := ByOID([]int{1, 3, 6, 1, 4, 1, 54321, 99, 2})
	if err != nil {
		t.Fatal(err)
	}
	if alg.Name() != "PLACEHOLDER-KEM" || alg.Kind() != KindKEM {
		t.Fatalf("ByOID = %s kind=%v", alg.Name(), alg.Kind())
	}
}

func TestPlaceholderKEM(t *testing.T) {
	alg, err := Lookup("PLACEHOLDER-KEM")
	if err != nil {
		t.Fatal(err)
	}
	if alg.Kind() != KindKEM || !alg.Available() {
		t.Fatal("KEM placeholder not available")
	}
	kp, err := alg.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ct, ss1, err := alg.Encapsulate(kp.Public)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) != alg.CiphertextSize() || len(ss1) != alg.SharedSecretSize() {
		t.Fatalf("KEM sizes: ct=%d ss=%d", len(ct), len(ss1))
	}
	ss2, err := alg.Decapsulate(kp.Private, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ss1, ss2) {
		t.Fatal("shared secrets differ")
	}
	ct[0] ^= 0x01
	ss3, err := alg.Decapsulate(kp.Private, ct)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ss1, ss3) {
		t.Fatal("tampered ciphertext produced the original secret")
	}
}
