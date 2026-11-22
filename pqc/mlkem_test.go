package pqc

import (
	"bytes"
	"testing"
)

func TestMLKEMRoundTrip(t *testing.T) {
	for _, name := range []string{"ML-KEM-768", "ML-KEM-1024"} {
		alg, err := Lookup(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if alg.Kind() != KindKEM || !alg.Available() {
			t.Fatalf("%s: kind=%v available=%v", name, alg.Kind(), alg.Available())
		}
		if alg.PrivateKeySize() != 64 || alg.SharedSecretSize() != 32 {
			t.Fatalf("%s: sizes sk=%d ss=%d", name, alg.PrivateKeySize(), alg.SharedSecretSize())
		}
		kp, err := alg.GenerateKey()
		if err != nil {
			t.Fatalf("%s keygen: %v", name, err)
		}
		if len(kp.Public.Raw) != alg.PublicKeySize() || len(kp.Private.Raw) != alg.PrivateKeySize() {
			t.Fatalf("%s: key sizes", name)
		}
		ct, ss1, err := alg.Encapsulate(kp.Public)
		if err != nil {
			t.Fatalf("%s encaps: %v", name, err)
		}
		if len(ct) != alg.CiphertextSize() || len(ss1) != alg.SharedSecretSize() {
			t.Fatalf("%s: ciphertext/shared sizes", name)
		}
		ss2, err := alg.Decapsulate(kp.Private, ct)
		if err != nil {
			t.Fatalf("%s decaps: %v", name, err)
		}
		if !bytes.Equal(ss1, ss2) {
			t.Fatalf("%s: shared secrets differ", name)
		}
		if _, err := alg.Decapsulate(kp.Private, append([]byte(nil), ct[:len(ct)-1]...)); err == nil {
			t.Fatalf("%s: truncated ciphertext accepted", name)
		}
	}
}

func TestMLKEMResolve(t *testing.T) {
	alg, err := Lookup("ML-KEM-768")
	if err != nil {
		t.Fatal(err)
	}
	byOID, err := ByOID(alg.OID())
	if err != nil || byOID.Name() != alg.Name() {
		t.Fatalf("ByOID: %v %v", byOID, err)
	}
	found := false
	for _, a := range All() {
		if a.Name() == alg.Name() {
			found = true
		}
	}
	if !found {
		t.Fatal("All() does not contain ML-KEM-768")
	}
}

func TestMLKEMDerivePublic(t *testing.T) {
	alg, err := Lookup("ML-KEM-768")
	if err != nil {
		t.Fatal(err)
	}
	kp, err := alg.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := alg.DerivePublic(kp.Private)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub.Raw, kp.Public.Raw) {
		t.Fatal("derived public key differs")
	}
}
