package pqsig

import (
	"bytes"
	"testing"
)

func TestRegistryHasAllAlgorithms(t *testing.T) {
	want := []string{
		"Dilithium2", "Dilithium3", "Dilithium5",
		"SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
		"SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
		"SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f",
	}
	got := Names()
	if len(got) != len(want) {
		t.Fatalf("Names() = %v, want %v", got, want)
	}
	for _, name := range want {
		if _, ok := ByName(name); !ok {
			t.Errorf("ByName(%q) not found", name)
		}
	}
}

func TestSignVerifyAllAlgorithms(t *testing.T) {
	msg := []byte("pqsig abstraction test message")
	for _, alg := range All() {
		alg := alg
		t.Run(alg.Name(), func(t *testing.T) {
			t.Parallel()
			kp, err := alg.GenerateKey()
			if err != nil {
				t.Fatal(err)
			}
			if len(kp.Public.Raw) != alg.PublicKeySize() {
				t.Fatalf("public key len=%d want=%d", len(kp.Public.Raw), alg.PublicKeySize())
			}
			if len(kp.Private.Raw) != alg.PrivateKeySize() {
				t.Fatalf("private key len=%d want=%d", len(kp.Private.Raw), alg.PrivateKeySize())
			}
			pub, err := alg.ParsePublicKey(kp.Public.Raw)
			if err != nil {
				t.Fatal(err)
			}
			priv, err := alg.ParsePrivateKey(kp.Private.Raw)
			if err != nil {
				t.Fatal(err)
			}
			sig, err := alg.Sign(priv, msg)
			if err != nil {
				t.Fatal(err)
			}
			if len(sig) != alg.SignatureSize() {
				t.Fatalf("signature len=%d want=%d", len(sig), alg.SignatureSize())
			}
			if err := alg.Verify(pub, msg, sig); err != nil {
				t.Fatalf("verify: %v", err)
			}
			if err := alg.Verify(pub, []byte("different message"), sig); err == nil {
				t.Fatal("verify accepted a different message")
			}
			bad := append([]byte(nil), sig...)
			bad[0] ^= 0x01
			if err := alg.Verify(pub, msg, bad); err == nil {
				t.Fatal("verify accepted a tampered signature")
			}
			// A key from another algorithm must be rejected before Verify.
			if alg.Name() != "Dilithium2" {
				other, _ := ByName("Dilithium2")
				otherKP, err := other.GenerateKey()
				if err != nil {
					t.Fatal(err)
				}
				if err := alg.Verify(otherKP.Public, msg, sig); err == nil {
					t.Fatal("verify accepted a key from another algorithm")
				}
			}
		})
	}
}

func TestKeyRoundTrip(t *testing.T) {
	for _, name := range []string{"Dilithium2", "SLH-DSA-SHA2-128s"} {
		alg, _ := ByName(name)
		kp, err := alg.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		pub, err := alg.ParsePublicKey(append([]byte(nil), kp.Public.Raw...))
		if err != nil {
			t.Fatal(err)
		}
		derived, err := kp.Private.Public()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(derived.Raw, pub.Raw) {
			t.Fatalf("%s derived public key mismatch", name)
		}
		if !bytes.Equal(pub.Raw, kp.Public.Raw) {
			t.Fatalf("%s public key round trip mismatch", name)
		}
		priv, err := alg.ParsePrivateKey(append([]byte(nil), kp.Private.Raw...))
		if err != nil {
			t.Fatal(err)
		}
		sig, err := alg.Sign(priv, []byte("round trip"))
		if err != nil {
			t.Fatal(err)
		}
		if err := alg.Verify(pub, []byte("round trip"), sig); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAlgorithmExtensionRoundTrip(t *testing.T) {
	for _, alg := range All() {
		der, err := EncodeAlgorithmExtension(alg)
		if err != nil {
			t.Fatalf("%s encode: %v", alg.Name(), err)
		}
		got, err := DecodeAlgorithmExtension(der)
		if err != nil {
			t.Fatalf("%s decode: %v", alg.Name(), err)
		}
		if got.Name() != alg.Name() {
			t.Fatalf("%s decoded as %s", alg.Name(), got.Name())
		}
	}
	if _, err := DecodeAlgorithmExtension([]byte{0x06, 0x03, 0x2a, 0x03, 0x04}); err == nil {
		t.Fatal("unknown OID was accepted")
	}
	if _, err := DecodeAlgorithmExtension([]byte{0x06, 0x03, 0x2a, 0x03}); err == nil {
		t.Fatal("truncated OID was accepted")
	}
}
