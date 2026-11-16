package pqsig

import (
	"crypto/sha256"
	"testing"
)

func TestTLSSignatureCodes(t *testing.T) {
	seen := make(map[uint16]string)
	for _, alg := range All() {
		code, ok := TLSCode(alg)
		if !ok {
			t.Fatalf("%s has no TLS code", alg.Name())
		}
		if other, ok := seen[code]; ok {
			t.Fatalf("TLS code 0x%04x used by %s and %s", code, other, alg.Name())
		}
		seen[code] = alg.Name()
		got, ok := AlgorithmByTLSCode(code)
		if !ok || got.Name() != alg.Name() {
			t.Fatalf("code 0x%04x resolved to %v, want %s", code, got, alg.Name())
		}
	}
	if _, ok := AlgorithmByTLSCode(0xFFFE); ok {
		t.Fatal("unknown TLS code was accepted")
	}
}

func TestCertificateVerifyInput(t *testing.T) {
	const context = "TLS 1.3, server CertificateVerify"
	transcript := sha256.Sum256([]byte("handshake transcript"))
	input := CertificateVerifyInput(context, transcript[:])
	if len(input) != 64+len(context)+1+len(transcript) {
		t.Fatalf("input len=%d", len(input))
	}
	for i := 0; i < 64; i++ {
		if input[i] != 0x20 {
			t.Fatalf("prefix[%d]=0x%02x", i, input[i])
		}
	}
	if string(input[64:64+len(context)]) != context {
		t.Fatal("context mismatch")
	}
	if input[64+len(context)] != 0 {
		t.Fatal("separator mismatch")
	}
}

func TestSignAllTLSSignatureLevels(t *testing.T) {
	const context = "TLS 1.3, server CertificateVerify"
	transcript := sha256.Sum256([]byte("nine-level TLS certificate verify test"))
	input := CertificateVerifyInput(context, transcript[:])
	wrongInput := CertificateVerifyInput("TLS 1.3, client CertificateVerify", transcript[:])

	for _, alg := range All() {
		alg := alg
		t.Run(alg.Name(), func(t *testing.T) {
			t.Parallel()
			kp, err := alg.GenerateKey()
			if err != nil {
				t.Fatal(err)
			}
			sig, err := alg.Sign(kp.Private, input)
			if err != nil {
				t.Fatal(err)
			}
			if err := alg.Verify(kp.Public, input, sig); err != nil {
				t.Fatalf("TLS CertificateVerify input: %v", err)
			}
			if err := alg.Verify(kp.Public, wrongInput, sig); err == nil {
				t.Fatal("accepted a different CertificateVerify context")
			}
			if err := alg.Verify(kp.Public, input, append([]byte(nil), sig...)); err != nil {
				t.Fatalf("copy verify: %v", err)
			}
		})
	}
}
