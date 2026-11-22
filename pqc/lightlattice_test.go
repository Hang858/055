package pqc

import (
	"bytes"
	"os"
	"testing"
)

func TestLightLatticeSign(t *testing.T) {
	if os.Getenv("LIGHTLATTICE_LIBDIR") == "" {
		t.Skip("set LIGHTLATTICE_LIBDIR to pqc/vendor/lib")
	}
	for _, name := range []string{"BiT-128", "BiT-256", "BiT-512"} {
		alg, err := Lookup(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if alg.Kind() != KindSig || !alg.Available() {
			t.Fatalf("%s: kind=%v available=%v", name, alg.Kind(), alg.Available())
		}
		kp, err := alg.GenerateKey()
		if err != nil {
			t.Fatalf("%s keygen: %v", name, err)
		}
		msg := bytes.Repeat([]byte{0x42}, 64)
		sig, err := alg.Sign(kp.Private, msg)
		if err != nil {
			t.Fatalf("%s sign: %v", name, err)
		}
		if err := alg.Verify(kp.Public, msg, sig); err != nil {
			t.Fatalf("%s verify: %v", name, err)
		}
		msg[0] ^= 1
		if err := alg.Verify(kp.Public, msg, sig); err == nil {
			t.Fatalf("%s: modified message accepted", name)
		}
	}
}

func TestLightLatticeKEM(t *testing.T) {
	if os.Getenv("LIGHTLATTICE_LIBDIR") == "" {
		t.Skip("set LIGHTLATTICE_LIBDIR to pqc/vendor/lib")
	}
	for _, name := range []string{"POLARLAC-128", "POLARLAC-256", "POLARLAC-512", "POLARLAC-Light", "POLARLAC-512-Star"} {
		alg, err := Lookup(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if alg.Kind() != KindKEM || !alg.Available() {
			t.Fatalf("%s: kind=%v available=%v", name, alg.Kind(), alg.Available())
		}
		kp, err := alg.GenerateKey()
		if err != nil {
			t.Fatalf("%s keygen: %v", name, err)
		}
		ct, ss1, err := alg.Encapsulate(kp.Public)
		if err != nil {
			t.Fatalf("%s encaps: %v", name, err)
		}
		ss2, err := alg.Decapsulate(kp.Private, ct)
		if err != nil {
			t.Fatalf("%s decaps: %v", name, err)
		}
		if !bytes.Equal(ss1, ss2) {
			t.Fatalf("%s: shared secrets differ", name)
		}
	}
}
