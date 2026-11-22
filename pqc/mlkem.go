package pqc

import (
	"crypto/mlkem"
	"encoding/asn1"
	"fmt"
)

// goKEMBackend 是纯 Go 的 ML-KEM 后端。C 注册表仍是默认入口；ML-KEM 由
// Go 标准库实现，避免为了一个算法引入 C 依赖。
type goKEMBackend struct {
	name    string
	version string
	oid     asn1.ObjectIdentifier
	level   int
}

func (b *goKEMBackend) publicKeySize() int {
	if b.level == 1024 {
		return 1568
	}
	return 1184
}

func (b *goKEMBackend) privateKeySize() int { return mlkem.SeedSize }
func (b *goKEMBackend) ciphertextSize() int {
	if b.level == 1024 {
		return 1568
	}
	return 1088
}
func (b *goKEMBackend) sharedSecretSize() int { return mlkem.SharedKeySize }

func (b *goKEMBackend) generateKey() (pk, sk []byte, err error) {
	if b.level == 1024 {
		dk, err := mlkem.GenerateKey1024()
		if err != nil {
			return nil, nil, err
		}
		return dk.EncapsulationKey().Bytes(), dk.Bytes(), nil
	}
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, nil, err
	}
	return dk.EncapsulationKey().Bytes(), dk.Bytes(), nil
}

func (b *goKEMBackend) derivePublic(sk []byte) ([]byte, error) {
	if b.level == 1024 {
		dk, err := mlkem.NewDecapsulationKey1024(sk)
		if err != nil {
			return nil, err
		}
		return dk.EncapsulationKey().Bytes(), nil
	}
	dk, err := mlkem.NewDecapsulationKey768(sk)
	if err != nil {
		return nil, err
	}
	return dk.EncapsulationKey().Bytes(), nil
}

func (b *goKEMBackend) encapsulate(pk []byte) (ct, ss []byte, err error) {
	if len(pk) != b.publicKeySize() {
		return nil, nil, fmt.Errorf("%w: public key %d != %d", ErrLength, len(pk), b.publicKeySize())
	}
	var ek interface {
		Encapsulate() ([]byte, []byte)
	}
	if b.level == 1024 {
		k, err := mlkem.NewEncapsulationKey1024(pk)
		if err != nil {
			return nil, nil, err
		}
		ek = k
	} else {
		k, err := mlkem.NewEncapsulationKey768(pk)
		if err != nil {
			return nil, nil, err
		}
		ek = k
	}
	ss, ct = ek.Encapsulate()
	return ct, ss, nil
}

func (b *goKEMBackend) decapsulate(sk, ct []byte) ([]byte, error) {
	if len(ct) != b.ciphertextSize() {
		return nil, fmt.Errorf("%w: ciphertext %d != %d", ErrLength, len(ct), b.ciphertextSize())
	}
	if b.level == 1024 {
		dk, err := mlkem.NewDecapsulationKey1024(sk)
		if err != nil {
			return nil, err
		}
		return dk.Decapsulate(ct)
	}
	dk, err := mlkem.NewDecapsulationKey768(sk)
	if err != nil {
		return nil, err
	}
	return dk.Decapsulate(ct)
}

var goKEMAlgorithms = []*goKEMBackend{
	{
		name:    "ML-KEM-768",
		version: "FIPS 203",
		oid:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2},
		level:   768,
	},
	{
		name:    "ML-KEM-1024",
		version: "FIPS 203",
		oid:     asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 3},
		level:   1024,
	},
}

func lookupGoKEM(name string) *Algorithm {
	for _, b := range goKEMAlgorithms {
		if b.name == name {
			return &Algorithm{goKEM: b}
		}
	}
	return nil
}

func allGoKEM() []*Algorithm {
	out := make([]*Algorithm, 0, len(goKEMAlgorithms))
	for _, b := range goKEMAlgorithms {
		out = append(out, &Algorithm{goKEM: b})
	}
	return out
}
