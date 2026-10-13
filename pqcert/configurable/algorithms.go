package main

import (
	"bytes"
	"crypto/rand"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/cloudflare/circl/kem"
	kems "github.com/cloudflare/circl/kem/schemes"
	"github.com/cloudflare/circl/sign"
	signs "github.com/cloudflare/circl/sign/schemes"
	"github.com/tjfoc/gmsm/sm2"
	gx "github.com/tjfoc/gmsm/x509"
)

var signatureNames = []string{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f", "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f"}
var kemNames = []string{"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}

func canonicalName(name string) string {
	switch name {
	case "Dilithium2":
		return "ML-DSA-44"
	case "Dilithium3":
		return "ML-DSA-65"
	case "Dilithium5":
		return "ML-DSA-87"
	case "Kyber512":
		return "ML-KEM-512"
	case "Kyber768":
		return "ML-KEM-768"
	case "Kyber1024":
		return "ML-KEM-1024"
	default:
		return name
	}
}

type Algorithm struct {
	Name string
	OID  asn1.ObjectIdentifier
	Sign sign.Scheme
	KEM  kem.Scheme
}

func algorithm(name string) (Algorithm, bool) {
	name = canonicalName(name)
	for i, n := range signatureNames {
		if n == name {
			oid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 54321, 20, 1, i + 1}
			if i < 3 {
				oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17 + i}
			}
			return Algorithm{n, oid, signs.ByName(n), nil}, true
		}
	}
	for i, n := range kemNames {
		if n == name {
			return Algorithm{n, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, i + 1}, nil, kems.ByName(n)}, true
		}
	}
	return Algorithm{}, false
}
func importPublic(name, path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) > 1024*1024 {
		return nil, fmt.Errorf("公钥文件超过1 MiB")
	}
	if name == "SM2" {
		var pub *sm2.PublicKey
		if strings.Contains(string(data), "[SM2]") {
			s := section(string(data), "SM2")
			x, okx := new(big.Int).SetString(value(s, "X"), 16)
			y, oky := new(big.Int).SetString(value(s, "Y"), 16)
			if !okx || !oky || !validSM2Point(x, y) {
				return nil, fmt.Errorf("SM2公钥坐标无效")
			}
			pub = &sm2.PublicKey{Curve: sm2.P256Sm2(), X: x, Y: y}
		} else {
			b, rest := pem.Decode(data)
			if b == nil || b.Type != "PUBLIC KEY" || len(strings.TrimSpace(string(rest))) != 0 {
				return nil, fmt.Errorf("SM2公钥须为PUBLIC KEY PEM或原项目文本")
			}
			pub, err = gx.ParseSm2PublicKey(b.Bytes)
			if err != nil {
				return nil, err
			}
		}
		if pub == nil || pub.X == nil || pub.Y == nil || !validSM2Point(pub.X, pub.Y) {
			return nil, fmt.Errorf("SM2公钥坐标无效")
		}
		return gx.MarshalSm2PublicKey(pub)
	}
	a, ok := algorithm(name)
	if !ok {
		return nil, fmt.Errorf("未知算法")
	}
	b, rest := pem.Decode(data)
	if b == nil {
		if bytes.HasPrefix(bytes.TrimSpace(data), []byte("[")) {
			return nil, fmt.Errorf("旧版公钥文本不能按标准ML-DSA/ML-KEM导入，请提供新程序生成的公钥PEM")
		}
		return nil, fmt.Errorf("PQC公钥须为带算法标识的PQC PUBLIC KEY PEM；无标识的原始公钥不能安全区分旧算法")
	}
	if b.Type != "PQC PUBLIC KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("应使用PQC PUBLIC KEY PEM")
	}
	if b.Headers["Algorithm"] != a.Name {
		return nil, fmt.Errorf("PQC公钥算法标识缺失或不匹配，要求Algorithm: %s", a.Name)
	}
	raw := b.Bytes
	if a.Sign != nil {
		_, err = a.Sign.UnmarshalBinaryPublicKey(raw)
	} else {
		_, err = a.KEM.UnmarshalBinaryPublicKey(raw)
	}
	if err != nil {
		return nil, err
	}
	return raw, nil
}
func section(text, tag string) string {
	pos := strings.Index(text, "["+tag+"]")
	if pos < 0 {
		return ""
	}
	s := text[pos+len(tag)+2:]
	if end := strings.Index(s, "["); end >= 0 {
		s = s[:end]
	}
	return s
}
func value(text, key string) string {
	for _, line := range strings.Split(text, "\n") {
		p := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(p) == 2 && strings.TrimSpace(p[0]) == key {
			return strings.TrimSpace(p[1])
		}
	}
	return ""
}

type PQKey struct {
	Public  []byte
	Private []byte
	Signer  sign.PrivateKey
}

func makePQKey(n NodeConfig) (PQKey, error) {
	if n.PublicKeyFile != "" {
		p, err := importPublic(n.Algorithm, n.PublicKeyFile)
		return PQKey{Public: p}, err
	}
	a, _ := algorithm(n.Algorithm)
	if a.Sign != nil {
		pk, sk, err := a.Sign.GenerateKey()
		if err != nil {
			return PQKey{}, err
		}
		p, err := pk.MarshalBinary()
		if err != nil {
			return PQKey{}, err
		}
		s, err := sk.MarshalBinary()
		return PQKey{p, s, sk}, err
	}
	pk, sk, err := a.KEM.GenerateKeyPair()
	if err != nil {
		return PQKey{}, err
	}
	p, err := pk.MarshalBinary()
	if err != nil {
		return PQKey{}, err
	}
	s, err := sk.MarshalBinary()
	return PQKey{Public: p, Private: s}, err
}
func makeSM2Key(n NodeConfig) (*sm2.PublicKey, *sm2.PrivateKey, error) {
	if n.PublicKeyFile != "" {
		raw, err := importPublic("SM2", n.PublicKeyFile)
		if err != nil {
			return nil, nil, err
		}
		pub, err := gx.ParseSm2PublicKey(raw)
		return pub, nil, err
	}
	sk, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return &sk.PublicKey, sk, nil
}

func validSM2Point(x, y *big.Int) bool {
	curve := sm2.P256Sm2()
	p := curve.Params().P
	return x != nil && y != nil && x.Sign() >= 0 && y.Sign() >= 0 && x.Cmp(p) < 0 && y.Cmp(p) < 0 && curve.IsOnCurve(x, y)
}
