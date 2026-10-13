package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	gx "github.com/tjfoc/gmsm/x509"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestUnmarkedPQPublicKeyImportRejected(t *testing.T) {
	a, _ := algorithm("Dilithium2")
	pk, _ := a.Sign.DeriveKey(make([]byte, a.Sign.SeedSize()))
	raw, err := pk.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "public.bin")
	if err = os.WriteFile(p, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := importPublic("ML-DSA-44", p); err == nil || !strings.Contains(err.Error(), "算法标识") {
		t.Fatalf("unmarked public key must be rejected: %v", err)
	}
}

func TestStandardPQPublicKeyPEMRequiresMatchingAlgorithmHeader(t *testing.T) {
	a, _ := algorithm("ML-DSA-44")
	pk, _, err := a.Sign.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := pk.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "public.pem")
	for _, header := range []string{"", "ML-DSA-65", "ML-DSA-44"} {
		b := pem.EncodeToMemory(&pem.Block{Type: "PQC PUBLIC KEY", Headers: map[string]string{"Algorithm": header}, Bytes: raw})
		if err = os.WriteFile(p, b, 0600); err != nil {
			t.Fatal(err)
		}
		_, err = importPublic("ML-DSA-44", p)
		if (err == nil) != (header == "ML-DSA-44") {
			t.Fatalf("header %q: %v", header, err)
		}
	}
}

func TestStandardAlgorithmsAndLegacyAliases(t *testing.T) {
	cases := []struct{ input, want, oid string }{
		{"ML-DSA-44", "ML-DSA-44", "2.16.840.1.101.3.4.3.17"},
		{"Dilithium2", "ML-DSA-44", "2.16.840.1.101.3.4.3.17"},
		{"ML-DSA-65", "ML-DSA-65", "2.16.840.1.101.3.4.3.18"},
		{"Dilithium3", "ML-DSA-65", "2.16.840.1.101.3.4.3.18"},
		{"ML-DSA-87", "ML-DSA-87", "2.16.840.1.101.3.4.3.19"},
		{"Dilithium5", "ML-DSA-87", "2.16.840.1.101.3.4.3.19"},
		{"ML-KEM-512", "ML-KEM-512", "2.16.840.1.101.3.4.4.1"},
		{"Kyber512", "ML-KEM-512", "2.16.840.1.101.3.4.4.1"},
		{"ML-KEM-768", "ML-KEM-768", "2.16.840.1.101.3.4.4.2"},
		{"Kyber768", "ML-KEM-768", "2.16.840.1.101.3.4.4.2"},
		{"ML-KEM-1024", "ML-KEM-1024", "2.16.840.1.101.3.4.4.3"},
		{"Kyber1024", "ML-KEM-1024", "2.16.840.1.101.3.4.4.3"},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			a, ok := algorithm(tc.input)
			if !ok || a.Name != tc.want || a.OID.String() != tc.oid {
				t.Fatalf("algorithm(%q) = %+v, %v", tc.input, a, ok)
			}
			if a.Sign != nil && a.Sign.Name() != tc.want || a.KEM != nil && a.KEM.Name() != tc.want {
				t.Fatalf("wrong backend for %s", tc.input)
			}
		})
	}
}

func TestLegacyPublicKeyTextIsNotReinterpretedAsStandard(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.txt")
	if err := os.WriteFile(path, []byte("[ML-DSA-44]\nPublicKey=00\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := importPublic("Dilithium2", path); err == nil || !strings.Contains(err.Error(), "旧") {
		t.Fatalf("legacy key should be rejected explicitly: %v", err)
	}
}

func TestLegacyConfigNamesGenerateStandardCertificates(t *testing.T) {
	c := Config{SchemaVersion: 1, Mode: "pure-pq", OutputDir: filepath.Join(t.TempDir(), "output"), Root: NodeConfig{Name: "root", CommonName: "Root", Algorithm: "Dilithium2", ValidDays: 30}, Leaves: []NodeConfig{{Name: "user", CommonName: "User", Algorithm: "Kyber512", ValidDays: 10}}}
	if err := validateConfig(c); err != nil {
		t.Fatal(err)
	}
	report, err := generate(c)
	if err != nil {
		t.Fatal(err)
	}
	if report.Certificates[0].Algorithm != "ML-DSA-44" || report.Certificates[1].Algorithm != "ML-KEM-512" {
		t.Fatalf("report must use standard names: %+v", report.Certificates)
	}
	for _, item := range []struct{ name, oid string }{{"root", "2.16.840.1.101.3.4.3.17"}, {"user", "2.16.840.1.101.3.4.4.1"}} {
		cert, _, err := readCertificate(filepath.Join(c.OutputDir, item.name+".crt"))
		if err != nil {
			t.Fatal(err)
		}
		if got := cert.TBS.PublicKey.Algorithm.Algorithm.String(); got != item.oid {
			t.Fatalf("%s public key OID = %s", item.name, got)
		}
	}
}
func TestHybridRejectsBadPQSignatureWithValidTraditionalSignature(t *testing.T) {
	for _, mode := range []string{"rsa-hybrid", "sm2-hybrid"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			rootCfg := NodeConfig{Name: "root", CommonName: "Root", Algorithm: "Dilithium2", ValidDays: 3650}
			leafCfg := NodeConfig{Name: "user", CommonName: "User", Algorithm: "Kyber512", ValidDays: 365}
			root, err := createNode(mode, rootCfg, nil, true, 0, now)
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := createNode(mode, leafCfg, root, false, -1, now)
			if err != nil {
				t.Fatal(err)
			}
			parent, err := parseDER(root.der)
			if err != nil {
				t.Fatal(err)
			}
			cert, err := parseDER(leaf.der)
			if err != nil {
				t.Fatal(err)
			}
			cert.TBS.Raw = nil
			for i, e := range cert.TBS.Extensions {
				if e.Id.Equal(oidPQSignature) {
					var p PQExtension
					if _, err = asn1.Unmarshal(e.Value, &p); err != nil {
						t.Fatal(err)
					}
					p.Data[0] ^= 1
					cert.TBS.Extensions[i].Value, err = asDER(p)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			raw, err := asDER(cert.TBS)
			if err != nil {
				t.Fatal(err)
			}
			var sig []byte
			if mode == "rsa-hybrid" {
				h := sha256.Sum256(raw)
				sig, err = rsa.SignPKCS1v15(rand.Reader, root.rsaKey, crypto.SHA256, h[:])
			} else {
				sig, err = root.sm2Key.Sign(rand.Reader, raw, nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			cert.Signature = asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}
			der, err := asDER(*cert)
			if err != nil {
				t.Fatal(err)
			}
			cert, err = parseDER(der)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "rsa-hybrid" {
				c, err := x509.ParseCertificate(der)
				if err != nil {
					t.Fatal(err)
				}
				if err = c.CheckSignatureFrom(root.native); err != nil {
					t.Fatal("fixture RSA signature is invalid:", err)
				}
			} else {
				c, err := gx.ParseCertificate(der)
				if err != nil {
					t.Fatal(err)
				}
				if err = c.CheckSignatureFrom(root.gm); err != nil {
					t.Fatal("fixture SM2 signature is invalid:", err)
				}
			}
			err = checkCertificate(mode, leafCfg, false, -1, cert, der, parent, root.der, rootCfg, now)
			if err == nil || !strings.Contains(err.Error(), "抗量子扩展签名") {
				t.Fatalf("bad PQ signature accepted or wrong failure: %v", err)
			}
		})
	}
}
func TestRejectsCertificatesOutsideValidity(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	n := NodeConfig{Name: "root", CommonName: "Root", Algorithm: "Dilithium2", ValidDays: 30}
	g, err := createNode("pure-pq", n, nil, true, 0, now)
	if err != nil {
		t.Fatal(err)
	}
	c, err := parseDER(g.der)
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Time{now.Add(-10 * time.Minute), now.AddDate(0, 0, 31)} {
		if err = checkCertificate("pure-pq", n, true, 0, c, g.der, c, g.der, n, at); err == nil {
			t.Fatal("invalid validity accepted")
		}
	}
}
func TestConcurrentGenerationNeverOverwrites(t *testing.T) {
	c := Config{SchemaVersion: 1, Mode: "pure-pq", OutputDir: filepath.Join(t.TempDir(), "output"), Root: NodeConfig{Name: "root", CommonName: "Root", Algorithm: "Dilithium2", ValidDays: 30}, Leaves: []NodeConfig{{Name: "user", CommonName: "User", Algorithm: "Kyber512", ValidDays: 10}}}
	if err := validateConfig(c); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := generate(c); results <- err }()
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successes=%d", successes)
	}
	for _, name := range []string{"root.key", "user.key"} {
		if err := os.Remove(filepath.Join(c.OutputDir, name)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := verify(c, c.OutputDir); err != nil {
		t.Fatal("verify required private keys:", err)
	}
}

func TestSM2RejectsOutOfRangeCoordinates(t *testing.T) {
	curve := sm2.P256Sm2()
	x := new(big.Int).Add(curve.Params().Gx, curve.Params().P)
	p := filepath.Join(t.TempDir(), "public.txt")
	if err := os.WriteFile(p, []byte(fmt.Sprintf("[SM2]\nX=%x\nY=%x\n", x, curve.Params().Gy)), 0600); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("malformed public key panicked: %v", r)
		}
	}()
	if _, err := importPublic("SM2", p); err == nil {
		t.Fatal("out-of-range coordinate accepted")
	}
}
func TestSM2VerifyRejectsOtherSubjectCurve(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	r := NodeConfig{Name: "root", CommonName: "Root", Algorithm: "SM2", ValidDays: 3650}
	n := NodeConfig{Name: "user", CommonName: "User", Algorithm: "SM2", ValidDays: 365}
	root, err := createNode("sm2", r, nil, true, 0, now)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sn, err := serial()
	if err != nil {
		t.Fatal(err)
	}
	tpl := &gx.Certificate{Version: 3, SerialNumber: sn, Subject: root.gm.Subject, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(0, 0, 365), IsCA: false, BasicConstraintsValid: true, MaxPathLen: -1, KeyUsage: gx.KeyUsageDigitalSignature, SignatureAlgorithm: gx.SM2WithSM3}
	tpl.Subject.CommonName = n.CommonName
	der, err := gx.CreateCertificate(tpl, root.gm, &sm2.PublicKey{Curve: key.Curve, X: key.X, Y: key.Y}, root.sm2Key)
	if err != nil {
		t.Fatal(err)
	}
	native, err := gx.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if err = native.CheckSignatureFrom(root.gm); err != nil {
		t.Fatal("fixture SM2 signature invalid:", err)
	}
	c, err := parseDER(der)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := parseDER(root.der)
	if err != nil {
		t.Fatal(err)
	}
	if err = checkCertificate("sm2", n, false, -1, c, der, parent, root.der, r, now); err == nil {
		t.Fatal("P256 subject accepted as configured SM2")
	}
}
func TestConfigurationRejectsCaseAliases(t *testing.T) {
	text := `{"schema_version":1,"mode":"pure-pq","MODE":"rsa-hybrid","output_dir":"output","root":{"name":"root","common_name":"Root","algorithm":"Dilithium2","valid_days":3650},"leaves":[{"name":"user","common_name":"User","algorithm":"Kyber512","valid_days":365}]}`
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(p); err == nil {
		t.Fatal("case alias overrode configured mode")
	}
}

func TestExportedPrivateKeysMatchCertificates(t *testing.T) {
	for _, mode := range []string{"pure-pq", "rsa-hybrid", "sm2-hybrid", "sm2"} {
		t.Run(mode, func(t *testing.T) {
			rootAlgo, leafAlgo := "Dilithium2", "Kyber512"
			if mode == "sm2" {
				rootAlgo, leafAlgo = "SM2", "SM2"
			}
			cfg := Config{SchemaVersion: 1, Mode: mode, OutputDir: filepath.Join(t.TempDir(), "output"), Root: NodeConfig{Name: "root", CommonName: "Root", Algorithm: rootAlgo, ValidDays: 30}, Leaves: []NodeConfig{{Name: "user", CommonName: "User", Algorithm: leafAlgo, ValidDays: 10}}}
			if _, err := generate(cfg); err != nil {
				t.Fatal(err)
			}
			for _, n := range []NodeConfig{cfg.Root, cfg.Leaves[0]} {
				cert, der, err := readCertificate(filepath.Join(cfg.OutputDir, n.Name+".crt"))
				if err != nil {
					t.Fatal(err)
				}
				getPEM := func(suffix string) []byte {
					b, err := os.ReadFile(filepath.Join(cfg.OutputDir, n.Name+suffix))
					if err != nil {
						t.Fatal(err)
					}
					block, _ := pem.Decode(b)
					if block == nil {
						t.Fatal("bad key PEM")
					}
					return block.Bytes
				}
				if mode != "sm2" {
					suffix := ".key"
					want := cert.TBS.PublicKey.PublicKey.Bytes
					if mode != "pure-pq" {
						suffix = ".pq.key"
						pub, err := getPQ(cert, oidPQPublic)
						if err != nil {
							t.Fatal(err)
						}
						want = pub.Data
					}
					a, _ := algorithm(n.Algorithm)
					var got []byte
					if a.Sign != nil {
						key, err := a.Sign.UnmarshalBinaryPrivateKey(getPEM(suffix))
						if err != nil {
							t.Fatal(err)
						}
						got, err = key.Public().(interface{ MarshalBinary() ([]byte, error) }).MarshalBinary()
						if err != nil {
							t.Fatal(err)
						}
					} else {
						key, err := a.KEM.UnmarshalBinaryPrivateKey(getPEM(suffix))
						if err != nil {
							t.Fatal(err)
						}
						got, err = key.Public().MarshalBinary()
						if err != nil {
							t.Fatal(err)
						}
					}
					if !bytes.Equal(got, want) {
						t.Fatal("PQ private key does not match certificate")
					}
				}
				if mode == "rsa-hybrid" {
					key, err := x509.ParsePKCS8PrivateKey(getPEM(".key"))
					if err != nil {
						t.Fatal(err)
					}
					native, err := x509.ParseCertificate(der)
					if err != nil {
						t.Fatal(err)
					}
					if !key.(*rsa.PrivateKey).PublicKey.Equal(native.PublicKey) {
						t.Fatal("RSA key mismatch")
					}
				}
				if mode == "sm2" || mode == "sm2-hybrid" {
					key, err := gx.ParsePKCS8PrivateKey(getPEM(".key"), nil)
					if err != nil {
						t.Fatal(err)
					}
					native, err := gx.ParseCertificate(der)
					if err != nil {
						t.Fatal(err)
					}
					pub := native.PublicKey.(*ecdsa.PublicKey)
					if pub.X.Cmp(key.X) != 0 || pub.Y.Cmp(key.Y) != 0 {
						t.Fatal("SM2 key mismatch")
					}
				}
			}
		})
	}
}

func TestConfigurationRejectsUnicodeAliases(t *testing.T) {
	text := `{"schema_version":1,"schema_verſion":1,"mode":"pure-pq","output_dir":"output","root":{"name":"root","common_name":"Root","algorithm":"Dilithium2","valid_days":3650},"leaves":[{"name":"user","common_name":"User","algorithm":"Kyber512","valid_days":365}]}`
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(p); err == nil {
		t.Fatal("Unicode alias mapped to known field")
	}
}
