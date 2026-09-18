package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/sign"
	mode2 "github.com/cloudflare/circl/sign/dilithium/mode2"
	mode3 "github.com/cloudflare/circl/sign/dilithium/mode3"
	mode5 "github.com/cloudflare/circl/sign/dilithium/mode5"
	"github.com/cloudflare/circl/sign/schemes"
)

type PQAlgorithm int

const (
	Dilithium2 PQAlgorithm = iota
	Dilithium3
	SPHINCS128s
	SPHINCS128f
	Kyber512
	Kyber768
	// 256 比特量子安全等级
	Dilithium5 // ML-DSA-87
	Kyber1024
	// 192 / 256 比特哈希签名（SLH-DSA）
	SPHINCS192s
	SPHINCS192f
	SPHINCS256s
	SPHINCS256f
)

var (
	OIDQuantumPublicKey = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 54321, 1, 1}
	OIDQuantumSignature = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 54321, 1, 2}
)

const certDir = "./certs"

type PQKeyPair struct {
	Algo     PQAlgorithm
	SignSK   interface{}
	SignPK   interface{}
	Scheme   sign.Scheme
	KemSK    interface{}
	KemPK    interface{}
	PubBytes []byte
}

func generateSerial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}
	return n
}

func getSPHINCSScheme(algo PQAlgorithm) sign.Scheme {
	var name string

	switch algo {
	case SPHINCS128s:
		name = "SLH-DSA-SHA2-128s"
	case SPHINCS128f:
		name = "SLH-DSA-SHA2-128f"
	case SPHINCS192s:
		name = "SLH-DSA-SHA2-192s"
	case SPHINCS192f:
		name = "SLH-DSA-SHA2-192f"
	case SPHINCS256s:
		name = "SLH-DSA-SHA2-256s"
	case SPHINCS256f:
		name = "SLH-DSA-SHA2-256f"
	default:
		panic("不支持的 SPHINCS 算法")
	}

	scheme := schemes.ByName(name)
	if scheme == nil {
		panic("当前 CIRCL 版本不支持: " + name)
	}
	return scheme
}

func generateCAKey(algo PQAlgorithm) *PQKeyPair {
	switch algo {
	case Dilithium2:
		pk, sk, _ := mode2.GenerateKey(rand.Reader)
		return &PQKeyPair{Algo: Dilithium2, SignSK: sk, SignPK: pk, PubBytes: pk.Bytes()}

	case Dilithium3:
		pk, sk, _ := mode3.GenerateKey(rand.Reader)
		return &PQKeyPair{Algo: Dilithium3, SignSK: sk, SignPK: pk, PubBytes: pk.Bytes()}

	case Dilithium5:
		pk, sk, _ := mode5.GenerateKey(rand.Reader)
		return &PQKeyPair{Algo: Dilithium5, SignSK: sk, SignPK: pk, PubBytes: pk.Bytes()}

	case SPHINCS128s, SPHINCS128f, SPHINCS192s, SPHINCS192f, SPHINCS256s, SPHINCS256f:
		scheme := getSPHINCSScheme(algo)
		pk, sk, err := scheme.GenerateKey()
		if err != nil {
			panic(err)
		}
		pubBytes, err := pk.MarshalBinary()
		if err != nil {
			panic(err)
		}
		return &PQKeyPair{
			Algo:     algo,
			Scheme:   scheme,
			SignPK:   pk,
			SignSK:   sk,
			PubBytes: pubBytes,
		}

	default:
		panic("不支持的 CA 算法")
	}
}

func generateEndEntityKey(algo PQAlgorithm) *PQKeyPair {
	switch algo {
	case Kyber512:
		pk, sk, _ := kyber512.GenerateKeyPair(rand.Reader)
		pubBytes, _ := pk.MarshalBinary()
		return &PQKeyPair{Algo: Kyber512, KemPK: pk, KemSK: sk, PubBytes: pubBytes}

	case Kyber768:
		pk, sk, _ := kyber768.GenerateKeyPair(rand.Reader)
		pubBytes, _ := pk.MarshalBinary()
		return &PQKeyPair{Algo: Kyber768, KemPK: pk, KemSK: sk, PubBytes: pubBytes}

	case Kyber1024:
		pk, sk, _ := kyber1024.GenerateKeyPair(rand.Reader)
		pubBytes, _ := pk.MarshalBinary()
		return &PQKeyPair{Algo: Kyber1024, KemPK: pk, KemSK: sk, PubBytes: pubBytes}

	case Dilithium2:
		pk, sk, _ := mode2.GenerateKey(rand.Reader)
		return &PQKeyPair{Algo: Dilithium2, SignPK: pk, SignSK: sk, PubBytes: pk.Bytes()}

	case Dilithium3:
		pk, sk, _ := mode3.GenerateKey(rand.Reader)
		return &PQKeyPair{Algo: Dilithium3, SignPK: pk, SignSK: sk, PubBytes: pk.Bytes()}

	case Dilithium5:
		pk, sk, _ := mode5.GenerateKey(rand.Reader)
		return &PQKeyPair{Algo: Dilithium5, SignPK: pk, SignSK: sk, PubBytes: pk.Bytes()}

	case SPHINCS128s, SPHINCS128f, SPHINCS192s, SPHINCS192f, SPHINCS256s, SPHINCS256f:
		scheme := getSPHINCSScheme(algo)
		pk, sk, err := scheme.GenerateKey()
		if err != nil {
			panic(err)
		}
		pubBytes, err := pk.MarshalBinary()
		if err != nil {
			panic(err)
		}
		return &PQKeyPair{
			Algo:     algo,
			Scheme:   scheme,
			SignPK:   pk,
			SignSK:   sk,
			PubBytes: pubBytes,
		}

	default:
		panic("不支持的终端算法")
	}
}

func pqSign(parentKey *PQKeyPair, tbs []byte) []byte {
	switch parentKey.Algo {
	case Dilithium2:
		sig := make([]byte, mode2.SignatureSize)
		mode2.SignTo(parentKey.SignSK.(*mode2.PrivateKey), tbs, sig)
		return sig

	case Dilithium3:
		sig := make([]byte, mode3.SignatureSize)
		mode3.SignTo(parentKey.SignSK.(*mode3.PrivateKey), tbs, sig)
		return sig

	case Dilithium5:
		sig := make([]byte, mode5.SignatureSize)
		mode5.SignTo(parentKey.SignSK.(*mode5.PrivateKey), tbs, sig)
		return sig

	case SPHINCS128s, SPHINCS128f, SPHINCS192s, SPHINCS192f, SPHINCS256s, SPHINCS256f:
		sk, ok := parentKey.SignSK.(sign.PrivateKey)
		if !ok {
			panic("invalid SPHINCS private key type")
		}
		return parentKey.Scheme.Sign(sk, tbs, nil)

	default:
		panic("不支持的签名算法")
	}
}

func ensureCertDir() {
	_ = os.MkdirAll(certDir, 0755)
}

func printCert(c *x509.Certificate, name string) {
	fmt.Printf("\n===== %s =====\n", name)
	fmt.Printf("CN: %s\n", c.Subject.CommonName)
	fmt.Printf("Issuer: %s\n", c.Issuer.CommonName)
	fmt.Printf("CA: %t\n", c.IsCA)
	fmt.Printf("Valid: %s -> %s\n", c.NotBefore.Format("2006-01-02"), c.NotAfter.Format("2006-01-02"))
}

func saveCert(c *x509.Certificate, filename string) {
	path := filepath.Join(certDir, filename)
	f, _ := os.Create(path)
	defer f.Close()
	_ = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	fmt.Printf("✅ 已保存: %s\n", path)
}

func genRSA() *rsa.PrivateKey {
	sk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return sk
}

func genRootCA(algo PQAlgorithm) (*rsa.PrivateKey, *x509.Certificate, *PQKeyPair) {
	rsaSK := genRSA()
	pq := generateCAKey(algo)

	tpl := &x509.Certificate{
		Version:               3,
		SerialNumber:          generateSerial(),
		Subject:               pkix.Name{CommonName: "PQ-Root-CA"},
		Issuer:                pkix.Name{CommonName: "PQ-Root-CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(20 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLen:            3,
		ExtraExtensions: []pkix.Extension{{
			Id:    OIDQuantumPublicKey,
			Value: pq.PubBytes,
		}},
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &rsaSK.PublicKey, rsaSK)
	if err != nil {
		panic(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}

	sig := pqSign(pq, c.RawTBSCertificate)
	tpl.ExtraExtensions = append(tpl.ExtraExtensions, pkix.Extension{
		Id:    OIDQuantumSignature,
		Value: sig,
	})

	der, err = x509.CreateCertificate(rand.Reader, tpl, tpl, &rsaSK.PublicKey, rsaSK)
	if err != nil {
		panic(err)
	}
	c, err = x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}

	return rsaSK, c, pq
}

func genIntermediate(
	parentRsa *rsa.PrivateKey,
	parentCert *x509.Certificate,
	parentPQ *PQKeyPair,
	cn string,
	algo PQAlgorithm,
) (*rsa.PrivateKey, *x509.Certificate, *PQKeyPair) {
	rsaSK := genRSA()
	pq := generateCAKey(algo)

	tpl := &x509.Certificate{
		Version:               3,
		SerialNumber:          generateSerial(),
		Subject:               pkix.Name{CommonName: cn},
		Issuer:                parentCert.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
		ExtraExtensions: []pkix.Extension{{
			Id:    OIDQuantumPublicKey,
			Value: pq.PubBytes,
		}},
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, parentCert, &rsaSK.PublicKey, parentRsa)
	if err != nil {
		panic(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}

	sig := pqSign(parentPQ, c.RawTBSCertificate)
	tpl.ExtraExtensions = append(tpl.ExtraExtensions, pkix.Extension{
		Id:    OIDQuantumSignature,
		Value: sig,
	})

	der, err = x509.CreateCertificate(rand.Reader, tpl, parentCert, &rsaSK.PublicKey, parentRsa)
	if err != nil {
		panic(err)
	}
	c, err = x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}

	return rsaSK, c, pq
}

func genEndEntity(
	parentRsa *rsa.PrivateKey,
	parentCert *x509.Certificate,
	parentPQ *PQKeyPair,
	algo PQAlgorithm,
	name string,
) *x509.Certificate {
	rsaSK := genRSA()
	pq := generateEndEntityKey(algo)

	tpl := &x509.Certificate{
		Version:               3,
		SerialNumber:          generateSerial(),
		Subject:               pkix.Name{CommonName: name},
		Issuer:                parentCert.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(2 * 365 * 24 * time.Hour),
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		ExtraExtensions: []pkix.Extension{{
			Id:    OIDQuantumPublicKey,
			Value: pq.PubBytes,
		}},
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, parentCert, &rsaSK.PublicKey, parentRsa)
	if err != nil {
		panic(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}

	sig := pqSign(parentPQ, c.RawTBSCertificate)
	tpl.ExtraExtensions = append(tpl.ExtraExtensions, pkix.Extension{
		Id:    OIDQuantumSignature,
		Value: sig,
	})

	der, err = x509.CreateCertificate(rand.Reader, tpl, parentCert, &rsaSK.PublicKey, parentRsa)
	if err != nil {
		panic(err)
	}
	c, err = x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}

	return c
}

func main() {
	fmt.Println("=== Dilithium + SPHINCS + Kyber 抗量子证书链生成器 ===")
	ensureCertDir()

	rootAlgo := Dilithium2
	inter1Algo := SPHINCS128s
	inter2Algo := Dilithium3

	rootRSA, rootCert, rootPQ := genRootCA(rootAlgo)
	printCert(rootCert, "根证书")
	saveCert(rootCert, "root_ca.pem")

	i1RSA, i1Cert, i1PQ := genIntermediate(rootRSA, rootCert, rootPQ, "PQ-Intermediate-1-SPHINCS", inter1Algo)
	printCert(i1Cert, "中间证书1")
	saveCert(i1Cert, "intermediate1.pem")

	i2RSA, i2Cert, i2PQ := genIntermediate(i1RSA, i1Cert, i1PQ, "PQ-Intermediate-2-Dilithium", inter2Algo)
	printCert(i2Cert, "中间证书2")
	saveCert(i2Cert, "intermediate2.pem")

	fmt.Println("\n=== 生成终端用户证书 ===")

	user1 := genEndEntity(i2RSA, i2Cert, i2PQ, Kyber512, "user-kyber512")
	printCert(user1, "用户证书 kyber512")
	saveCert(user1, "user_kyber512.pem")

	user2 := genEndEntity(i2RSA, i2Cert, i2PQ, Kyber768, "user-kyber768")
	printCert(user2, "用户证书 kyber768")
	saveCert(user2, "user_kyber768.pem")

	user3 := genEndEntity(i2RSA, i2Cert, i2PQ, Dilithium2, "user-dilithium2")
	printCert(user3, "用户证书 dilithium2")
	saveCert(user3, "user_dilithium2.pem")

	user4 := genEndEntity(i2RSA, i2Cert, i2PQ, Dilithium3, "user-dilithium3")
	printCert(user4, "用户证书 dilithium3")
	saveCert(user4, "user_dilithium3.pem")

	user5 := genEndEntity(i2RSA, i2Cert, i2PQ, SPHINCS128s, "user-sphincs128s")
	printCert(user5, "用户证书 sphincs128s")
	saveCert(user5, "user_sphincs128s.pem")

	user6 := genEndEntity(i2RSA, i2Cert, i2PQ, SPHINCS128f, "user-sphincs128f")
	printCert(user6, "用户证书 sphincs128f")
	saveCert(user6, "user_sphincs128f.pem")

	// 256 比特量子安全等级：ML-DSA-87/Dilithium5 签名 + Kyber-1024 KEM
	fmt.Println("\n=== 256 比特量子安全等级用户证书 ===")

	user7 := genEndEntity(i2RSA, i2Cert, i2PQ, Dilithium5, "user-mldsa87")
	printCert(user7, "用户证书 ML-DSA-87/Dilithium5 (256 比特签名)")
	saveCert(user7, "user_mldsa87.pem")

	user8 := genEndEntity(i2RSA, i2Cert, i2PQ, Kyber1024, "user-kyber1024")
	printCert(user8, "用户证书 Kyber-1024 (256 比特 KEM)")
	saveCert(user8, "user_kyber1024.pem")

	// 192 / 256 比特哈希签名（SLH-DSA）
	fmt.Println("\n=== 192 / 256 比特哈希签名用户证书 ===")

	user9 := genEndEntity(i2RSA, i2Cert, i2PQ, SPHINCS192f, "user-slhdsa192f")
	printCert(user9, "用户证书 SLH-DSA-SHA2-192f (192 比特签名)")
	saveCert(user9, "user_slhdsa192f.pem")

	user10 := genEndEntity(i2RSA, i2Cert, i2PQ, SPHINCS256f, "user-slhdsa256f")
	printCert(user10, "用户证书 SLH-DSA-SHA2-256f (256 比特签名)")
	saveCert(user10, "user_slhdsa256f.pem")

	fmt.Println("\n===== 标准 RSA 证书链验签 =====")
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	inter := x509.NewCertPool()
	inter.AddCert(i1Cert)
	inter.AddCert(i2Cert)

	_, err := user1.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
	})
	if err != nil {
		fmt.Println("验签失败:", err)
	} else {
		fmt.Println("✅ 标准 X509 证书链验证成功")
	}

	fmt.Println("\n🎉 全部完成！")
}
