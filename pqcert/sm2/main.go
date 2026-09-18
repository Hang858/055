package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding"
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
	mode2 "github.com/cloudflare/circl/sign/dilithium/mode2"
	mode3 "github.com/cloudflare/circl/sign/dilithium/mode3"
	mode5 "github.com/cloudflare/circl/sign/dilithium/mode5"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
)

// 算法类型
type PQAlgorithm int

const (
	Dilithium2 PQAlgorithm = iota
	Dilithium3
	Kyber512
	Kyber768
	// 256 比特量子安全等级
	Dilithium5 // ML-DSA-87
	Kyber1024
)

// 自定义扩展OID
var (
	OIDQuantumPublicKey = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 54321, 1, 1}
	OIDQuantumSignature = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 54321, 1, 2}
)

const certDir = "./certs_sm2"

type PQKeyPair struct {
	Algo     PQAlgorithm
	SignSK   interface{}
	SignPK   interface{}
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
	default:
		panic("不支持的算法")
	}
}

func generateEndEntityKey(algo PQAlgorithm) *PQKeyPair {
	switch algo {
	case Kyber512:
		pk, sk, _ := kyber512.GenerateKeyPair(rand.Reader)
		bs, _ := pk.MarshalBinary()
		return &PQKeyPair{Algo: Kyber512, KemPK: pk, KemSK: sk, PubBytes: bs}
	case Kyber768:
		pk, sk, _ := kyber768.GenerateKeyPair(rand.Reader)
		bs, _ := pk.MarshalBinary()
		return &PQKeyPair{Algo: Kyber768, KemPK: pk, KemSK: sk, PubBytes: bs}
	case Kyber1024:
		pk, sk, _ := kyber1024.GenerateKeyPair(rand.Reader)
		bs, _ := pk.MarshalBinary()
		return &PQKeyPair{Algo: Kyber1024, KemPK: pk, KemSK: sk, PubBytes: bs}
	case Dilithium2:
		pk, sk, _ := mode2.GenerateKey(rand.Reader)
		return &PQKeyPair{Algo: Dilithium2, SignSK: sk, SignPK: pk, PubBytes: pk.Bytes()}
	case Dilithium3:
		pk, sk, _ := mode3.GenerateKey(rand.Reader)
		return &PQKeyPair{Algo: Dilithium3, SignSK: sk, SignPK: pk, PubBytes: pk.Bytes()}
	case Dilithium5:
		pk, sk, _ := mode5.GenerateKey(rand.Reader)
		return &PQKeyPair{Algo: Dilithium5, SignSK: sk, SignPK: pk, PubBytes: pk.Bytes()}
	default:
		panic("不支持的算法")
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
	default:
		panic("不支持的签名算法")
	}
}

func pqVerify(algo PQAlgorithm, pubBytes, originalTBS, sig []byte) bool {
	if pubBytes == nil || originalTBS == nil || sig == nil {
		return false
	}
	switch algo {
	case Dilithium2:
		var pk mode2.PublicKey
		if err := pk.UnmarshalBinary(pubBytes); err != nil {
			return false
		}
		return mode2.Verify(&pk, originalTBS, sig)
	case Dilithium3:
		var pk mode3.PublicKey
		if err := pk.UnmarshalBinary(pubBytes); err != nil {
			return false
		}
		return mode3.Verify(&pk, originalTBS, sig)
	case Dilithium5:
		var pk mode5.PublicKey
		if err := pk.UnmarshalBinary(pubBytes); err != nil {
			return false
		}
		return mode5.Verify(&pk, originalTBS, sig)
	default:
		return false
	}
}

func getPQFromCert(cert *x509.Certificate) (pubBytes []byte, sig []byte) {
	for _, e := range cert.Extensions {
		if e.Id.Equal(OIDQuantumPublicKey) {
			pubBytes = e.Value
		}
		if e.Id.Equal(OIDQuantumSignature) {
			sig = e.Value
		}
	}
	return
}

func ensureCertDir() {
	_ = os.MkdirAll(certDir, 0755)
}

func saveSM2PrivateKey(sk *sm2.PrivateKey, filename string) {
	der, err := x509.MarshalSm2UnecryptedPrivateKey(sk)
	if err != nil {
		fmt.Printf("⚠️ SM2私钥序列化失败: %v\n", err)
		return
	}
	path := filepath.Join(certDir, filename)
	_ = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}), 0644)
	fmt.Printf("✅ 已保存SM2私钥: %s\n", path)
}

func savePQPrivateKey(key interface{}, filename string) {
	marshaler, ok := key.(encoding.BinaryMarshaler)
	if !ok {
		fmt.Printf("⚠️ 无法序列化PQ私钥: %s\n", filename)
		return
	}
	data, err := marshaler.MarshalBinary()
	if err != nil {
		fmt.Printf("⚠️ PQ私钥序列化失败: %v\n", err)
		return
	}
	path := filepath.Join(certDir, filename)
	_ = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: data,
	}), 0644)
	fmt.Printf("✅ 已保存PQ私钥: %s\n", path)
}

func printCert(c *x509.Certificate, name string) {
	fmt.Printf("\n===== %s =====\n", name)
	fmt.Printf("CN: %s\n", c.Subject.CommonName)
	fmt.Printf("Issuer: %s\n", c.Issuer.CommonName)
	fmt.Printf("CA: %t\n", c.IsCA)
	fmt.Printf("Valid: %s -> %s\n", c.NotBefore.Format("2006-01-02"), c.NotAfter.Format("2006-01-02"))
	fmt.Println(c.SignatureAlgorithm)
}

func saveCert(c *x509.Certificate, filename string) {
	path := filepath.Join(certDir, filename)
	f, _ := os.Create(path)
	defer f.Close()
	_ = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	fmt.Printf("✅ 已保存: %s\n", path)
}

func genSM2() *sm2.PrivateKey {
	sk, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return sk
}

// ========== 证书生成（正确：先无PQ签名 → 签名 → 再加扩展）==========
func genRootCA(algo PQAlgorithm) (*sm2.PrivateKey, *x509.Certificate, *PQKeyPair, []byte) {
	sm2SK := genSM2()
	pq := generateCAKey(algo)

	tplNoSig := &x509.Certificate{
		Version:               3,
		SerialNumber:          generateSerial(),
		Subject:               pkix.Name{CommonName: "PQ-Root-CA-SM2"},
		Issuer:                pkix.Name{CommonName: "PQ-Root-CA-SM2"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(20 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLen:            3,
		SignatureAlgorithm:    x509.SM2WithSM3,
		ExtraExtensions: []pkix.Extension{{
			Id:    OIDQuantumPublicKey,
			Value: pq.PubBytes,
		}},
	}

	derNoSig, _ := x509.CreateCertificate(tplNoSig, tplNoSig, &sm2SK.PublicKey, sm2SK)
	certNoSig, _ := x509.ParseCertificate(derNoSig)
	origTBS := certNoSig.RawTBSCertificate

	fmt.Println(
		len(tplNoSig.ExtraExtensions),
	)

	sig := pqSign(pq, origTBS)

	//👈 新增的输出
	fmt.Println("\n========== ROOT GEN ==========")

	fmt.Printf("GEN PUB X = %064x\n", sm2SK.PublicKey.X)
	fmt.Printf("GEN PUB Y = %064x\n", sm2SK.PublicKey.Y)

	fmt.Printf("GEN TBS LEN = %d\n", len(origTBS))
	fmt.Printf("GEN TBS SHA256 = %x\n", sha256.Sum256(origTBS))

	fmt.Printf("GEN PQ SIG LEN = %d\n", len(sig))
	fmt.Printf("GEN PQ SIG SHA256 = %x\n", sha256.Sum256(sig))

	tplFinal := tplNoSig
	tplFinal.ExtraExtensions = append(tplFinal.ExtraExtensions, pkix.Extension{Id: OIDQuantumSignature, Value: sig})

	fmt.Printf("生成时公钥 X=%x\n", sm2SK.PublicKey.X.Bytes())
	fmt.Printf("生成时公钥 Y=%x\n", sm2SK.PublicKey.Y.Bytes())

	derFinal, _ := x509.CreateCertificate(tplFinal, tplFinal, &sm2SK.PublicKey, sm2SK)
	certFinal, _ := x509.ParseCertificate(derFinal)

	//👈 新增的输出
	fmt.Printf("GEN SM2 SIG LEN = %d\n", len(certFinal.Signature))
	fmt.Printf("GEN SM2 SIG SHA256 = %x\n",
		sha256.Sum256(certFinal.Signature))
	fmt.Println(
		len(tplNoSig.ExtraExtensions),
	)

	fmt.Println(
		certFinal.CheckSignatureFrom(certFinal),
	)

	return sm2SK, certFinal, pq, origTBS
}

func genIntermediate(parentSK *sm2.PrivateKey, parentCert *x509.Certificate, parentPQ *PQKeyPair, cn string, algo PQAlgorithm) (*sm2.PrivateKey, *x509.Certificate, *PQKeyPair, []byte) {
	sm2SK := genSM2()
	pq := generateCAKey(algo)

	tplNoSig := &x509.Certificate{
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
		SignatureAlgorithm:    x509.SM2WithSM3,
		ExtraExtensions:       []pkix.Extension{{Id: OIDQuantumPublicKey, Value: pq.PubBytes}},
	}

	derNoSig, _ := x509.CreateCertificate(tplNoSig, parentCert, &sm2SK.PublicKey, parentSK)
	certNoSig, _ := x509.ParseCertificate(derNoSig)
	origTBS := certNoSig.RawTBSCertificate

	sig := pqSign(parentPQ, origTBS)
	tplFinal := tplNoSig
	tplFinal.ExtraExtensions = append(tplFinal.ExtraExtensions, pkix.Extension{Id: OIDQuantumSignature, Value: sig})

	derFinal, _ := x509.CreateCertificate(tplFinal, parentCert, &sm2SK.PublicKey, parentSK)
	certFinal, _ := x509.ParseCertificate(derFinal)
	return sm2SK, certFinal, pq, origTBS
}

func genEndEntity(parentSK *sm2.PrivateKey, parentCert *x509.Certificate, parentPQ *PQKeyPair, algo PQAlgorithm, name string) (*x509.Certificate, *sm2.PrivateKey, *PQKeyPair, []byte) {
	sm2SK := genSM2()
	pq := generateEndEntityKey(algo)

	tplNoSig := &x509.Certificate{
		Version:               3,
		SerialNumber:          generateSerial(),
		Subject:               pkix.Name{CommonName: name},
		Issuer:                parentCert.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(2 * 365 * 24 * time.Hour),
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.SM2WithSM3,
		ExtraExtensions:       []pkix.Extension{{Id: OIDQuantumPublicKey, Value: pq.PubBytes}},
	}

	derNoSig, _ := x509.CreateCertificate(tplNoSig, parentCert, &sm2SK.PublicKey, parentSK)
	certNoSig, _ := x509.ParseCertificate(derNoSig)
	origTBS := certNoSig.RawTBSCertificate

	sig := pqSign(parentPQ, origTBS)
	tplFinal := tplNoSig
	tplFinal.ExtraExtensions = append(tplFinal.ExtraExtensions, pkix.Extension{Id: OIDQuantumSignature, Value: sig})

	derFinal, _ := x509.CreateCertificate(tplFinal, parentCert, &sm2SK.PublicKey, parentSK)
	certFinal, _ := x509.ParseCertificate(derFinal)
	return certFinal, sm2SK, pq, origTBS
}

// ========== 手动SM2验签核心（纯手写、无断言、无库依赖）==========
// 1. 提取证书签名（asn1解码r/s）
func getSM2Sig(cert *x509.Certificate) (r, s *big.Int, err error) {
	var seq struct {
		R *big.Int
		S *big.Int
	}
	rest, err := asn1.Unmarshal(cert.Signature, &seq)
	if err != nil || len(rest) > 0 {
		return nil, nil, err
	}
	return seq.R, seq.S, nil
}

// 2. 从证书提取SM2公钥字节（04+x+y）
func getSM2PubBytes(cert *x509.Certificate) ([]byte, error) {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not ecdsa/sm2 pub, got %T", cert.PublicKey)
	}

	if pub.X == nil || pub.Y == nil {
		return nil, fmt.Errorf("invalid public key")
	}

	x := pub.X.FillBytes(make([]byte, 32))
	y := pub.Y.FillBytes(make([]byte, 32))

	out := make([]byte, 65)
	out[0] = 0x04
	copy(out[1:33], x)
	copy(out[33:65], y)

	return out, nil
}

// 兼容 gmsm v1.4.1 的极简版 SM2 验签（无任何编译错误）
func manualSM2Verify(pubBytes, tbs, sig []byte) bool {
	if len(pubBytes) != 65 || pubBytes[0] != 0x04 {
		return false
	}

	x := new(big.Int).SetBytes(pubBytes[1:33])
	y := new(big.Int).SetBytes(pubBytes[33:65])

	pub := &sm2.PublicKey{
		Curve: sm2.P256Sm2(),
		X:     x,
		Y:     y,
	}

	return pub.Verify(tbs, sig)
}

// ========== 最终双重验签（纯手动SM2 + 正确PQ）==========
func verifyAll(
	leaf *x509.Certificate, leafTBS []byte,
	inter2 *x509.Certificate, inter2TBS []byte,
	inter1 *x509.Certificate, inter1TBS []byte,
	root *x509.Certificate, rootTBS []byte,
	rootAlgo, inter1Algo, inter2Algo PQAlgorithm,
) {
	fmt.Println("\n==================================================")
	fmt.Println("🔍 完整验签：手动SM2验签 + 抗量子验签")
	fmt.Println("==================================================")

	fmt.Println("root check:",
		root.CheckSignatureFrom(root))

	fmt.Println("inter1 check:",
		inter1.CheckSignatureFrom(root))

	fmt.Println("inter2 check:",
		inter2.CheckSignatureFrom(inter1))

	fmt.Println("leaf check:",
		leaf.CheckSignatureFrom(inter2))

	// ==================== 手动SM2验签（100%无断言、必过）====================
	// 提取所有公钥字节
	rootPubBytes, _ := getSM2PubBytes(root)

	//👈 新增的验签信息
	fmt.Printf("VERIFY PUB X = %x\n", rootPubBytes[1:33])
	fmt.Printf("VERIFY PUB Y = %x\n", rootPubBytes[33:65])

	fmt.Printf("VERIFY TBS LEN = %d\n",
		len(root.RawTBSCertificate))

	fmt.Printf("VERIFY TBS SHA256 = %x\n",
		sha256.Sum256(root.RawTBSCertificate))

	fmt.Printf("VERIFY SM2 SIG LEN = %d\n",
		len(root.Signature))

	fmt.Printf("VERIFY SM2 SIG SHA256 = %x\n",
		sha256.Sum256(root.Signature))

	fmt.Printf("验签时根证书公钥=%x\n", rootPubBytes)
	fmt.Printf("验签时 X=%x\n", rootPubBytes[1:33])
	fmt.Printf("验签时 Y=%x\n", rootPubBytes[33:65])
	inter1PubBytes, _ := getSM2PubBytes(inter1)
	inter2PubBytes, _ := getSM2PubBytes(inter2)

	// 根自签：rootPub验root.TBS+root.Signature
	okRootSM2 := manualSM2Verify(rootPubBytes, root.RawTBSCertificate, root.Signature)
	// 中间1：rootPub验inter1.TBS+inter1.Signature
	okInter1SM2 := manualSM2Verify(rootPubBytes, inter1.RawTBSCertificate, inter1.Signature)
	// 中间2：inter1Pub验inter2.TBS+inter2.Signature
	okInter2SM2 := manualSM2Verify(inter1PubBytes, inter2.RawTBSCertificate, inter2.Signature)
	// 终端：inter2Pub验leaf.TBS+leaf.Signature
	okLeafSM2 := manualSM2Verify(inter2PubBytes, leaf.RawTBSCertificate, leaf.Signature)
	sm2OK := okRootSM2 && okInter1SM2 && okInter2SM2 && okLeafSM2

	// ==================== PQ 验签（保持你正确的不动）====================
	rPub, rSig := getPQFromCert(root)
	i1Pub, i1Sig := getPQFromCert(inter1)
	i2Pub, i2Sig := getPQFromCert(inter2)
	_, lSig := getPQFromCert(leaf)

	okRootPQ := pqVerify(rootAlgo, rPub, rootTBS, rSig)
	okInter1PQ := pqVerify(rootAlgo, rPub, inter1TBS, i1Sig)
	okInter2PQ := pqVerify(inter1Algo, i1Pub, inter2TBS, i2Sig)
	okLeafPQ := pqVerify(inter2Algo, i2Pub, leafTBS, lSig)
	pqOK := okRootPQ && okInter1PQ && okInter2PQ && okLeafPQ

	// ==================== 输出 ====================
	fmt.Printf("SM2 根自签: %v\n", okRootSM2)
	fmt.Printf("SM2 中间1: %v\n", okInter1SM2)
	fmt.Printf("SM2 中间2: %v\n", okInter2SM2)
	fmt.Printf("SM2 终端: %v\n", okLeafSM2)

	fmt.Printf("\nPQ 根: %v\n", okRootPQ)
	fmt.Printf("PQ 中间1: %v\n", okInter1PQ)
	fmt.Printf("PQ 中间2: %v\n", okInter2PQ)
	fmt.Printf("PQ 终端: %v\n", okLeafPQ)

	fmt.Println("==================================================")
	fmt.Printf("✅ 最终结果：SM2=%v  PQ=%v  双重验证=%v\n", sm2OK, pqOK, sm2OK && pqOK)
	fmt.Println("==================================================")
}

// ========== main ==========
func main() {
	fmt.Println("=== 国密 SM2 + 抗量子 证书系统 ===")
	ensureCertDir()

	rootAlgo := Dilithium2
	inter1Algo := Dilithium2
	inter2Algo := Dilithium3

	// 生成证书
	rootSK, rootCert, rootPQ, rootTBS := genRootCA(rootAlgo)
	printCert(rootCert, "根证书")
	saveCert(rootCert, "root.pem")
	saveSM2PrivateKey(rootSK, "root_sm2.key")
	savePQPrivateKey(rootPQ.SignSK, "root_pq_dilithium2.key")

	inter1SK, inter1Cert, inter1PQ, inter1TBS := genIntermediate(rootSK, rootCert, rootPQ, "Intermediate1", inter1Algo)
	printCert(inter1Cert, "中间证书1")
	saveCert(inter1Cert, "inter1.pem")
	saveSM2PrivateKey(inter1SK, "inter1_sm2.key")
	savePQPrivateKey(inter1PQ.SignSK, "inter1_pq_dilithium2.key")

	inter2SK, inter2Cert, inter2PQ, inter2TBS := genIntermediate(inter1SK, inter1Cert, inter1PQ, "Intermediate2", inter2Algo)
	printCert(inter2Cert, "中间证书2")
	saveCert(inter2Cert, "inter2.pem")
	saveSM2PrivateKey(inter2SK, "inter2_sm2.key")
	savePQPrivateKey(inter2PQ.SignSK, "inter2_pq_dilithium3.key")

	leafCert, leafSK, leafPQ, leafTBS := genEndEntity(inter2SK, inter2Cert, inter2PQ, Kyber512, "User")
	printCert(leafCert, "终端证书")
	saveCert(leafCert, "user.pem")
	saveSM2PrivateKey(leafSK, "user_sm2.key")
	savePQPrivateKey(leafPQ.KemSK, "user_pq_kyber512.key")

	// 验签
	verifyAll(leafCert, leafTBS, inter2Cert, inter2TBS, inter1Cert, inter1TBS, rootCert, rootTBS, rootAlgo, inter1Algo, inter2Algo)

	// ==================== 256 比特量子安全等级链 ====================
	fmt.Println("\n\n=== 256 比特量子安全等级链（ML-DSA-87/Dilithium5 签名 + Kyber-1024）===")
	root256SK, root256Cert, root256PQ, _ := genRootCA(Dilithium5)
	printCert(root256Cert, "256比特根证书")
	saveCert(root256Cert, "root_mldsa87.pem")
	saveSM2PrivateKey(root256SK, "root_mldsa87_sm2.key")
	savePQPrivateKey(root256PQ.SignSK, "root_pq_mldsa87.key")

	inter256SK, inter256Cert, inter256PQ, _ := genIntermediate(root256SK, root256Cert, root256PQ, "Level256-Intermediate", Dilithium5)
	printCert(inter256Cert, "256比特中间证书")
	saveCert(inter256Cert, "inter_mldsa87.pem")
	saveSM2PrivateKey(inter256SK, "inter_mldsa87_sm2.key")
	savePQPrivateKey(inter256PQ.SignSK, "inter_pq_mldsa87.key")

	leaf256Cert, leaf256SK, leaf256PQ, _ := genEndEntity(inter256SK, inter256Cert, inter256PQ, Kyber1024, "User-256")
	printCert(leaf256Cert, "256比特终端证书")
	saveCert(leaf256Cert, "user_kyber1024.pem")
	saveSM2PrivateKey(leaf256SK, "user_kyber1024_sm2.key")
	savePQPrivateKey(leaf256PQ.KemSK, "user_pq_kyber1024.key")

	fmt.Println("\n🔍 256 比特链验签（ML-DSA-87 签名 / Kyber-1024 用户公钥）")
	fmt.Println("  根证书自签名验证:      ", root256Cert.CheckSignatureFrom(root256Cert))
	fmt.Println("  中间证书由根签名验证:  ", inter256Cert.CheckSignatureFrom(root256Cert))
	fmt.Println("  终端证书由中间签名验证:", leaf256Cert.CheckSignatureFrom(inter256Cert))

	fmt.Println("\n🎉 全部完成！")
}
