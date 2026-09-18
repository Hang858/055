package main

import (
	"crypto/rand"
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
	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/dilithium/mode2"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/cloudflare/circl/sign/dilithium/mode5"
	"github.com/cloudflare/circl/sign/schemes"
)

type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type SubjectPublicKeyInfo struct {
	Algorithm AlgorithmIdentifier
	PublicKey asn1.BitString
}

type Validity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

type TBSCertificate struct {
	Version              int `asn1:"optional,explicit,tag:0"`
	SerialNumber         *big.Int
	Signature            AlgorithmIdentifier
	Issuer               asn1.RawValue
	Validity             Validity
	Subject              asn1.RawValue
	SubjectPublicKeyInfo SubjectPublicKeyInfo
	Extensions           []Extension `asn1:"optional,explicit,tag:3"`
}

type Extension struct {
	Id       asn1.ObjectIdentifier
	Critical bool `asn1:"optional"`
	Value    []byte
}

type Certificate struct {
	TBSCertificate     TBSCertificate
	SignatureAlgorithm AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type BasicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

var (
	oidMLDSA44  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 11}
	oidMLDSA65  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 12}
	oidKyber512 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 40801, 5, 1, 1}
	oidKyber768 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 40801, 5, 1, 2}

	// 256 比特量子安全等级（与 ML-DSA-44/Kyber-512 的 128 比特等级配对）
	oidMLDSA87   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 13}
	oidKyber1024 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 40801, 5, 1, 3}

	// 实验用 SPHINCS / SLH-DSA OID
	oidSLHDSA128s = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 54321, 10, 1}
	oidSLHDSA128f = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 54321, 10, 2}

	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidCommonName       = asn1.ObjectIdentifier{2, 5, 4, 3}
)

const certDir = "./pq_x509_certs"

type PQKeyPair struct {
	AlgoOID  asn1.ObjectIdentifier
	SignSK   interface{}
	SignPK   interface{}
	KemSK    interface{}
	Scheme   sign.Scheme
	PubBytes []byte
}

func generateSerial() *big.Int {
	serialMax := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialMax)
	if err != nil {
		panic(err)
	}
	return serial
}

func newName(cn string) asn1.RawValue {
	rdn := []struct {
		ID    asn1.ObjectIdentifier
		Value string
	}{
		{oidCommonName, cn},
	}
	der, _ := asn1.Marshal(rdn)
	return asn1.RawValue{FullBytes: der}
}

func createExtension(oid asn1.ObjectIdentifier, critical bool, value any) Extension {
	der, err := asn1.Marshal(value)
	if err != nil {
		panic(err)
	}
	return Extension{Id: oid, Critical: critical, Value: der}
}

func isSLHDSA(algoOID asn1.ObjectIdentifier) bool {
	return algoOID.Equal(oidSLHDSA128s) || algoOID.Equal(oidSLHDSA128f)
}

func getSLHDSAScheme(algoOID asn1.ObjectIdentifier) sign.Scheme {
	var name string

	switch {
	case algoOID.Equal(oidSLHDSA128s):
		name = "SLH-DSA-SHA2-128s"
	case algoOID.Equal(oidSLHDSA128f):
		name = "SLH-DSA-SHA2-128f"
	default:
		panic("unsupported SPHINCS / SLH-DSA algorithm")
	}

	scheme := schemes.ByName(name)
	if scheme == nil {
		panic("当前 CIRCL 版本不支持: " + name)
	}
	return scheme
}

func generateSignKey(algoOID asn1.ObjectIdentifier) *PQKeyPair {
	switch {
	case algoOID.Equal(oidMLDSA44):
		pk, sk, _ := mode2.GenerateKey(rand.Reader)
		return &PQKeyPair{
			AlgoOID:  algoOID,
			SignSK:   sk,
			SignPK:   pk,
			PubBytes: pk.Bytes(),
		}

	case algoOID.Equal(oidMLDSA65):
		pk, sk, _ := mode3.GenerateKey(rand.Reader)
		return &PQKeyPair{
			AlgoOID:  algoOID,
			SignSK:   sk,
			SignPK:   pk,
			PubBytes: pk.Bytes(),
		}

	// 256 比特量子安全等级签名
	case algoOID.Equal(oidMLDSA87):
		pk, sk, _ := mode5.GenerateKey(rand.Reader)
		return &PQKeyPair{
			AlgoOID:  algoOID,
			SignSK:   sk,
			SignPK:   pk,
			PubBytes: pk.Bytes(),
		}

	case isSLHDSA(algoOID):
		scheme := getSLHDSAScheme(algoOID)
		pk, sk, err := scheme.GenerateKey()
		if err != nil {
			panic(err)
		}
		pubBytes, err := pk.MarshalBinary()
		if err != nil {
			panic(err)
		}
		return &PQKeyPair{
			AlgoOID:  algoOID,
			SignSK:   sk,
			SignPK:   pk,
			Scheme:   scheme,
			PubBytes: pubBytes,
		}

	default:
		panic("unsupported signature algorithm")
	}
}

func generateEndKey(algoOID asn1.ObjectIdentifier) *PQKeyPair {
	switch {
	case algoOID.Equal(oidKyber512):
		pk, sk, _ := kyber512.GenerateKeyPair(rand.Reader)
		buf, _ := pk.MarshalBinary()
		return &PQKeyPair{AlgoOID: algoOID, KemSK: sk, PubBytes: buf}

	case algoOID.Equal(oidKyber768):
		pk, sk, _ := kyber768.GenerateKeyPair(rand.Reader)
		buf, _ := pk.MarshalBinary()
		return &PQKeyPair{AlgoOID: algoOID, KemSK: sk, PubBytes: buf}

	// 256 比特量子安全等级 KEM
	case algoOID.Equal(oidKyber1024):
		pk, sk, _ := kyber1024.GenerateKeyPair(rand.Reader)
		buf, _ := pk.MarshalBinary()
		return &PQKeyPair{AlgoOID: algoOID, KemSK: sk, PubBytes: buf}

	case algoOID.Equal(oidMLDSA44), algoOID.Equal(oidMLDSA65), algoOID.Equal(oidMLDSA87), isSLHDSA(algoOID):
		return generateSignKey(algoOID)

	default:
		panic("unsupported end entity algorithm")
	}
}

func pqSign(sk interface{}, algoOID asn1.ObjectIdentifier, data []byte) []byte {
	switch {
	case algoOID.Equal(oidMLDSA44):
		sig := make([]byte, mode2.SignatureSize)
		mode2.SignTo(sk.(*mode2.PrivateKey), data, sig)
		return sig

	case algoOID.Equal(oidMLDSA65):
		sig := make([]byte, mode3.SignatureSize)
		mode3.SignTo(sk.(*mode3.PrivateKey), data, sig)
		return sig

	case algoOID.Equal(oidMLDSA87):
		sig := make([]byte, mode5.SignatureSize)
		mode5.SignTo(sk.(*mode5.PrivateKey), data, sig)
		return sig

	case isSLHDSA(algoOID):
		scheme := getSLHDSAScheme(algoOID)
		return scheme.Sign(sk.(sign.PrivateKey), data, nil)

	default:
		panic("only signature algorithms can sign")
	}
}

func pqVerify(pk interface{}, algoOID asn1.ObjectIdentifier, data, sig []byte) bool {
	switch {
	case algoOID.Equal(oidMLDSA44):
		return mode2.Verify(pk.(*mode2.PublicKey), data, sig)

	case algoOID.Equal(oidMLDSA65):
		return mode3.Verify(pk.(*mode3.PublicKey), data, sig)

	case algoOID.Equal(oidMLDSA87):
		return mode5.Verify(pk.(*mode5.PublicKey), data, sig)

	case isSLHDSA(algoOID):
		scheme := getSLHDSAScheme(algoOID)
		return scheme.Verify(pk.(sign.PublicKey), data, sig, nil)

	default:
		return false
	}
}

func generateCertificate(
	subjectCN, issuerCN string,
	validDays int,
	isCA bool,
	maxPathLen int,
	subjectKey *PQKeyPair,
	signerKey *PQKeyPair,
) []byte {
	subject := newName(subjectCN)
	issuer := newName(issuerCN)

	spki := SubjectPublicKeyInfo{
		Algorithm: AlgorithmIdentifier{Algorithm: subjectKey.AlgoOID},
		PublicKey: asn1.BitString{
			Bytes:     subjectKey.PubBytes,
			BitLength: len(subjectKey.PubBytes) * 8,
		},
	}

	var exts []Extension
	exts = append(exts, createExtension(oidBasicConstraints, true, BasicConstraints{
		IsCA:       isCA,
		MaxPathLen: maxPathLen,
	}))

	var ku asn1.BitString
	if isCA {
		ku = asn1.BitString{Bytes: []byte{0x06}, BitLength: 7}
	} else {
		ku = asn1.BitString{Bytes: []byte{0x80}, BitLength: 7}
	}
	exts = append(exts, createExtension(oidKeyUsage, true, ku))

	tbs := TBSCertificate{
		Version:              2,
		SerialNumber:         generateSerial(),
		Signature:            AlgorithmIdentifier{Algorithm: signerKey.AlgoOID},
		Issuer:               issuer,
		Validity:             Validity{NotBefore: time.Now(), NotAfter: time.Now().AddDate(0, 0, validDays)},
		Subject:              subject,
		SubjectPublicKeyInfo: spki,
		Extensions:           exts,
	}

	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		panic(err)
	}

	sig := pqSign(signerKey.SignSK, signerKey.AlgoOID, tbsDER)

	cert := Certificate{
		TBSCertificate:     tbs,
		SignatureAlgorithm: AlgorithmIdentifier{Algorithm: signerKey.AlgoOID},
		SignatureValue: asn1.BitString{
			Bytes:     sig,
			BitLength: len(sig) * 8,
		},
	}

	der, err := asn1.Marshal(cert)
	if err != nil {
		panic(err)
	}
	return der
}

func ParseCertificate(der []byte) (*Certificate, error) {
	var cert Certificate
	_, err := asn1.Unmarshal(der, &cert)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func oidToName(oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal(oidMLDSA44):
		return "ML-DSA-44 / Dilithium2"
	case oid.Equal(oidMLDSA65):
		return "ML-DSA-65 / Dilithium3"
	case oid.Equal(oidMLDSA87):
		return "ML-DSA-87 / Dilithium5（256 比特量子安全等级）"
	case oid.Equal(oidSLHDSA128s):
		return "SLH-DSA-SHA2-128s / SPHINCS+"
	case oid.Equal(oidSLHDSA128f):
		return "SLH-DSA-SHA2-128f / SPHINCS+"
	case oid.Equal(oidKyber512):
		return "Kyber-512"
	case oid.Equal(oidKyber768):
		return "Kyber-768"
	case oid.Equal(oidKyber1024):
		return "Kyber-1024（256 比特量子安全等级）"
	default:
		return oid.String()
	}
}

func extractCN(der []byte) string {
	var rdnSequence []struct {
		Type  asn1.ObjectIdentifier
		Value interface{}
	}

	_, err := asn1.Unmarshal(der, &rdnSequence)
	if err != nil {
		return "(解析失败)"
	}

	for _, rdn := range rdnSequence {
		if rdn.Type.Equal(oidCommonName) {
			if str, ok := rdn.Value.(string); ok {
				return str
			}
		}
	}
	return "(未知)"
}

func PrintCertInfo(cert *Certificate, name string) {
	fmt.Printf("\n==================================================\n")
	fmt.Printf("📄 证书解析: %s\n", name)
	fmt.Printf("==================================================\n")
	fmt.Printf("版本: X.509 v3\n")
	fmt.Printf("序列号: %X\n", cert.TBSCertificate.SerialNumber)
	fmt.Printf("签名算法: %s\n", oidToName(cert.SignatureAlgorithm.Algorithm))
	fmt.Printf("颁发者: CN=%s\n", extractCN(cert.TBSCertificate.Issuer.FullBytes))
	fmt.Printf("主题: CN=%s\n", extractCN(cert.TBSCertificate.Subject.FullBytes))
	fmt.Printf("有效期从: %s\n", cert.TBSCertificate.Validity.NotBefore.Format(time.DateTime))
	fmt.Printf("有效期至: %s\n", cert.TBSCertificate.Validity.NotAfter.Format(time.DateTime))
	fmt.Printf("公钥算法: %s\n", oidToName(cert.TBSCertificate.SubjectPublicKeyInfo.Algorithm.Algorithm))
	fmt.Printf("公钥长度: %d 字节\n", len(cert.TBSCertificate.SubjectPublicKeyInfo.PublicKey.Bytes))
	fmt.Printf("签名长度: %d 字节\n", len(cert.SignatureValue.Bytes))
}

func VerifyCertSignature(certDER []byte, issuerPub interface{}, issuerOID asn1.ObjectIdentifier) bool {
	cert, err := ParseCertificate(certDER)
	if err != nil {
		return false
	}

	tbsDER, err := asn1.Marshal(cert.TBSCertificate)
	if err != nil {
		return false
	}

	sig := cert.SignatureValue.Bytes
	return pqVerify(issuerPub, issuerOID, tbsDER, sig)
}

func VerifyCertificateChain(
	chainName string,
	leafDER, interDER, rootDER []byte,
	interPub interface{},
	interOID asn1.ObjectIdentifier,
	rootPub interface{},
	rootOID asn1.ObjectIdentifier,
) bool {
	rootOK := VerifyCertSignature(rootDER, rootPub, rootOID)
	interOK := VerifyCertSignature(interDER, rootPub, rootOID)
	leafOK := VerifyCertSignature(leafDER, interPub, interOID)

	fmt.Printf("\n==================================================\n")
	fmt.Printf("🔍 %s 证书链验签结果\n", chainName)
	fmt.Printf("==================================================\n")
	fmt.Printf("根证书自签名验证: %v\n", rootOK)
	fmt.Printf("中间证书由根签名验证: %v\n", interOK)
	fmt.Printf("终端证书由中间签名验证: %v\n", leafOK)

	return rootOK && interOK && leafOK
}

func ensureDir() {
	_ = os.MkdirAll(certDir, 0755)
}

func SavePEM(der []byte, name string) {
	path := filepath.Join(certDir, name)
	_ = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}), 0644)
	fmt.Printf("✅ 已保存: %s\n", path)
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

func savePrivateKeyFromPair(pair *PQKeyPair, filename string) {
	if pair.SignSK != nil {
		savePQPrivateKey(pair.SignSK, filename)
	} else if pair.KemSK != nil {
		savePQPrivateKey(pair.KemSK, filename)
	}
}

func buildChain(
	chainName string,
	rootCN string,
	interCN string,
	leafCN string,
	rootAlgo asn1.ObjectIdentifier,
	interAlgo asn1.ObjectIdentifier,
	leafAlgo asn1.ObjectIdentifier,
	rootFile string,
	interFile string,
	leafFile string,
) bool {
	fmt.Printf("\n\n==================== %s ====================\n", chainName)

	rootKey := generateSignKey(rootAlgo)
	interKey := generateSignKey(interAlgo)
	leafKey := generateEndKey(leafAlgo)

	rootDER := generateCertificate(rootCN, rootCN, 3650, true, 3, rootKey, rootKey)
	interDER := generateCertificate(interCN, rootCN, 1825, true, 1, interKey, rootKey)
	leafDER := generateCertificate(leafCN, interCN, 365, false, -1, leafKey, interKey)

	SavePEM(rootDER, rootFile)
	SavePEM(interDER, interFile)
	SavePEM(leafDER, leafFile)

	// 导出私钥
	rootKeyFile := rootFile[:len(rootFile)-4] + ".key"
	interKeyFile := interFile[:len(interFile)-4] + ".key"
	leafKeyFile := leafFile[:len(leafFile)-4] + ".key"
	savePrivateKeyFromPair(rootKey, rootKeyFile)
	savePrivateKeyFromPair(interKey, interKeyFile)
	savePrivateKeyFromPair(leafKey, leafKeyFile)

	rootCert, _ := ParseCertificate(rootDER)
	interCert, _ := ParseCertificate(interDER)
	leafCert, _ := ParseCertificate(leafDER)

	PrintCertInfo(rootCert, chainName+" - 根证书")
	PrintCertInfo(interCert, chainName+" - 中间证书")
	PrintCertInfo(leafCert, chainName+" - 用户证书")

	return VerifyCertificateChain(
		chainName,
		leafDER,
		interDER,
		rootDER,
		interKey.SignPK,
		interAlgo,
		rootKey.SignPK,
		rootAlgo,
	)
}

func main() {
	ensureDir()
	fmt.Println("=== 四套纯抗量子 X.509 v3 证书链：Kyber / Dilithium / SPHINCS / 256比特等级 ===")

	// 1. Kyber 用户证书链：
	// Root 和 Intermediate 用 Dilithium 签名，User 公钥是 Kyber
	kyberOK := buildChain(
		"链1：Kyber用户证书链，CA使用Dilithium签名",
		"Kyber-Chain-Root-Dilithium",
		"Kyber-Chain-Intermediate-Dilithium",
		"user-kyber512",
		oidMLDSA44,
		oidMLDSA65,
		oidKyber512,
		"kyber_chain_root_dilithium.pem",
		"kyber_chain_intermediate_dilithium.pem",
		"user_kyber512.pem",
	)

	// 2. Dilithium 用户证书链：
	// Root、Intermediate、User 都是 Dilithium
	dilithiumOK := buildChain(
		"链2：全Dilithium证书链",
		"Dilithium-Chain-Root",
		"Dilithium-Chain-Intermediate",
		"user-dilithium",
		oidMLDSA44,
		oidMLDSA65,
		oidMLDSA44,
		"dilithium_chain_root.pem",
		"dilithium_chain_intermediate.pem",
		"user_dilithium.pem",
	)

	// 3. SPHINCS 用户证书链：
	// Root、Intermediate、User 全部使用 SPHINCS / SLH-DSA
	sphincsOK := buildChain(
		"链3：全SPHINCS证书链",
		"SPHINCS-Chain-Root",
		"SPHINCS-Chain-Intermediate",
		"user-sphincs",
		oidSLHDSA128s,
		oidSLHDSA128s,
		oidSLHDSA128s,
		"sphincs_chain_root.pem",
		"sphincs_chain_intermediate.pem",
		"user_sphincs.pem",
	)

	// 4. 256 比特量子安全等级证书链：
	// Root、Intermediate 用 ML-DSA-87 签名，User 公钥是 Kyber-1024
	level256OK := buildChain(
		"链4：256 比特量子安全等级链（ML-DSA-87 签名 + Kyber-1024 用户公钥）",
		"Level256-Chain-Root-MLDSA87",
		"Level256-Chain-Intermediate-MLDSA87",
		"user-kyber1024",
		oidMLDSA87,
		oidMLDSA87,
		oidKyber1024,
		"level256_chain_root_mldsa87.pem",
		"level256_chain_intermediate_mldsa87.pem",
		"user_kyber1024.pem",
	)

	fmt.Println("\n==================================================")
	fmt.Println("🎉 最终结果")
	fmt.Println("==================================================")
	fmt.Printf("Kyber用户证书链可信: %v\n", kyberOK)
	fmt.Printf("Dilithium证书链可信: %v\n", dilithiumOK)
	fmt.Printf("SPHINCS证书链可信: %v\n", sphincsOK)
	fmt.Printf("256比特等级链(ML-DSA-87)可信: %v\n", level256OK)

	fmt.Println("\n量子安全等级覆盖：")
	fmt.Println("  128 比特：ML-DSA-44/Dilithium2（签名）、Kyber-512（KEM）")
	fmt.Println("  192 比特：ML-DSA-65/Dilithium3（签名）、Kyber-768（KEM）")
	fmt.Println("  256 比特：ML-DSA-87/Dilithium5（签名）、Kyber-1024（KEM）")

	fmt.Println("\n✅ 全部完成！")
}
