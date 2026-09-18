package main

import (
	"crypto/rand"
	"encoding"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode2"
)

const (
	outputDir     = "../certs-sample"
	userLoginName = "admin3"
)

// OID
var (
	oidMLDSA44          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 11}
	oidCommonName       = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
)

// ---- ASN.1 结构 ----
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

// ---- 解析外部公钥 ----
func parseMLDSAPublicKey(filePath string) []byte {
	data, err := os.ReadFile(filePath)
	if err != nil {
		panic(fmt.Sprintf("读取公钥文件失败: %v", err))
	}
	content := string(data)

	pos := strings.Index(content, "[ML-DSA-44]")
	if pos == -1 {
		panic("未找到 [ML-DSA-44] 段")
	}
	section := content[pos:]
	if end := strings.Index(section[1:], "["); end != -1 {
		section = section[:end+1]
	}

	var pubHex string
	for _, line := range strings.Split(section, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "PublicKey=") {
			pubHex = strings.TrimPrefix(line, "PublicKey=")
		}
	}
	if pubHex == "" {
		panic("[ML-DSA-44] 段中未找到 PublicKey")
	}

	raw, err := hex.DecodeString(pubHex)
	if err != nil {
		panic(fmt.Sprintf("ML-DSA 公钥 hex 解析失败: %v", err))
	}
	return raw
}

// ---- 工具函数 ----
func genSerial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	return n
}

func newName(cn string) asn1.RawValue {
	rdn := []struct {
		ID    asn1.ObjectIdentifier
		Value string
	}{{oidCommonName, cn}}
	der, _ := asn1.Marshal(rdn)
	return asn1.RawValue{FullBytes: der}
}

func createExtension(oid asn1.ObjectIdentifier, critical bool, value any) Extension {
	der, _ := asn1.Marshal(value)
	return Extension{Id: oid, Critical: critical, Value: der}
}

func generateCertificate(
	subjectCN, issuerCN string,
	validDays int,
	isCA bool, maxPathLen int,
	subjectPubBytes []byte,
	signerSK *mode2.PrivateKey,
) []byte {
	subj := newName(subjectCN)
	issuer := newName(issuerCN)

	spki := SubjectPublicKeyInfo{
		Algorithm: AlgorithmIdentifier{Algorithm: oidMLDSA44},
		PublicKey: asn1.BitString{
			Bytes:     subjectPubBytes,
			BitLength: len(subjectPubBytes) * 8,
		},
	}

	var exts []Extension
	exts = append(exts, createExtension(oidBasicConstraints, true, BasicConstraints{
		IsCA: isCA, MaxPathLen: maxPathLen,
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
		SerialNumber:         genSerial(),
		Signature:            AlgorithmIdentifier{Algorithm: oidMLDSA44},
		Issuer:               issuer,
		Validity:             Validity{NotBefore: time.Now(), NotAfter: time.Now().AddDate(0, 0, validDays)},
		Subject:              subj,
		SubjectPublicKeyInfo: spki,
		Extensions:           exts,
	}

	tbsDER, _ := asn1.Marshal(tbs)

	sig := make([]byte, mode2.SignatureSize)
	mode2.SignTo(signerSK, tbsDER, sig)

	cert := Certificate{
		TBSCertificate:     tbs,
		SignatureAlgorithm: AlgorithmIdentifier{Algorithm: oidMLDSA44},
		SignatureValue:     asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	}
	der, _ := asn1.Marshal(cert)
	return der
}

func verifyCert(certDER []byte, rootPub *mode2.PublicKey) bool {
	var cert Certificate
	if _, err := asn1.Unmarshal(certDER, &cert); err != nil {
		return false
	}
	tbsDER, _ := asn1.Marshal(cert.TBSCertificate)
	return mode2.Verify(rootPub, tbsDER, cert.SignatureValue.Bytes)
}

func savePEM(filename, blockType string, der []byte) {
	path := filepath.Join(outputDir, filename)
	os.MkdirAll(outputDir, 0755)
	_ = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0644)
	fmt.Printf("✅ 已保存: %s\n", path)
}

func savePQKey(key interface{}, filename string) {
	marshaler, ok := key.(encoding.BinaryMarshaler)
	if !ok {
		fmt.Printf("⚠️ 无法序列化: %s\n", filename)
		return
	}
	data, _ := marshaler.MarshalBinary()
	savePEM(filename, "PRIVATE KEY", data)
}

// ---- main ----
func main() {
	fmt.Println("==============================================")
	fmt.Println("  纯 PQ 证书链：ML-DSA Root（自签名）→ User")
	fmt.Println("==============================================")

	// ─── 1. 导入外部 ML-DSA 用户公钥 ───
	userPubBytes := parseMLDSAPublicKey("../data/public_keys.txt")
	var userPub mode2.PublicKey
	if err := userPub.UnmarshalBinary(userPubBytes); err != nil {
		panic(fmt.Sprintf("解析 ML-DSA 公钥失败: %v", err))
	}
	fmt.Printf("\n✅ 导入外部 ML-DSA-44 用户公钥 (%d 字节)\n", len(userPubBytes))

	// ─── 2. Root CA 自签名证书 ───
	rootPK, rootSK, _ := mode2.GenerateKey(rand.Reader)
	rootPubBytes := rootPK.Bytes()

	rootDER := generateCertificate(
		"ML-DSA-Root-CA", "ML-DSA-Root-CA",
		3650, true, 0,
		rootPubBytes, rootSK,
	)
	savePEM("mldsa_root.pem", "CERTIFICATE", rootDER)
	fmt.Printf("\n── ML-DSA Root CA 证书 ──\n")
	fmt.Printf("  CN: ML-DSA-Root-CA | 自签名 | CA: true\n")
	fmt.Printf("  公钥: %d 字节 | 签名: %d 字节\n", len(rootPubBytes), mode2.SignatureSize)

	// ─── 3. 用户证书（外部公钥，Root 签发，只给证书） ───
	userDER := generateCertificate(
		userLoginName, "ML-DSA-Root-CA",
		365, false, -1,
		userPubBytes, rootSK,
	)
	savePEM("mldsa_user.pem", "CERTIFICATE", userDER)
	fmt.Println("ℹ️  用户私钥在对接方手中，不导出")
	fmt.Printf("\n── ML-DSA 用户证书 ──\n")
	fmt.Printf("  CN: %s | Issuer: ML-DSA-Root-CA | CA: false\n", userLoginName)

	// ─── 4. 验证 ───
	fmt.Println("\n==============================================")
	fmt.Println("  🔍 证书链验证")
	fmt.Println("==============================================")
	rootOK := verifyCert(rootDER, rootPK)
	userOK := verifyCert(userDER, rootPK)
	fmt.Printf("  Root 自签名:       %v\n", rootOK)
	fmt.Printf("  User 由 Root 签发:  %v\n", userOK)
	if rootOK && userOK {
		fmt.Println("\n🎉 纯 PQ 证书链验证通过！")
	} else {
		fmt.Println("\n❌ 证书链验证失败！")
	}
}
