package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	mode2 "pqtls_project/internal/crypto/myvendor/github.com/cloudflare/circl/sign/dilithium/mode2"
)

// 定义抗量子算法相关的OID（示例）
var (
	OIDQuantumPublicKey = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 54321, 1, 1}
	OIDQuantumSignature = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 54321, 1, 2}
)

// 使用 Dilithium2（mode2）
var dilithiumName = "Dilithium2"

// 证书保存目录
const certDir = "./certs"

// 证书文件命名
var certFiles = map[string]string{
	"root":          "root-ca.pem",
	"intermediate1": "intermediate1-ca.pem",
	"intermediate2": "intermediate2-ca.pem",
	"endentity":     "end-entity.pem",
}

// 私钥文件命名
var keyFiles = map[string]string{
	"root":          "root-ca-key.pem",
	"intermediate1": "intermediate1-ca-key.pem",
	"intermediate2": "intermediate2-ca-key.pem",
	"endentity":     "end-entity-key.pem",
}

// 抗量子私钥文件命名
var pqKeyFiles = map[string]string{
	"root":          "root-ca-pq-key.bin",
	"intermediate1": "intermediate1-ca-pq-key.bin",
	"intermediate2": "intermediate2-ca-pq-key.bin",
	"endentity":     "end-entity-pq-key.bin",
}

// 检查证书是否支持抗量子算法
func CheckQuantumResistanceSupport(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDQuantumPublicKey) || ext.Id.Equal(OIDQuantumSignature) {
			return true
		}
	}
	return false
}

// 获取证书支持的抗量子算法信息
func GetQuantumAlgorithmInfo(cert *x509.Certificate) *QuantumAlgorithmInfo {
	info := &QuantumAlgorithmInfo{
		HasQuantumPublicKey: false,
		HasQuantumSignature: false,
		PublicKeySize:       0,
		SignatureSize:       0,
		SupportedAlgorithms: []string{},
	}

	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDQuantumPublicKey) {
			info.HasQuantumPublicKey = true
			info.PublicKeySize = len(ext.Value)

			// 根据公钥大小推断算法类型
			switch len(ext.Value) {
			case mode2.PublicKeySize:
				info.SupportedAlgorithms = append(info.SupportedAlgorithms, "Dilithium2")
			case 1952: // Dilithium3 公钥大小
				info.SupportedAlgorithms = append(info.SupportedAlgorithms, "Dilithium3")
			case 2592: // Dilithium5 公钥大小
				info.SupportedAlgorithms = append(info.SupportedAlgorithms, "Dilithium5")
			default:
				info.SupportedAlgorithms = append(info.SupportedAlgorithms, fmt.Sprintf("未知算法(公钥大小:%d)", len(ext.Value)))
			}
		} else if ext.Id.Equal(OIDQuantumSignature) {
			info.HasQuantumSignature = true
			info.SignatureSize = len(ext.Value)

			// 根据签名大小推断算法类型
			switch len(ext.Value) {
			case mode2.SignatureSize:
				if !contains(info.SupportedAlgorithms, "Dilithium2") {
					info.SupportedAlgorithms = append(info.SupportedAlgorithms, "Dilithium2")
				}
			case 3293: // Dilithium3 签名大小
				if !contains(info.SupportedAlgorithms, "Dilithium3") {
					info.SupportedAlgorithms = append(info.SupportedAlgorithms, "Dilithium3")
				}
			case 4595: // Dilithium5 签名大小
				if !contains(info.SupportedAlgorithms, "Dilithium5") {
					info.SupportedAlgorithms = append(info.SupportedAlgorithms, "Dilithium5")
				}
			default:
				if !contains(info.SupportedAlgorithms, fmt.Sprintf("未知算法(签名大小:%d)", len(ext.Value))) {
					info.SupportedAlgorithms = append(info.SupportedAlgorithms, fmt.Sprintf("未知算法(签名大小:%d)", len(ext.Value)))
				}
			}
		}
	}

	return info
}

// 抗量子算法信息结构
type QuantumAlgorithmInfo struct {
	HasQuantumPublicKey bool
	HasQuantumSignature bool
	PublicKeySize       int
	SignatureSize       int
	SupportedAlgorithms []string
}

// 辅助函数：检查字符串切片是否包含某个元素
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// 打印抗量子算法支持信息
func PrintQuantumSupportInfo(cert *x509.Certificate, certName string) {
	fmt.Printf("\n=== %s 抗量子算法支持信息 ===\n", certName)

	if CheckQuantumResistanceSupport(cert) {
		fmt.Println("✓ 支持抗量子算法")

		info := GetQuantumAlgorithmInfo(cert)

		if info.HasQuantumPublicKey {
			fmt.Printf("✓ 包含抗量子公钥扩展\n")
			fmt.Printf("  公钥大小: %d 字节\n", info.PublicKeySize)
		} else {
			fmt.Printf("✗ 未找到抗量子公钥扩展\n")
		}

		if info.HasQuantumSignature {
			fmt.Printf("✓ 包含抗量子签名扩展\n")
			fmt.Printf("  签名大小: %d 字节\n", info.SignatureSize)
		} else {
			fmt.Printf("✗ 未找到抗量子签名扩展\n")
		}

		if len(info.SupportedAlgorithms) > 0 {
			fmt.Printf("  支持的算法: %v\n", info.SupportedAlgorithms)
		}

		// 检查抗量子签名验证状态
		quantumPublicKey, quantumSignature, _ := extractQuantumExtensions(cert)
		if quantumPublicKey != nil && quantumSignature != nil {
			fmt.Printf("✓ 抗量子密钥对完整\n")
		} else {
			fmt.Printf("⚠ 抗量子密钥对不完整\n")
		}

	} else {
		fmt.Println("✗ 不支持抗量子算法")
	}

	// 检查扩展字段详情
	fmt.Println("\n扩展字段详情:")
	quantumExtCount := 0
	for i, ext := range cert.Extensions {
		if ext.Id.Equal(OIDQuantumPublicKey) || ext.Id.Equal(OIDQuantumSignature) {
			extType := "公钥"
			if ext.Id.Equal(OIDQuantumSignature) {
				extType = "签名"
			}
			fmt.Printf("  [%d] %s扩展 (OID: %s, 大小: %d 字节)\n",
				i, extType, ext.Id.String(), len(ext.Value))
			quantumExtCount++
		}
	}

	if quantumExtCount == 0 {
		fmt.Println("  未找到抗量子相关扩展")
	}

	fmt.Println("=====================================")
}

// 验证抗量子签名功能
func VerifyQuantumSignature(cert *x509.Certificate, parent *x509.Certificate) error {
	fmt.Printf("\n验证 %s 的抗量子签名:\n", cert.Subject.CommonName)

	// 检查是否支持抗量子
	if !CheckQuantumResistanceSupport(cert) {
		return fmt.Errorf("证书不支持抗量子算法")
	}

	info := GetQuantumAlgorithmInfo(cert)
	if !info.HasQuantumSignature {
		return fmt.Errorf("证书未包含抗量子签名")
	}

	if !CheckQuantumResistanceSupport(parent) {
		return fmt.Errorf("父证书不支持抗量子算法")
	}

	parentInfo := GetQuantumAlgorithmInfo(parent)
	if !parentInfo.HasQuantumPublicKey {
		return fmt.Errorf("父证书未包含抗量子公钥")
	}

	// 从父证书提取抗量子公钥
	parentQuantumPublicKey, err := extractQuantumPublicKeyFromParent(parent)
	if err != nil {
		return fmt.Errorf("提取父证书抗量子公钥失败: %v", err)
	}

	// 从当前证书提取抗量子签名
	quantumSignature, err := extractQuantumSignatureFromCert(cert)
	if err != nil {
		return fmt.Errorf("提取抗量子签名失败: %v", err)
	}

	// 构建验证模板
	verificationTemplate := x509.Certificate{
		Version:      cert.Version,
		SerialNumber: cert.SerialNumber,
		Issuer:       parent.Subject,
		Subject:      cert.Subject,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		PublicKey:    cert.PublicKey,
	}

	// 使用原始数据确保一致性
	if cert.RawIssuer != nil {
		verificationTemplate.RawIssuer = make([]byte, len(cert.RawIssuer))
		copy(verificationTemplate.RawIssuer, cert.RawIssuer)
	}
	if cert.RawSubject != nil {
		verificationTemplate.RawSubject = make([]byte, len(cert.RawSubject))
		copy(verificationTemplate.RawSubject, cert.RawSubject)
	}

	// 创建TBS数据
	tbsData, err := createTBSDataWithoutExtensions(&verificationTemplate)
	if err != nil {
		return fmt.Errorf("创建TBS数据失败: %v", err)
	}

	fmt.Printf("  TBS数据哈希: %x\n", sha256.Sum256(tbsData))
	fmt.Printf("  签名大小: %d 字节\n", len(quantumSignature))

	// 验证签名
	if !quantumVerify(parentQuantumPublicKey, tbsData, quantumSignature) {
		return fmt.Errorf("抗量子签名验证失败")
	}

	fmt.Printf("✓ 抗量子签名验证成功\n")
	return nil
}

// 批量检查证书链的抗量子支持
func CheckCertificateChainQuantumSupport(certChain ...*x509.Certificate) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("证书链抗量子算法支持检查")
	fmt.Println(strings.Repeat("=", 60))

	for i, cert := range certChain {
		certName := fmt.Sprintf("证书 %d: %s", i+1, cert.Subject.CommonName)
		PrintQuantumSupportInfo(cert, certName)

		// 如果是中间证书或叶子证书，尝试验证抗量子签名
		if i > 0 {
			parent := certChain[i-1]
			err := VerifyQuantumSignature(cert, parent)
			if err != nil {
				fmt.Printf("⚠ 抗量子签名验证失败: %v\n", err)
			}
		}
	}

	fmt.Println(strings.Repeat("=", 60))
}

// 确保证书目录存在
func ensureCertDir() error {
	return os.MkdirAll(certDir, 0755)
}

// 抗量子密钥对结构（使用 mode2）
type QuantumKeyPair struct {
	PrivateKey *mode2.PrivateKey
	PublicKey  *mode2.PublicKey
}

func printCertificateInfo(cert *x509.Certificate) {
	fmt.Println("====== 证书信息 ======")
	fmt.Printf("版本: %d\n", cert.Version)
	fmt.Printf("序列号: %s\n", cert.SerialNumber.String())
	fmt.Printf("签名算法: %s\n", cert.SignatureAlgorithm.String())
	fmt.Printf("颁发者(Issuer): %s\n", cert.Issuer.String())
	fmt.Printf("使用者(Subject): %s\n", cert.Subject.String())
	fmt.Printf("有效期: %s ~ %s\n", cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
	fmt.Printf("是否CA: %t\n", cert.IsCA)
	fmt.Printf("Key Usage: %v\n", cert.KeyUsage)
	fmt.Printf("扩展Key Usage: %v\n", cert.ExtKeyUsage)
	fmt.Printf("自签名证书: %t\n", isSelfSigned(cert))

	// 公钥信息
	fmt.Printf("公钥算法: %s\n", cert.PublicKeyAlgorithm.String())

	// SubjectKeyId 和 AuthorityKeyId
	if len(cert.SubjectKeyId) > 0 {
		fmt.Printf("Subject Key Identifier: %s\n", hex.EncodeToString(cert.SubjectKeyId))
	}
	if len(cert.AuthorityKeyId) > 0 {
		fmt.Printf("Authority Key Identifier: %s\n", hex.EncodeToString(cert.AuthorityKeyId))
	}

	// SAN（DNS/Email/IP）
	if len(cert.DNSNames) > 0 {
		fmt.Printf("DNS 名称: %v\n", cert.DNSNames)
	}

	// 扩展字段
	if len(cert.Extensions) > 0 {
		fmt.Println("扩展字段:")
		for _, ext := range cert.Extensions {
			fmt.Printf("  OID=%s, Critical=%v, ValueLen=%d\n", ext.Id.String(), ext.Critical, len(ext.Value))
		}
	}
	fmt.Println("=====================")
}

// 检查证书是否为自签名
func isSelfSigned(cert *x509.Certificate) bool {
	return cert.Issuer.String() == cert.Subject.String()
}

// 保存证书到文件
func saveCertificate(cert *x509.Certificate, certType string) error {
	if err := ensureCertDir(); err != nil {
		return err
	}

	filename := filepath.Join(certDir, certFiles[certType])
	certOut, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("创建证书文件失败: %v", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}); err != nil {
		return fmt.Errorf("编码证书失败: %v", err)
	}

	log.Printf("证书已保存: %s", filename)
	return nil
}

// 从文件加载证书
func loadCertificate(certType string) (*x509.Certificate, error) {
	filename := filepath.Join(certDir, certFiles[certType])
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("读取证书文件失败: %v", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("解析PEM数据失败")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("不是证书文件")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析证书失败: %v", err)
	}

	log.Printf("证书已加载: %s", filename)
	return cert, nil
}

// 保存RSA私钥到文件
func saveRSAPrivateKey(privKey *rsa.PrivateKey, keyType string) error {
	if err := ensureCertDir(); err != nil {
		return err
	}

	filename := filepath.Join(certDir, keyFiles[keyType])
	keyOut, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("创建私钥文件失败: %v", err)
	}
	defer keyOut.Close()

	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("序列化私钥失败: %v", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyBytes,
	}); err != nil {
		return fmt.Errorf("编码私钥失败: %v", err)
	}

	log.Printf("RSA私钥已保存: %s", filename)
	return nil
}

// 从文件加载RSA私钥
func loadRSAPrivateKey(keyType string) (*rsa.PrivateKey, error) {
	filename := filepath.Join(certDir, keyFiles[keyType])
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("读取私钥文件失败: %v", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("解析PEM数据失败")
	}

	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("不是私钥文件")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析私钥失败: %v", err)
	}

	privKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("不是RSA私钥")
	}

	log.Printf("RSA私钥已加载: %s", filename)
	return privKey, nil
}

// 保存抗量子私钥到文件
func savePQPrivateKey(pqKeyPair *QuantumKeyPair, keyType string) error {
	if err := ensureCertDir(); err != nil {
		return err
	}

	filename := filepath.Join(certDir, pqKeyFiles[keyType])
	keyOut, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("创建抗量子私钥文件失败: %v", err)
	}
	defer keyOut.Close()

	// 序列化抗量子私钥
	privKeyBytes := pqKeyPair.PrivateKey.Bytes()
	if _, err := keyOut.Write(privKeyBytes); err != nil {
		return fmt.Errorf("写入抗量子私钥失败: %v", err)
	}

	log.Printf("抗量子私钥已保存: %s", filename)
	return nil
}

// 从文件加载抗量子私钥
func loadPQPrivateKey(keyType string) (*mode2.PrivateKey, error) {
	filename := filepath.Join(certDir, pqKeyFiles[keyType])
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("读取抗量子私钥文件失败: %v", err)
	}

	var privKey mode2.PrivateKey
	if err := privKey.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("解析抗量子私钥失败: %v", err)
	}

	log.Printf("抗量子私钥已加载: %s", filename)
	return &privKey, nil
}

// 检查证书是否已存在
func certificateExists(certType string) bool {
	filename := filepath.Join(certDir, certFiles[certType])
	_, err := os.Stat(filename)
	return err == nil
}

// 生成抗量子密钥对（mode2）
func generateQuantumKeyPair() (*QuantumKeyPair, error) {
	pk, sk, err := mode2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("生成Dilithium密钥对失败: %v", err)
	}
	return &QuantumKeyPair{
		PrivateKey: sk,
		PublicKey:  pk,
	}, nil
}

// 抗量子签名（mode2.SignTo）
func quantumSign(privateKey *mode2.PrivateKey, data []byte) ([]byte, error) {
	signature := make([]byte, mode2.SignatureSize)
	mode2.SignTo(privateKey, data, signature)
	return signature, nil
}

// 抗量子签名验证（mode2.Verify）
func quantumVerify(publicKey *mode2.PublicKey, data []byte, signature []byte) bool {
	return mode2.Verify(publicKey, data, signature)
}

// 序列化 Dilithium 公钥（返回字节切片）
func serializeDilithiumPublicKey(publicKey *mode2.PublicKey) []byte {
	if publicKey == nil {
		return nil
	}
	return publicKey.Bytes()
}

// 反序列化 Dilithium 公钥（返回 *mode2.PublicKey）
func deserializeDilithiumPublicKey(data []byte) (*mode2.PublicKey, error) {
	var pk mode2.PublicKey
	if err := pk.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return &pk, nil
}

// 生成主题密钥标识符 (使用传统公钥)
func generateSubjectKeyId(pubKey crypto.PublicKey) []byte {
	pubBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil
	}
	hash := sha256.Sum256(pubBytes)
	return hash[:]
}

// 创建TBS数据（不包含任何扩展字段）并确保一致性
func createTBSDataWithoutExtensions(template *x509.Certificate) ([]byte, error) {
	type TBSCertificate struct {
		Version            int `asn1:"optional,explicit,default:0,tag:0"`
		SerialNumber       *big.Int
		SignatureAlgorithm pkix.AlgorithmIdentifier
		Issuer             asn1.RawValue
		Validity           struct {
			NotBefore time.Time
			NotAfter  time.Time
		}
		Subject   asn1.RawValue
		PublicKey struct {
			Algorithm pkix.AlgorithmIdentifier
			PublicKey asn1.BitString
		}
		IssuerUniqueID  asn1.BitString `asn1:"optional,tag:1"`
		SubjectUniqueID asn1.BitString `asn1:"optional,tag:2"`
	}

	var tbs TBSCertificate

	// 关键修复1：确保版本一致（使用v3证书）
	tbs.Version = 2 // ASN.1中v3证书表示为2（0=v1, 1=v2, 2=v3）

	tbs.SerialNumber = template.SerialNumber

	// 使用证书实际的签名算法
	tbs.SignatureAlgorithm = pkix.AlgorithmIdentifier{
		Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, // sha256WithRSAEncryption
	}

	// 关键修复2：确保颁发者一致
	if template.RawIssuer != nil {
		// 如果有原始颁发者数据，直接使用
		tbs.Issuer = asn1.RawValue{FullBytes: template.RawIssuer}
	} else if template.Issuer.String() != "" {
		// 否则手动编码颁发者
		issuerRDNs := template.Issuer.ToRDNSequence()
		issuerBytes, err := asn1.Marshal(issuerRDNs)
		if err != nil {
			return nil, fmt.Errorf("编码颁发者失败: %v", err)
		}
		tbs.Issuer = asn1.RawValue{FullBytes: issuerBytes}
	} else {
		// 如果颁发者为空，使用空序列
		emptySeq, _ := asn1.Marshal([]asn1.RawValue{})
		tbs.Issuer = asn1.RawValue{FullBytes: emptySeq}
	}

	// 关键修复3：确保使用者一致
	if template.RawSubject != nil {
		tbs.Subject = asn1.RawValue{FullBytes: template.RawSubject}
	} else {
		subjectRDNs := template.Subject.ToRDNSequence()
		subjectBytes, err := asn1.Marshal(subjectRDNs)
		if err != nil {
			return nil, fmt.Errorf("编码使用者失败: %v", err)
		}
		tbs.Subject = asn1.RawValue{FullBytes: subjectBytes}
	}

	// 关键修复4：确保时间格式一致（使用UTC）
	tbs.Validity.NotBefore = template.NotBefore.UTC()
	tbs.Validity.NotAfter = template.NotAfter.UTC()

	// 关键修复5：确保公钥一致
	tbs.PublicKey.Algorithm = pkix.AlgorithmIdentifier{
		Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}, // rsaEncryption
	}

	if template.PublicKey != nil {
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(template.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("序列化公钥失败: %v", err)
		}
		var pubKeyInfo struct {
			Algorithm pkix.AlgorithmIdentifier
			PublicKey asn1.BitString
		}
		if _, err := asn1.Unmarshal(pubKeyBytes, &pubKeyInfo); err != nil {
			return nil, fmt.Errorf("解析公钥信息失败: %v", err)
		}
		tbs.PublicKey.PublicKey = pubKeyInfo.PublicKey
	} else {
		// 如果公钥为空，记录警告
		log.Println("警告: 模板公钥为空")
	}

	// 序列化TBS数据
	tbsData, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("序列化TBS数据失败: %v", err)
	}

	return tbsData, nil
}

// 从证书扩展中提取抗量子公钥和签名
func extractQuantumExtensions(cert *x509.Certificate) (*mode2.PublicKey, []byte, error) {
	var quantumPublicKey *mode2.PublicKey
	var quantumSignature []byte

	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDQuantumPublicKey) {
			pk, err := deserializeDilithiumPublicKey(ext.Value)
			if err != nil {
				return nil, nil, fmt.Errorf("反序列化抗量子公钥失败: %v", err)
			}
			quantumPublicKey = pk
		} else if ext.Id.Equal(OIDQuantumSignature) {
			quantumSignature = ext.Value
		}
	}

	return quantumPublicKey, quantumSignature, nil
}

// 从父证书提取抗量子公钥
func extractQuantumPublicKeyFromParent(parent *x509.Certificate) (*mode2.PublicKey, error) {
	for _, ext := range parent.Extensions {
		if ext.Id.Equal(OIDQuantumPublicKey) {
			return deserializeDilithiumPublicKey(ext.Value)
		}
	}
	return nil, fmt.Errorf("父证书中未找到抗量子公钥")
}

// 生成自签名根 CA（带抗量子公钥扩展）
func generateRootCA() (*rsa.PrivateKey, *x509.Certificate, *QuantumKeyPair, error) {
	// 如果证书已存在，则加载
	if certificateExists("root") {
		log.Println("根CA证书已存在，正在加载...")
		privKey, err := loadRSAPrivateKey("root")
		if err != nil {
			return nil, nil, nil, err
		}
		cert, err := loadCertificate("root")
		if err != nil {
			return nil, nil, nil, err
		}
		pqPrivKey, err := loadPQPrivateKey("root")
		if err != nil {
			return nil, nil, nil, err
		}

		// 从证书扩展中提取抗量子公钥
		pqPubKey, _, err := extractQuantumExtensions(cert)
		if err != nil {
			return nil, nil, nil, err
		}

		return privKey, cert, &QuantumKeyPair{PrivateKey: pqPrivKey, PublicKey: pqPubKey}, nil
	}

	log.Println("生成新的自签名根CA证书...")
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}

	quantumKeyPair, err := generateQuantumKeyPair()
	if err != nil {
		return nil, nil, nil, err
	}

	// 明确创建自签名证书模板
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Quantum Root CA"},
			Country:       []string{"US"},
			Province:      []string{"California"},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Quantum Street 123"},
			PostalCode:    []string{"94105"},
			CommonName:    "Quantum Root CA",
		},
		// 对于自签名证书，颁发者和主题相同
		Issuer: pkix.Name{
			Organization:  []string{"Quantum Root CA"},
			Country:       []string{"US"},
			Province:      []string{"California"},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Quantum Street 123"},
			PostalCode:    []string{"94105"},
			CommonName:    "Quantum Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10年有效期
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
		SubjectKeyId:          generateSubjectKeyId(privKey.PublicKey),
		ExtraExtensions: []pkix.Extension{
			{
				Id:       OIDQuantumPublicKey,
				Critical: false,
				Value:    serializeDilithiumPublicKey(quantumKeyPair.PublicKey),
			},
		},
	}

	// 明确使用自签名：证书和父证书都是同一个模板
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, nil, err
	}

	// 验证确实是自签名
	if !isSelfSigned(cert) {
		return nil, nil, nil, fmt.Errorf("生成的根证书不是自签名证书")
	}

	// 保存证书和密钥
	if err := saveCertificate(cert, "root"); err != nil {
		return nil, nil, nil, err
	}
	if err := saveRSAPrivateKey(privKey, "root"); err != nil {
		return nil, nil, nil, err
	}
	if err := savePQPrivateKey(quantumKeyPair, "root"); err != nil {
		return nil, nil, nil, err
	}

	log.Printf("自签名根CA证书生成成功: %s", cert.Subject.CommonName)
	return privKey, cert, quantumKeyPair, nil
}

// 生成中间 CA（由 root 签名），并在 extra extension 中加入量子签名
func generateIntermediateCA(rootPrivKey *rsa.PrivateKey, rootCert *x509.Certificate, rootQuantumKeyPair *QuantumKeyPair) (*rsa.PrivateKey, *x509.Certificate, *QuantumKeyPair, error) {
	// 如果证书已存在，则加载
	if certificateExists("intermediate1") {
		log.Println("第一级中间CA证书已存在，正在加载...")
		privKey, err := loadRSAPrivateKey("intermediate1")
		if err != nil {
			return nil, nil, nil, err
		}
		cert, err := loadCertificate("intermediate1")
		if err != nil {
			return nil, nil, nil, err
		}
		pqPrivKey, err := loadPQPrivateKey("intermediate1")
		if err != nil {
			return nil, nil, nil, err
		}

		// 从证书扩展中提取抗量子公钥
		pqPubKey, _, err := extractQuantumExtensions(cert)
		if err != nil {
			return nil, nil, nil, err
		}

		return privKey, cert, &QuantumKeyPair{PrivateKey: pqPrivKey, PublicKey: pqPubKey}, nil
	}

	log.Println("生成新的第一级中间CA证书...")
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}

	quantumKeyPair, err := generateQuantumKeyPair()
	if err != nil {
		return nil, nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Quantum Intermediate CA"},
			Country:      []string{"US"},
			Province:     []string{"CA"},
			CommonName:   "Quantum Intermediate CA Level 1",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour), // 5年有效期
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		SubjectKeyId:          generateSubjectKeyId(privKey.PublicKey),
		AuthorityKeyId:        rootCert.SubjectKeyId,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       OIDQuantumPublicKey,
				Critical: false,
				Value:    serializeDilithiumPublicKey(quantumKeyPair.PublicKey),
			},
		},
	}

	// 关键修复：在生成TBS数据前设置所有必要字段
	template.PublicKey = &privKey.PublicKey
	template.Issuer = rootCert.Subject // 设置颁发者为根CA的主题
	template.Version = 3               // 明确设置版本为3

	// 生成不包含扩展字段的TBS数据用于抗量子签名
	tbsData, err := createTBSDataWithoutExtensions(&template)
	if err != nil {
		return nil, nil, nil, err
	}

	quantumSignature, err := quantumSign(rootQuantumKeyPair.PrivateKey, tbsData)
	if err != nil {
		return nil, nil, nil, err
	}

	// 把量子签名放进扩展里
	template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
		Id:       OIDQuantumSignature,
		Critical: false,
		Value:    quantumSignature,
	})

	certDER, err := x509.CreateCertificate(rand.Reader, &template, rootCert, &privKey.PublicKey, rootPrivKey)
	if err != nil {
		return nil, nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, nil, err
	}

	// 保存证书和密钥
	if err := saveCertificate(cert, "intermediate1"); err != nil {
		return nil, nil, nil, err
	}
	if err := saveRSAPrivateKey(privKey, "intermediate1"); err != nil {
		return nil, nil, nil, err
	}
	if err := savePQPrivateKey(quantumKeyPair, "intermediate1"); err != nil {
		return nil, nil, nil, err
	}

	return privKey, cert, quantumKeyPair, nil
}

// 生成第二级中间 CA
func generateIntermediateCA2(intermediatePrivKey *rsa.PrivateKey, intermediateCert *x509.Certificate, intermediateQuantumKeyPair *QuantumKeyPair) (*rsa.PrivateKey, *x509.Certificate, *QuantumKeyPair, error) {
	// 如果证书已存在，则加载
	if certificateExists("intermediate2") {
		log.Println("第二级中间CA证书已存在，正在加载...")
		privKey, err := loadRSAPrivateKey("intermediate2")
		if err != nil {
			return nil, nil, nil, err
		}
		cert, err := loadCertificate("intermediate2")
		if err != nil {
			return nil, nil, nil, err
		}
		pqPrivKey, err := loadPQPrivateKey("intermediate2")
		if err != nil {
			return nil, nil, nil, err
		}

		// 从证书扩展中提取抗量子公钥
		pqPubKey, _, err := extractQuantumExtensions(cert)
		if err != nil {
			return nil, nil, nil, err
		}

		return privKey, cert, &QuantumKeyPair{PrivateKey: pqPrivKey, PublicKey: pqPubKey}, nil
	}

	log.Println("生成新的第二级中间CA证书...")
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}

	quantumKeyPair, err := generateQuantumKeyPair()
	if err != nil {
		return nil, nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Organization: []string{"Quantum Issuing CA"},
			Country:      []string{"US"},
			CommonName:   "Quantum Issuing CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(3 * 365 * 24 * time.Hour), // 3年有效期
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		SubjectKeyId:          generateSubjectKeyId(privKey.PublicKey),
		AuthorityKeyId:        intermediateCert.SubjectKeyId,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       OIDQuantumPublicKey,
				Critical: false,
				Value:    serializeDilithiumPublicKey(quantumKeyPair.PublicKey),
			},
		},
	}

	// 关键修复：在生成TBS数据前设置所有必要字段
	template.PublicKey = &privKey.PublicKey
	template.Issuer = intermediateCert.Subject // 设置颁发者为第一级中间CA的主题
	template.Version = 3                       // 明确设置版本为3

	// 生成不包含扩展字段的TBS数据用于抗量子签名
	tbsData, err := createTBSDataWithoutExtensions(&template)
	if err != nil {
		return nil, nil, nil, err
	}

	quantumSignature, err := quantumSign(intermediateQuantumKeyPair.PrivateKey, tbsData)
	if err != nil {
		return nil, nil, nil, err
	}

	// 把量子签名放进扩展里
	template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
		Id:       OIDQuantumSignature,
		Critical: false,
		Value:    quantumSignature,
	})

	certDER, err := x509.CreateCertificate(rand.Reader, &template, intermediateCert, &privKey.PublicKey, intermediatePrivKey)
	if err != nil {
		return nil, nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, nil, err
	}

	// 保存证书和密钥
	if err := saveCertificate(cert, "intermediate2"); err != nil {
		return nil, nil, nil, err
	}
	if err := saveRSAPrivateKey(privKey, "intermediate2"); err != nil {
		return nil, nil, nil, err
	}
	if err := savePQPrivateKey(quantumKeyPair, "intermediate2"); err != nil {
		return nil, nil, nil, err
	}

	return privKey, cert, quantumKeyPair, nil
}

// 终端实体证书（由第二级中间 CA 签名）
func generateEndEntityCert(issuingPrivKey *rsa.PrivateKey, issuingCert *x509.Certificate, issuingQuantumKeyPair *QuantumKeyPair) (*rsa.PrivateKey, *x509.Certificate, *QuantumKeyPair, error) {
	// 如果证书已存在，则加载
	if certificateExists("endentity") {
		log.Println("终端实体证书已存在，正在加载...")
		privKey, err := loadRSAPrivateKey("endentity")
		if err != nil {
			return nil, nil, nil, err
		}
		cert, err := loadCertificate("endentity")
		if err != nil {
			return nil, nil, nil, err
		}
		pqPrivKey, err := loadPQPrivateKey("endentity")
		if err != nil {
			return nil, nil, nil, err
		}

		// 从证书扩展中提取抗量子公钥
		pqPubKey, _, err := extractQuantumExtensions(cert)
		if err != nil {
			return nil, nil, nil, err
		}

		return privKey, cert, &QuantumKeyPair{PrivateKey: pqPrivKey, PublicKey: pqPubKey}, nil
	}

	log.Println("生成新的终端实体证书...")
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}

	quantumKeyPair, err := generateQuantumKeyPair()
	if err != nil {
		return nil, nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1000),
		Subject: pkix.Name{
			Organization: []string{"Quantum Secure Corp"},
			Country:      []string{"US"},
			CommonName:   "quantum-secure.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1年有效期
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              []string{"quantum-secure.example.com", "www.quantum-secure.example.com"},
		SubjectKeyId:          generateSubjectKeyId(privKey.PublicKey),
		AuthorityKeyId:        issuingCert.SubjectKeyId,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       OIDQuantumPublicKey,
				Critical: false,
				Value:    serializeDilithiumPublicKey(quantumKeyPair.PublicKey),
			},
		},
	}

	// 关键修复：在生成TBS数据前设置所有必要字段
	template.PublicKey = &privKey.PublicKey
	template.Issuer = issuingCert.Subject // 设置颁发者为第二级中间CA的主题
	template.Version = 3                  // 明确设置版本为3

	// 生成不包含扩展字段的TBS数据用于抗量子签名
	tbsData, err := createTBSDataWithoutExtensions(&template)
	if err != nil {
		return nil, nil, nil, err
	}

	quantumSignature, err := quantumSign(issuingQuantumKeyPair.PrivateKey, tbsData)
	if err != nil {
		return nil, nil, nil, err
	}

	// 把量子签名放进扩展里
	template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
		Id:       OIDQuantumSignature,
		Critical: false,
		Value:    quantumSignature,
	})

	certDER, err := x509.CreateCertificate(rand.Reader, &template, issuingCert, &privKey.PublicKey, issuingPrivKey)
	if err != nil {
		return nil, nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, nil, err
	}

	// 保存证书和密钥
	if err := saveCertificate(cert, "endentity"); err != nil {
		return nil, nil, nil, err
	}
	if err := saveRSAPrivateKey(privKey, "endentity"); err != nil {
		return nil, nil, nil, err
	}
	if err := savePQPrivateKey(quantumKeyPair, "endentity"); err != nil {
		return nil, nil, nil, err
	}

	return privKey, cert, quantumKeyPair, nil
}

// 验证证书签名（先传统再量子）
func verifyCertificateSignatureWithQuantum(cert *x509.Certificate, parent *x509.Certificate) error {
	// 如果是自签名证书（根证书），跳过传统签名验证
	if !isSelfSigned(cert) {
		// 传统 RSA 签名验证
		if err := cert.CheckSignatureFrom(parent); err != nil {
			return fmt.Errorf("传统证书签名验证失败: %v", err)
		}
	}

	// 从父证书提取抗量子公钥
	parentQuantumPublicKey, err := extractQuantumPublicKeyFromParent(parent)
	if err != nil {
		return fmt.Errorf("从父证书提取抗量子公钥失败: %v", err)
	}

	// 从当前证书提取抗量子签名
	quantumSignature, err := extractQuantumSignatureFromCert(cert)
	if err != nil {
		return fmt.Errorf("从当前证书提取抗量子签名失败: %v", err)
	}

	// 关键修复：构建与生成时一致的模板
	verificationTemplate := x509.Certificate{
		Version:      cert.Version,
		SerialNumber: cert.SerialNumber,
		Issuer:       parent.Subject, // 使用父证书的主题作为颁发者
		Subject:      cert.Subject,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		PublicKey:    cert.PublicKey,
	}

	// 如果有原始数据，使用原始数据确保一致性
	if cert.RawIssuer != nil {
		verificationTemplate.RawIssuer = make([]byte, len(cert.RawIssuer))
		copy(verificationTemplate.RawIssuer, cert.RawIssuer)
	}
	if cert.RawSubject != nil {
		verificationTemplate.RawSubject = make([]byte, len(cert.RawSubject))
		copy(verificationTemplate.RawSubject, cert.RawSubject)
	}

	tbsData, err := createTBSDataWithoutExtensions(&verificationTemplate)
	if err != nil {
		return fmt.Errorf("创建TBS数据失败: %v", err)
	}

	if !quantumVerify(parentQuantumPublicKey, tbsData, quantumSignature) {
		return fmt.Errorf("抗量子签名验证失败")
	}
	fmt.Printf("✓ 抗量子签名验证成功: %s 由 %s 正确签名\n", cert.Subject.CommonName, parent.Subject.CommonName)

	if !isSelfSigned(cert) {
		fmt.Printf("✓ 传统证书签名验证成功: %s 由 %s 正确签名\n", cert.Subject.CommonName, parent.Subject.CommonName)
	} else {
		fmt.Printf("✓ 自签名根证书验证成功: %s\n", cert.Subject.CommonName)
	}
	return nil
}

// 从证书提取抗量子签名
func extractQuantumSignatureFromCert(cert *x509.Certificate) ([]byte, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDQuantumSignature) {
			return ext.Value, nil
		}
	}
	return nil, fmt.Errorf("证书中未找到抗量子签名扩展")
}

// 证书链完整性检查
func comprehensiveCertificateCheck(cert *x509.Certificate, expectedCN string) error {
	fmt.Printf("\n=== 检查证书: %s ===\n", cert.Subject.CommonName)
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("证书尚未生效 (生效时间: %s)", cert.NotBefore)
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("证书已过期 (过期时间: %s)", cert.NotAfter)
	}
	fmt.Printf("✓ 有效期检查通过: %s 到 %s\n", cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"))
	if expectedCN != "" && cert.Subject.CommonName != expectedCN {
		return fmt.Errorf("证书主题不匹配: 期望 '%s', 实际 '%s'", expectedCN, cert.Subject.CommonName)
	}
	fmt.Printf("✓ 主题名称检查通过: %s\n", cert.Subject.CommonName)
	if cert.IsCA {
		if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return fmt.Errorf("CA证书必须具有KeyUsageCertSign权限")
		}
		fmt.Printf("✓ CA证书密钥用法检查通过\n")
	} else {
		if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			return fmt.Errorf("终端证书必须具有KeyUsageDigitalSignature权限")
		}
		fmt.Printf("✓ 终端证书密钥用法检查通过\n")
	}
	if !cert.BasicConstraintsValid {
		return fmt.Errorf("基本约束无效")
	}
	fmt.Printf("✓ 基本约束检查通过 (IsCA: %t)\n", cert.IsCA)
	fmt.Printf("✓ 自签名证书: %t\n", isSelfSigned(cert))
	return nil
}

// 验证整条证书链（使用 x509.Verify）并打印链信息
func verifyFullCertificateChain(leafCert *x509.Certificate, intermediates []*x509.Certificate, rootPool *x509.CertPool) error {
	fmt.Println("\n=== 开始证书链验证 ===")
	if err := comprehensiveCertificateCheck(leafCert, "quantum-secure.example.com"); err != nil {
		return err
	}
	for i, intermediate := range intermediates {
		if err := comprehensiveCertificateCheck(intermediate, ""); err != nil {
			return fmt.Errorf("中间证书 %d 检查失败: %v", i+1, err)
		}
	}
	opts := x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CurrentTime:   time.Now(),
	}
	for _, cert := range intermediates {
		opts.Intermediates.AddCert(cert)
	}
	chains, err := leafCert.Verify(opts)
	if err != nil {
		return fmt.Errorf("证书链验证失败: %v", err)
	}
	fmt.Printf("\n✓ 证书链验证成功! 找到 %d 条有效链:\n", len(chains))
	for i, chain := range chains {
		fmt.Printf("链 %d:\n", i+1)
		for j, cert := range chain {
			issuer := "自签名"
			if j > 0 {
				issuer = chain[j-1].Subject.CommonName
			}
			fmt.Printf("  [%d] %s (由 %s 签发)\n", j, cert.Subject.CommonName, issuer)
		}
	}
	return nil
}

// 传统 RSA 签名测试
func testSigning(privKey *rsa.PrivateKey, cert *x509.Certificate) {
	data := []byte("重要的抗量子安全数据")
	hash := sha256.Sum256(data)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hash[:])
	if err != nil {
		panic(err)
	}
	pubKey := cert.PublicKey.(*rsa.PublicKey)
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], signature); err != nil {
		panic("签名验证失败: " + err.Error())
	}
	fmt.Println("✓ 传统RSA签名生成和验证测试成功")
}

// 抗量子签名测试
func testQuantumSigning(quantumKeyPair *QuantumKeyPair) {
	data := []byte("重要的抗量子安全数据")
	signature, err := quantumSign(quantumKeyPair.PrivateKey, data)
	if err != nil {
		panic(fmt.Sprintf("抗量子签名生成失败: %v", err))
	}
	if !quantumVerify(quantumKeyPair.PublicKey, data, signature) {
		panic("抗量子签名验证失败")
	}
	fmt.Println("✓ 抗量子签名生成和验证测试成功")
	fmt.Printf("  签名大小: %d 字节\n", len(signature))
	fmt.Printf("  公钥大小: %d 字节\n", len(quantumKeyPair.PublicKey.Bytes()))
	fmt.Printf("  私钥大小: %d 字节\n", len(quantumKeyPair.PrivateKey.Bytes()))
}

func serializeCertificateChain(certs ...*x509.Certificate) {
	for i, cert := range certs {
		pemData := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		fmt.Printf("证书 %d (%s):\n", i+1, cert.Subject.CommonName)
		fmt.Printf("  序列号: %s\n", cert.SerialNumber)
		fmt.Printf("  SHA256指纹: %x\n", sha256.Sum256(cert.Raw))
		fmt.Printf("  自签名: %t\n", isSelfSigned(cert))
		fmt.Printf("  PEM长度: %d bytes\n\n", len(pemData))
	}
}

// 从文件加载整个证书链
func loadCertificateChain() (*x509.Certificate, *x509.Certificate, *x509.Certificate, *x509.Certificate, error) {
	rootCert, err := loadCertificate("root")
	if err != nil {
		return nil, nil, nil, nil, err
	}

	intermediate1Cert, err := loadCertificate("intermediate1")
	if err != nil {
		return nil, nil, nil, nil, err
	}

	intermediate2Cert, err := loadCertificate("intermediate2")
	if err != nil {
		return nil, nil, nil, nil, err
	}

	endEntityCert, err := loadCertificate("endentity")
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return rootCert, intermediate1Cert, intermediate2Cert, endEntityCert, nil
}

// 仅验证模式：从文件加载证书并进行验证
func verificationMode() error {
	fmt.Println("\n=== 验证模式：从文件加载证书链 ===")

	// 加载证书链
	rootCert, intermediate1Cert, intermediate2Cert, endEntityCert, err := loadCertificateChain()
	if err != nil {
		return fmt.Errorf("加载证书链失败: %v", err)
	}

	fmt.Println("证书链加载成功:")
	fmt.Printf("  - 根CA (自签名): %s\n", rootCert.Subject.CommonName)
	fmt.Printf("  - 第一级中间CA: %s\n", intermediate1Cert.Subject.CommonName)
	fmt.Printf("  - 第二级中间CA: %s\n", intermediate2Cert.Subject.CommonName)
	fmt.Printf("  - 终端实体: %s\n", endEntityCert.Subject.CommonName)

	// 验证各级证书签名
	fmt.Println("\n验证证书签名关系...")

	// 根证书是自签名的，单独处理
	fmt.Printf("根证书自签名验证: %s\n", rootCert.Subject.CommonName)
	if !isSelfSigned(rootCert) {
		return fmt.Errorf("根证书不是自签名证书")
	}
	fmt.Printf("✓ 根证书自签名验证成功\n")

	if err := verifyCertificateSignatureWithQuantum(intermediate1Cert, rootCert); err != nil {
		return err
	}
	if err := verifyCertificateSignatureWithQuantum(intermediate2Cert, intermediate1Cert); err != nil {
		return err
	}
	if err := verifyCertificateSignatureWithQuantum(endEntityCert, intermediate2Cert); err != nil {
		return err
	}

	// 完整的证书链验证
	fmt.Println("\n进行完整的证书链验证...")
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	intermediates := []*x509.Certificate{intermediate1Cert, intermediate2Cert}
	if err := verifyFullCertificateChain(endEntityCert, intermediates, rootPool); err != nil {
		return err
	}

	// 测试签名功能
	fmt.Println("\n测试签名和验证功能...")

	// 加载终端实体私钥
	endPrivKey, err := loadRSAPrivateKey("endentity")
	if err != nil {
		return err
	}
	testSigning(endPrivKey, endEntityCert)

	// 加载终端实体抗量子私钥
	endPQPrivKey, err := loadPQPrivateKey("endentity")
	if err != nil {
		return err
	}

	// 从终端实体证书提取抗量子公钥
	endPQPubKey, _, err := extractQuantumExtensions(endEntityCert)
	if err != nil {
		return err
	}

	testQuantumSigning(&QuantumKeyPair{
		PrivateKey: endPQPrivKey,
		PublicKey:  endPQPubKey,
	})

	return nil
}

// 生成模式：生成新的证书链
func generationMode() error {
	fmt.Println("=== 生成模式：创建新的证书链 ===")
	fmt.Printf("使用 %s\n", dilithiumName)
	fmt.Printf("公钥大小: %d 字节\n", mode2.PublicKeySize)
	fmt.Printf("私钥大小: %d 字节\n", mode2.PrivateKeySize)
	fmt.Printf("签名大小: %d 字节\n\n", mode2.SignatureSize)

	// 1. 生成自签名根CA（包含抗量子密钥对）
	fmt.Println("1. 生成自签名根CA证书...")
	rootPrivKey, rootCert, rootQuantumKeyPair, err := generateRootCA()
	if err != nil {
		return err
	}

	// 2. 生成第一级中间CA
	fmt.Println("2. 生成第一级中间CA证书...")
	intermediatePrivKey, intermediateCert, intermediateQuantumKeyPair, err := generateIntermediateCA(rootPrivKey, rootCert, rootQuantumKeyPair)
	if err != nil {
		return err
	}

	// 3. 生成第二级中间CA
	fmt.Println("3. 生成第二级中间CA证书...")
	issuingPrivKey, issuingCert, issuingQuantumKeyPair, err := generateIntermediateCA2(intermediatePrivKey, intermediateCert, intermediateQuantumKeyPair)
	if err != nil {
		return err
	}

	// 4. 生成终端实体证书
	fmt.Println("4. 生成终端实体证书...")
	endPrivKey, endCert, endQuantumKeyPair, err := generateEndEntityCert(issuingPrivKey, issuingCert, issuingQuantumKeyPair)
	if err != nil {
		return err
	}

	// 5. 验证各级证书签名（包含抗量子验证）
	fmt.Println("\n5. 验证证书签名关系...")

	// 根证书是自签名的，单独处理
	fmt.Printf("根证书自签名验证: %s\n", rootCert.Subject.CommonName)
	if !isSelfSigned(rootCert) {
		return fmt.Errorf("根证书不是自签名证书")
	}
	fmt.Printf("✓ 根证书自签名验证成功\n")

	if err := verifyCertificateSignatureWithQuantum(intermediateCert, rootCert); err != nil {
		return err
	}
	if err := verifyCertificateSignatureWithQuantum(issuingCert, intermediateCert); err != nil {
		return err
	}
	if err := verifyCertificateSignatureWithQuantum(endCert, issuingCert); err != nil {
		return err
	}

	// 6. 构建完整的证书链验证
	fmt.Println("\n6. 进行完整的证书链验证...")
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	intermediates := []*x509.Certificate{intermediateCert, issuingCert}
	if err := verifyFullCertificateChain(endCert, intermediates, rootPool); err != nil {
		return err
	}

	// 7. 演示证书序列化
	fmt.Println("\n7. 证书序列化演示...")
	serializeCertificateChain(rootCert, intermediateCert, issuingCert, endCert)

	// 8. 测试签名功能
	fmt.Println("\n8. 测试签名和验证功能...")
	testSigning(endPrivKey, endCert)
	testQuantumSigning(endQuantumKeyPair)

	return nil
}

func main() {
	//fmt.Println("=== 支持抗量子的PKI证书链管理系统 (自签名根证书) ===")
	//
	//// 确保证书目录存在
	//if err := ensureCertDir(); err != nil {
	//	log.Fatalf("创建证书目录失败: %v", err)
	//}
	//
	//// 检查是否已有证书存在
	//certExists := certificateExists("root") &&
	//	certificateExists("intermediate1") &&
	//	certificateExists("intermediate2") &&
	//	certificateExists("endentity")
	//
	//if certExists {
	//	fmt.Println("检测到已有证书链文件")
	//	fmt.Println("选择模式:")
	//	fmt.Println("1. 验证模式 (使用现有证书)")
	//	fmt.Println("2. 重新生成模式 (覆盖现有证书)")
	//	fmt.Print("请选择 (1/2): ")
	//
	//	var choice string
	//	fmt.Scanln(&choice)
	//
	//	switch choice {
	//	case "1":
	//		if err := verificationMode(); err != nil {
	//			log.Fatalf("验证失败: %v", err)
	//		}
	//	case "2":
	//		if err := generationMode(); err != nil {
	//			log.Fatalf("生成失败: %v", err)
	//		}
	//	default:
	//		fmt.Println("无效选择，使用验证模式")
	//		if err := verificationMode(); err != nil {
	//			log.Fatalf("验证失败: %v", err)
	//		}
	//	}
	//} else {
	//	fmt.Println("未找到现有证书链，进入生成模式")
	//	if err := generationMode(); err != nil {
	//		log.Fatalf("生成失败: %v", err)
	//	}
	//}
	//
	//fmt.Println("\n=== 支持抗量子的PKI证书链构建和验证完成 ===")
	//fmt.Printf("证书文件保存在: %s/\n", certDir)
	//fmt.Println("根证书是自签名证书，可用于建立信任链")

	fmt.Println("=== 开始构建支持抗量子的PKI证书链 ===")
	fmt.Printf("使用 %s\n", dilithiumName)
	fmt.Printf("公钥大小: %d 字节\n", mode2.PublicKeySize)
	fmt.Printf("私钥大小: %d 字节\n", mode2.PrivateKeySize)
	fmt.Printf("签名大小: %d 字节\n\n", mode2.SignatureSize)

	// 1. 生成根CA（包含抗量子密钥对）
	fmt.Println("1. 生成根CA证书...")
	rootPrivKey, rootCert, rootQuantumKeyPair, err := generateRootCA()
	if err != nil {
		panic(err)
	}

	// 2. 生成第一级中间CA
	fmt.Println("2. 生成第一级中间CA证书...")
	intermediatePrivKey, intermediateCert, intermediateQuantumKeyPair, err := generateIntermediateCA(rootPrivKey, rootCert, rootQuantumKeyPair)
	if err != nil {
		panic(err)
	}

	// 3. 生成第二级中间CA
	fmt.Println("3. 生成第二级中间CA证书...")
	issuingPrivKey, issuingCert, issuingQuantumKeyPair, err := generateIntermediateCA2(intermediatePrivKey, intermediateCert, intermediateQuantumKeyPair)
	if err != nil {
		panic(err)
	}

	// 4. 生成终端实体证书
	fmt.Println("4. 生成终端实体证书...")
	endPrivKey, endCert, endQuantumKeyPair, err := generateEndEntityCert(issuingPrivKey, issuingCert, issuingQuantumKeyPair)
	if err != nil {
		panic(err)
	}

	// 5. 检查证书链的抗量子支持
	CheckCertificateChainQuantumSupport(rootCert, intermediateCert, issuingCert, endCert)

	// 6. 验证各级证书签名（包含抗量子验证）
	fmt.Println("\n5. 验证证书签名关系...")
	if err := verifyCertificateSignatureWithQuantum(intermediateCert, rootCert); err != nil {
		panic(err)
	}
	if err := verifyCertificateSignatureWithQuantum(issuingCert, intermediateCert); err != nil {
		panic(err)
	}
	if err := verifyCertificateSignatureWithQuantum(endCert, issuingCert); err != nil {
		panic(err)
	}

	// 7. 构建完整的证书链验证
	fmt.Println("\n6. 进行完整的证书链验证...")
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	intermediates := []*x509.Certificate{intermediateCert, issuingCert}
	if err := verifyFullCertificateChain(endCert, intermediates, rootPool); err != nil {
		panic(err)
	}

	// 8. 演示证书序列化
	fmt.Println("\n7. 证书序列化演示...")
	serializeCertificateChain(rootCert, intermediateCert, issuingCert, endCert)

	// 9. 测试签名功能
	fmt.Println("\n8. 测试签名和验证功能...")
	testSigning(endPrivKey, endCert)
	testQuantumSigning(endQuantumKeyPair)

	// 使用变量避免编译警告
	_ = intermediatePrivKey
	_ = issuingPrivKey
	_ = endPrivKey
	_ = endQuantumKeyPair

	fmt.Println("\n=== 支持抗量子的PKI证书链构建和验证完成 ===")
}
