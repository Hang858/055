package main

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tjfoc/gmsm/sm2"
	gmx509 "github.com/tjfoc/gmsm/x509"
)

const (
	outputDir     = "../../certs"
	userLoginName = "admin3"
)

func parseSM2PublicKey(filePath string) (*sm2.PublicKey, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("读取公钥文件失败: %v", err)
	}
	content := string(data)
	pos := strings.Index(content, "[SM2]")
	if pos == -1 {
		return nil, fmt.Errorf("未找到 [SM2] 段")
	}
	section := content[pos:]
	if end := strings.Index(section[1:], "["); end != -1 {
		section = section[:end+1]
	}

	var xHex, yHex string
	for _, line := range strings.Split(section, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "X=") {
			xHex = strings.TrimPrefix(line, "X=")
		}
		if strings.HasPrefix(line, "Y=") {
			yHex = strings.TrimPrefix(line, "Y=")
		}
	}
	if xHex == "" || yHex == "" {
		return nil, fmt.Errorf("[SM2] 段中未找到 X 或 Y")
	}

	x := new(big.Int)
	y := new(big.Int)
	x.SetString(xHex, 16)
	y.SetString(yHex, 16)
	return &sm2.PublicKey{Curve: sm2.P256Sm2(), X: x, Y: y}, nil
}

func genSerial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	return n
}

func genSM2Key() *sm2.PrivateKey {
	sk, _ := sm2.GenerateKey(rand.Reader)
	return sk
}

func savePEM(filename, blockType string, der []byte) {
	path := filepath.Join(outputDir, filename)
	os.MkdirAll(outputDir, 0755)
	_ = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0644)
	fmt.Printf("✅ 已保存: %s\n", path)
}

func saveSM2Key(sk *sm2.PrivateKey, filename string) {
	der, _ := gmx509.MarshalSm2UnecryptedPrivateKey(sk)
	savePEM(filename, "PRIVATE KEY", der)
}

func main() {
	fmt.Println("==============================================")
	fmt.Println("  国密 SM2 证书链：Root（自签名）→ User")
	fmt.Println("==============================================")

	// ─── 1. 导入外部 SM2 用户公钥 ───
	userPub, err := parseSM2PublicKey("../../public_keys.txt")
	if err != nil {
		panic(err)
	}
	fmt.Printf("\n✅ 导入外部 SM2 用户公钥\n")
	fmt.Printf("   X = %064x\n   Y = %064x\n", userPub.X, userPub.Y)

	// ─── 2. Root CA 自签名证书 ───
	rootSK := genSM2Key()
	rootTpl := &gmx509.Certificate{
		Version:               3,
		SerialNumber:          genSerial(),
		Subject:               pkix.Name{CommonName: "SM2-Root-CA"},
		Issuer:                pkix.Name{CommonName: "SM2-Root-CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(20 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              gmx509.KeyUsageCertSign | gmx509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		SignatureAlgorithm:    gmx509.SM2WithSM3,
	}
	rootDER, err := gmx509.CreateCertificate(rootTpl, rootTpl, &rootSK.PublicKey, rootSK)
	if err != nil {
		panic(fmt.Sprintf("生成 Root 证书失败: %v", err))
	}
	rootCert, _ := gmx509.ParseCertificate(rootDER)

	savePEM("sm2_root.pem", "CERTIFICATE", rootDER)
	fmt.Printf("\n── SM2 Root CA 证书 ──\n")
	fmt.Printf("  CN: %s | 自签名 | CA: %t\n", rootCert.Subject.CommonName, rootCert.IsCA)
	fmt.Printf("  Valid: %s → %s\n",
		rootCert.NotBefore.Format("2006-01-02"), rootCert.NotAfter.Format("2006-01-02"))

	// ─── 3. 用户证书（外部公钥，Root 签发，只给证书） ───
	userTpl := &gmx509.Certificate{
		Version:               3,
		SerialNumber:          genSerial(),
		Subject:               pkix.Name{CommonName: userLoginName},
		Issuer:                rootCert.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * 365 * 24 * time.Hour),
		IsCA:                  false,
		KeyUsage:              gmx509.KeyUsageDigitalSignature | gmx509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    gmx509.SM2WithSM3,
	}
	userDER, err := gmx509.CreateCertificate(userTpl, rootCert, userPub, rootSK)
	if err != nil {
		panic(fmt.Sprintf("生成用户证书失败: %v", err))
	}
	userCert, _ := gmx509.ParseCertificate(userDER)

	savePEM("sm2_user.pem", "CERTIFICATE", userDER)
	fmt.Println("ℹ️  用户私钥在对接方手中，不导出")
	fmt.Printf("\n── SM2 用户证书 ──\n")
	fmt.Printf("  CN: %s | Issuer: %s | CA: %t\n",
		userCert.Subject.CommonName, userCert.Issuer.CommonName, userCert.IsCA)

	// ─── 4. 验证 ───
	fmt.Println("\n==============================================")
	fmt.Println("  🔍 证书链验证")
	fmt.Println("==============================================")
	fmt.Printf("  Root 自签名:       %v\n", rootCert.CheckSignatureFrom(rootCert))
	fmt.Printf("  User 由 Root 签发:  %v\n", userCert.CheckSignatureFrom(rootCert))
	fmt.Println("\n🎉 SM2 证书链完成！")
}
