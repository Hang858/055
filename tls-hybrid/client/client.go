package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

// 错误类型定义
var (
	ErrCertExpired      = errors.New("certificate has expired")
	ErrCertNotYetValid  = errors.New("certificate is not yet valid")
	ErrInvalidCertChain = errors.New("invalid certificate chain")
)

func encrypt(key []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decrypt(key []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func validateCertExpiry(certs []*x509.Certificate) error {
	now := time.Now()
	for _, cert := range certs {
		if now.After(cert.NotAfter) {
			return ErrCertExpired
		}
		if now.Before(cert.NotBefore) {
			return ErrCertNotYetValid
		}
	}
	return nil
}

// supportedKEX 是源码库支持的混合密钥交换组，按量子安全等级标注。
var supportedKEX = []tls.CurveID{
	tls.SM2Kyber512Draft00,     // 128 比特量子安全等级
	tls.X25519Kyber512Draft00,  // 128 比特量子安全等级
	tls.X25519Kyber1024Draft00, // 256 比特量子安全等级
	tls.SM2Kyber1024Draft00,    // 256 比特量子安全等级
	tls.X25519Kyber768Draft00,  // 192 比特
	tls.X25519,                 // 传统算法，用于兼容性回退
}

var kexFlag = flag.String("kex", "", "只启用指定的密钥交换组（默认启用全部）")

// selectKEX 依据 -kex 参数选择启用哪些密钥交换组。
func selectKEX() []tls.CurveID {
	if *kexFlag == "" {
		return supportedKEX
	}
	byName := map[string]tls.CurveID{
		"SM2Kyber512Draft00":     tls.SM2Kyber512Draft00,
		"X25519Kyber512Draft00":  tls.X25519Kyber512Draft00,
		"X25519Kyber1024Draft00": tls.X25519Kyber1024Draft00,
		"SM2Kyber1024Draft00":    tls.SM2Kyber1024Draft00,
		"X25519Kyber768Draft00":  tls.X25519Kyber768Draft00,
		"X25519":                 tls.X25519,
	}
	id, ok := byName[*kexFlag]
	if !ok {
		log.Fatalf("未知密钥交换组 %q；可选：SM2Kyber512Draft00、X25519Kyber512Draft00、X25519Kyber1024Draft00、SM2Kyber1024Draft00、X25519Kyber768Draft00、X25519", *kexFlag)
	}
	return []tls.CurveID{id}
}

func main() {
	flag.Parse()

	caCert, err := ioutil.ReadFile("server.crt")
	if err != nil {
		panic(fmt.Sprintf("读取CA证书失败: %v", err))
	}

	// 2. 创建证书池并添加CA证书
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	start := time.Now()
	config := &tls.Config{
		InsecureSkipVerify: true,
		RootCAs:            caCertPool, // 指定信任的CA证书池
		CurvePreferences:   selectKEX(),
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}

	// 创建带事件监听的上下文
	ctx := context.WithValue(
		context.Background(),
		tls.CFEventHandlerContextKey{},
		func(ev tls.CFEvent) {
			switch e := ev.(type) {
			case tls.CFEventTLS13NegotiatedKEX:
				switch e.KEX {
				case tls.X25519Kyber512Draft00:
					fmt.Println("Used X25519Kyber512Draft00")
				case tls.SM2Kyber512Draft00:
					fmt.Println("Used Kyber512sm2")
				case tls.X25519Kyber768Draft00:
					fmt.Println("Used X25519Kyber768Draft00")
				case tls.X25519Kyber1024Draft00:
					fmt.Println("Used X25519Kyber1024Draft00 (256 比特量子安全等级)")
				case tls.SM2Kyber1024Draft00:
					fmt.Println("Used SM2Kyber1024Draft00 (256 比特量子安全等级)")
				case tls.X25519:
					fmt.Println("Used X25519")
				}
			}
		},
	)

	req, _ := http.NewRequestWithContext(ctx, "GET", "https://localhost:8080", nil)
	resp, err := client.Do(req)

	// 处理网络错误
	if err != nil {
		fmt.Printf("请求失败: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.TLS != nil {
		certs := resp.TLS.PeerCertificates // 获取服务器返回的证书链
		if err := validateCertExpiry(certs); err != nil {
			fmt.Printf("[安全] 证书验证失败: %v\n", err)
			return
		}
	} else {
		fmt.Println("无 TLS 连接信息")
		return
	}

	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// 导出密钥材料
	if resp.TLS == nil {
		fmt.Println("No TLS connection")
		return
	}
	keyMaterial, err := resp.TLS.ExportKeyingMaterial("my_app_key", nil, 32)
	if err != nil {
		fmt.Println("Key export failed:", err)
		return
	}

	// 加密要发送的数据
	plaintext := []byte("Secret client message")
	ciphertext, err := encrypt(keyMaterial, plaintext)
	if err != nil {
		fmt.Println("Encryption failed:", err)
		return
	}

	// 发送加密后的POST请求
	postReq, _ := http.NewRequestWithContext(ctx, "POST", "https://localhost:8080", bytes.NewReader(ciphertext))
	postResp, err := client.Do(postReq)
	if err != nil {
		fmt.Println("POST request failed:", err)
		return
	}
	defer postResp.Body.Close()

	// 读取并解密响应
	encryptedResponse, err := io.ReadAll(postResp.Body)
	if err != nil {
		fmt.Println("Reading response failed:", err)
		return
	}

	decryptedResponse, err := decrypt(keyMaterial, encryptedResponse)
	if err != nil {
		fmt.Println("Decryption failed:", err)
		return
	}

	fmt.Printf("Server response: %s\n", decryptedResponse)

	duration := time.Since(start)
	fmt.Printf("代码执行时间: %v\n", duration)
}
