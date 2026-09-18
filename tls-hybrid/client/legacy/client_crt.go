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
	"fmt"
	"io"
	"net/http"
	"time"
)

// 错误类型定义
var (
	ErrCertExpired      = errors.New("certificate has expired")
	ErrCertNotYetValid  = errors.New("certificate is not yet valid")
	ErrInvalidCertChain = errors.New("invalid certificate chain")
)

// AES-GCM加密函数
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

// AES-GCM解密函数
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
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// 增强的证书验证函数
func verifyServerCert(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	now := time.Now().UTC()
	timeTolerance := 300 * time.Second // 允许5分钟时间偏差

	for _, asn1Data := range rawCerts {
		cert, err := x509.ParseCertificate(asn1Data)
		if err != nil {
			return fmt.Errorf("%w: parse failed", ErrInvalidCertChain)
		}

		// 检查证书生效时间（考虑时间偏差）
		if now.Add(-timeTolerance).Before(cert.NotBefore) {
			return fmt.Errorf("%w: %s (not before %s)",
				ErrCertNotYetValid,
				cert.Subject.CommonName,
				cert.NotBefore.Format(time.RFC3339))
		}

		// 检查证书过期时间（考虑时间偏差）
		if now.Add(timeTolerance).After(cert.NotAfter) {
			return fmt.Errorf("%w: %s (expired at %s)",
				ErrCertExpired,
				cert.Subject.CommonName,
				cert.NotAfter.Format(time.RFC3339))
		}
	}
	return nil
}

func main() {
	// 创建自定义TLS配置
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // 禁用默认验证
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if err := verifyServerCert(rawCerts, verifiedChains); err != nil {
				return err
			}
			return nil
		},
		CurvePreferences: []tls.CurveID{
			tls.SM2Kyber512Draft00,
			tls.X25519Kyber768Draft00,
			tls.X25519,
		},
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}

	// 创建HTTP客户端
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
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
				case tls.SM2Kyber512Draft00:
					fmt.Println("[KEX] 使用SM2Kyber512Draft00")
				case tls.X25519Kyber768Draft00:
					fmt.Println("[KEX] 使用X25519Kyber768Draft00")
				case tls.X25519:
					fmt.Println("[KEX] 使用X25519")
				}
				//case tls.CFEventTLS13HandshakeStatus:
				//	fmt.Printf("[握手] 状态更新: %s\n", e.Status)
			}
		},
	)

	// 第一阶段：建立连接并验证证书
	fmt.Println("=== 阶段1：证书验证 ===")
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://localhost:8080", nil)
	resp, err := client.Do(req)

	// 处理证书错误
	if err != nil {
		switch {
		case errors.Is(err, ErrCertExpired):
			fmt.Println("[安全] 终止连接：检测到过期证书")
		case errors.Is(err, ErrCertNotYetValid):
			fmt.Println("[安全] 终止连接：证书未生效")
		case errors.Is(err, ErrInvalidCertChain):
			fmt.Println("[安全] 终止连接：证书链无效")
		default:
			fmt.Printf("连接失败: %v\n", err)
		}
		return
	}
	defer resp.Body.Close()

	// 第二阶段：导出会话密钥
	fmt.Println("\n=== 阶段2：密钥导出 ===")
	if resp.TLS == nil {
		fmt.Println("错误：未建立TLS连接")
		return
	}

	keyMaterial, err := resp.TLS.ExportKeyingMaterial("APP_SECRET", nil, 32)
	if err != nil {
		fmt.Printf("密钥导出失败: %v\n", err)
		return
	}
	fmt.Printf("导出会话密钥: %x\n", keyMaterial[:16])

	// 第三阶段：加密数据传输
	fmt.Println("\n=== 阶段3：加密通信 ===")
	plaintext := []byte("重要数据: 42")
	ciphertext, err := encrypt(keyMaterial, plaintext)
	if err != nil {
		fmt.Printf("加密失败: %v\n", err)
		return
	}

	// 发送加密数据
	postReq, _ := http.NewRequestWithContext(ctx, "POST", "https://localhost:8080", bytes.NewReader(ciphertext))
	postResp, err := client.Do(postReq)
	if err != nil {
		fmt.Printf("发送数据失败: %v\n", err)
		return
	}
	defer postResp.Body.Close()

	// 处理加密响应
	encryptedResp, err := io.ReadAll(postResp.Body)
	if err != nil {
		fmt.Printf("读取响应失败: %v\n", err)
		return
	}

	decryptedResp, err := decrypt(keyMaterial, encryptedResp)
	if err != nil {
		fmt.Printf("解密失败: %v\n", err)
		return
	}

	fmt.Printf("服务器响应: %s\n", decryptedResp)
}
