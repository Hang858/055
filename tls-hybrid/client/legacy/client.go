//package main
//
//import (
//	"context"
//	"crypto/tls"
//	"fmt"
//	"net/http"
//)
//
//func main() {
//	// 创建自定义的 TLS 配置
//	config := &tls.Config{
//		InsecureSkipVerify: true, // 跳过证书验证
//		CurvePreferences: []tls.CurveID{
//			tls.SM2Kyber512Draft00,
//			tls.X25519Kyber768Draft00, // 优先使用混合 KEM
//			tls.X25519,                // 回退到经典 X25519
//		},
//		MinVersion: tls.VersionTLS13, // 强制使用 TLS 1.3
//		MaxVersion: tls.VersionTLS13,
//	}
//	fmt.Println(config.CurvePreferences)
//	// 创建 HTTP 请求，并绑定事件处理器
//	req, err := http.NewRequestWithContext(
//		context.WithValue(
//			context.Background(),
//			tls.CFEventHandlerContextKey{}, // 绑定事件处理器
//			func(ev tls.CFEvent) {
//				switch e := ev.(type) {
//				case tls.CFEventTLS13NegotiatedKEX:
//					// 打印实际使用的密钥交换算法
//					switch e.KEX {
//					case tls.SM2Kyber512Draft00:
//						fmt.Println("Used Kyber768sm2")
//					case tls.X25519Kyber768Draft00:
//						fmt.Println("Used X25519Kyber768Draft00")
//					case tls.X25519:
//						fmt.Println("Used X25519")
//					default:
//						fmt.Printf("Used unknown curve: %d\n", e.KEX)
//					}
//				case tls.CFEventTLS13HRR:
//					fmt.Println("HelloRetryRequest triggered")
//				}
//			},
//		),
//		"GET",
//		"https://localhost:8080", // 服务器地址
//		//"https://pq.cloudflareresearch.com",
//		//"https://www.google.com",
//		nil,
//	)
//	if err != nil {
//		fmt.Println("创建请求失败:", err)
//		return
//	}
//
//	// 创建 HTTP 客户端，并将 config 应用到 Transport
//	client := &http.Client{
//		Transport: &http.Transport{
//			TLSClientConfig: config, // 使用自定义的 TLS 配置
//		},
//	}
//
//	// 发送请求
//	resp, err := client.Do(req)
//	if err != nil {
//		fmt.Println("请求失败:", err)
//		return
//	}
//	defer resp.Body.Close()
//
//	fmt.Println("请求成功，状态码:", resp.StatusCode)
//}

package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"
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

func main() {
	start := time.Now()
	config := &tls.Config{
		InsecureSkipVerify: true,
		CurvePreferences: []tls.CurveID{
			tls.SM2Kyber512Draft00,
			tls.X25519Kyber768Draft00,
			tls.X25519,
		},
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}

	// 创建支持连接复用的HTTP客户端
	transport := &http.Transport{
		TLSClientConfig:     config,
		MaxIdleConns:        1,
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     90 * time.Second,
	}
	client := &http.Client{Transport: transport}

	// 创建带事件监听的上下文
	ctx := context.WithValue(
		context.Background(),
		tls.CFEventHandlerContextKey{},
		func(ev tls.CFEvent) {
			switch e := ev.(type) {
			case tls.CFEventTLS13NegotiatedKEX:
				switch e.KEX {
				case tls.SM2Kyber512Draft00:
					fmt.Println("Used Kyber768sm2")
				case tls.X25519Kyber768Draft00:
					fmt.Println("Used X25519Kyber768Draft00")
				case tls.X25519:
					fmt.Println("Used X25519")
				}
			}
		},
	)

	// 初始请求建立连接
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://localhost:8080", nil)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Initial request failed:", err)
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
