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
	"log"
	"net/http"
	"os"
	"sync" // Import sync for WaitGroup
	"time"
)

// 错误类型定义
var (
	ErrCertExpired      = errors.New("certificate has expired")
	ErrCertNotYetValid  = errors.New("certificate is not yet valid")
	ErrInvalidCertChain = errors.New("invalid certificate chain")
)

// 全局配置
var (
	certFile    string
	keyFile     string
	caCertFile  string
	serverAddr  string
	postMessage string
	showKex     bool
)

func init() {
	flag.StringVar(&certFile, "cert", "/Users/zhaohaitian/Desktop/新近期工作/证书_TLS协议实现/tlsv1/tls/server_client/server_root_cert.pem", "服务器证书文件")
	flag.StringVar(&keyFile, "key", "/Users/zhaohaitian/Desktop/新近期工作/证书_TLS协议实现/tlsv1/tls/server_client/server_root_key.pem", "服务器私钥文件")
	flag.StringVar(&caCertFile, "ca", "/Users/zhaohaitian/Desktop/新近期工作/证书_TLS协议实现/tlsv1/tls/server_client/server_root_cert1.pem", "CA 证书文件 (客户端使用)")
	flag.StringVar(&serverAddr, "addr", "localhost:8080", "服务器地址")
	flag.StringVar(&postMessage, "msg", "Secret quantum-safe message", "客户端发送的消息")
	flag.BoolVar(&showKex, "showkex", true, "显示协商的密钥交换算法")
}

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

func handler(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil {
		http.Error(w, "Not a TLS connection", http.StatusInternalServerError)
		return
	}

	// 导出32字节密钥材料
	keyMaterial, err := r.TLS.ExportKeyingMaterial("quantum_app_key", nil, 32)
	if err != nil {
		http.Error(w, "Failed to export key material", http.StatusInternalServerError)
		return
	}

	if r.Method == http.MethodPost {
		// 读取加密的请求体
		ciphertext, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}

		// 解密数据
		plaintext, err := decrypt(keyMaterial, ciphertext)
		if err != nil {
			http.Error(w, "Decryption failed", http.StatusBadRequest)
			return
		}

		log.Printf("🔒 服务器接收到: %s\n", plaintext)

		// 加密响应
		response := []byte("量子安全响应: " + string(plaintext))
		encryptedResponse, err := encrypt(keyMaterial, response)
		if err != nil {
			http.Error(w, "Encryption failed", http.StatusInternalServerError)
			return
		}

		w.Write(encryptedResponse)
	} else {
		fmt.Fprintf(w, "欢迎使用量子安全通信服务！请发送 POST 请求")
	}
}

func runServer(wg *sync.WaitGroup) {
	defer wg.Done()

	config := &tls.Config{
		CurvePreferences: []tls.CurveID{
			tls.X25519Kyber512Draft00,
			tls.SM2Kyber512Draft00,
			tls.X25519Kyber768Draft00,
			tls.X25519,
		},
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}

	http.HandleFunc("/", handler)
	server := &http.Server{
		Addr:      serverAddr,
		TLSConfig: config,
	}

	log.Printf("🚀 启动量子安全服务器 (TLS 1.3) 在 %s", serverAddr)
	log.Printf("📜 使用证书: %s, 密钥: %s", certFile, keyFile)

	// ListenAndServeTLS blocks, so we run it in a goroutine
	go func() {
		err := server.ListenAndServeTLS(certFile, keyFile)
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("服务器启动失败: %v", err)
		}
	}()

	// Give the server a moment to start
	time.Sleep(500 * time.Millisecond)
}

func runClient(wg *sync.WaitGroup) {
	defer wg.Done()

	start := time.Now()

	// 读取CA证书
	caCert, err := os.ReadFile(caCertFile)
	if err != nil {
		log.Fatalf("读取CA证书失败: %v", err)
	}

	// 创建证书池并添加CA证书
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		log.Fatal("无法添加CA证书到池中")
	}

	config := &tls.Config{
		InsecureSkipVerify: true, // 核心改动：跳过服务器证书验证
		RootCAs:            caCertPool,
		CurvePreferences: []tls.CurveID{
			tls.X25519Kyber512Draft00,
			tls.SM2Kyber512Draft00,
			tls.X25519Kyber768Draft00,
			tls.X25519,
		},
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}

	// 事件处理函数
	eventHandler := func(ev tls.CFEvent) {
		if !showKex {
			return
		}
		switch e := ev.(type) {
		case tls.CFEventTLS13NegotiatedKEX:
			switch e.KEX {
			case tls.X25519Kyber512Draft00:
				log.Println("🔑 使用密钥交换算法: X25519Kyber512Draft00 (混合后量子)")
			case tls.SM2Kyber512Draft00:
				log.Println("🔑 使用密钥交换算法: SM2Kyber512Draft00 (混合后量子)")
			case tls.X25519Kyber768Draft00:
				log.Println("🔑 使用密钥交换算法: X25519Kyber768Draft00 (混合后量子)")
			case tls.X25519:
				log.Println("🔑 使用密钥交换算法: X25519 (传统)")
			}
		}
	}

	// 创建带事件监听的上下文
	ctx := context.WithValue(context.Background(), tls.CFEventHandlerContextKey{}, eventHandler)

	// 初始GET请求建立连接
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://"+serverAddr, nil)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.TLS == nil {
		log.Fatal("无 TLS 连接信息")
	}

	//// 验证证书有效期
	//certs := resp.TLS.PeerCertificates
	//if err := validateCertExpiry(certs); err != nil {
	//	log.Fatalf("[安全] 证书验证失败: %v", err)
	//}

	io.Copy(io.Discard, resp.Body)

	// 导出密钥材料
	keyMaterial, err := resp.TLS.ExportKeyingMaterial("quantum_app_key", nil, 32)
	if err != nil {
		log.Fatalf("密钥导出失败: %v", err)
	}

	// 加密要发送的数据
	plaintext := []byte(postMessage)
	ciphertext, err := encrypt(keyMaterial, plaintext)
	if err != nil {
		log.Fatalf("加密失败: %v", err)
	}

	// 发送加密后的POST请求
	postReq, _ := http.NewRequestWithContext(ctx, "POST", "https://"+serverAddr, bytes.NewReader(ciphertext))
	postResp, err := client.Do(postReq)
	if err != nil {
		log.Fatalf("POST 请求失败: %v", err)
	}
	defer postResp.Body.Close()

	// 读取并解密响应
	encryptedResponse, err := io.ReadAll(postResp.Body)
	if err != nil {
		log.Fatalf("读取响应失败: %v", err)
	}

	decryptedResponse, err := decrypt(keyMaterial, encryptedResponse)
	if err != nil {
		log.Fatalf("解密失败: %v", err)
	}

	log.Printf("📩 服务器响应: %s", decryptedResponse)
	log.Printf("⏱️ 总执行时间: %v", time.Since(start))
}

func main() {
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	var wg sync.WaitGroup
	wg.Add(2) // We have two goroutines: server and client

	// Run the server in a goroutine
	go runServer(&wg)

	// Run the client in a goroutine after a short delay to ensure server is ready
	go func() {
		time.Sleep(1 * time.Second) // Give the server time to fully start up
		runClient(&wg)
	}()

	wg.Wait() // Wait for both server and client to complete
	log.Println("✅ 客户端和服务器交互完成。")
}
