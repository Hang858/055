package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
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

func handler(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil {
		http.Error(w, "Not a TLS connection", http.StatusInternalServerError)
		return
	}

	// 导出32字节密钥材料
	keyMaterial, err := r.TLS.ExportKeyingMaterial("my_app_key", nil, 32)
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

		fmt.Printf("Server received: %s\n", plaintext)

		// 加密响应
		response := []byte("Server response to: " + string(plaintext))
		encryptedResponse, err := encrypt(keyMaterial, response)
		if err != nil {
			http.Error(w, "Encryption failed", http.StatusInternalServerError)
			return
		}

		w.Write(encryptedResponse)
	} else {
		fmt.Fprintf(w, "Hello! Send POST request with encrypted data")
	}
}

// 支持的混合密钥交换组（按量子安全等级标注）
// HQC 组只在带 -tags pq_hqc 构建（并链接 liboqs）时可用。
var supportedKEX = func() []tls.CurveID {
	list := []tls.CurveID{
		tls.SM2Kyber512Draft00,     // 128 比特量子安全等级
		tls.X25519Kyber512Draft00,  // 128 比特量子安全等级
		tls.X25519Kyber1024Draft00, // 256 比特量子安全等级
		tls.SM2Kyber1024Draft00,    // 256 比特量子安全等级
		tls.X25519Kyber768Draft00,  // 192 比特
	}
	if tls.HQCEnabled() {
		list = append(list,
			tls.X25519HQC128, // 128 比特量子安全等级（HQC）
			tls.X25519HQC256, // 256 比特量子安全等级（HQC）
		)
	}
	return append(list, tls.X25519) // 传统算法，用于兼容性回退
}()

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
		// HQC（需 -tags pq_hqc 构建）；后两个别名与测试大纲 X25519HQC1/5 的写法对齐
		"X25519HQC-128": tls.X25519HQC128,
		"X25519HQC-256": tls.X25519HQC256,
		"X25519HQC1":    tls.X25519HQC128,
		"X25519HQC5":    tls.X25519HQC256,
	}
	id, ok := byName[*kexFlag]
	if !ok {
		log.Fatalf("未知密钥交换组 %q；可选：SM2Kyber512Draft00、X25519Kyber512Draft00、X25519Kyber1024Draft00、SM2Kyber1024Draft00、X25519Kyber768Draft00、X25519HQC-128、X25519HQC-256、X25519", *kexFlag)
	}
	if (id == tls.X25519HQC128 || id == tls.X25519HQC256) && !tls.HQCEnabled() {
		log.Fatalf("HQC 组需要带 -tags pq_hqc 构建并链接 liboqs；当前构建不含 HQC")
	}
	return []tls.CurveID{id}
}

func main() {
	flag.Parse()
	log.Printf("启用的密钥交换组: %v", selectKEX())
	config := &tls.Config{
		CurvePreferences: selectKEX(),
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
	}

	http.HandleFunc("/", handler)
	server := &http.Server{
		Addr:      ":8080",
		TLSConfig: config,
	}

	log.Println("Starting HTTPS server on :8080")
	err := server.ListenAndServeTLS("./server_root_cert1.pem", "./server_root_key1.pem")
	if err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
