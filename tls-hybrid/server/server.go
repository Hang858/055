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
	"os"
	"strings"
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
			tls.SM2HQC128,    // 128 比特量子安全等级（SM2 + HQC）
			tls.SM2HQC256,    // 256 比特量子安全等级（SM2 + HQC）
		)
	}
	return append(list, tls.X25519) // 传统算法，用于兼容性回退
}()

var kexFlag = flag.String("kex", "", "启用的密钥交换组，可用逗号分隔多个（默认启用全部）")

// certFlag / keyFlag 指定服务端证书与私钥；默认值保持历史行为（当前目录下的两个文件），
// 这样既可以在 tls-hybrid/server 目录直接启动，也可以从项目根目录用相对路径启动：
//
//	.build/server -cert .build/certs/server_root_cert1.pem -key .build/certs/server_root_key1.pem
var certFlag = flag.String("cert", "./server_root_cert1.pem", "服务端证书文件")
var keyFlag = flag.String("key", "./server_root_key1.pem", "服务端私钥文件")

// kexByName 组名 → CurveID。DummyKex(0xfe33) 是预留给 HelloRetryRequest 测试的
// “服务端不会支持”的组：客户端把它放在首位、同时 supported_groups 里保留 X25519，
// 即可让服务端回 HRR（见 docs/TLS测试-用例执行步骤.md 的 TLS-1-8）。
var kexByName = map[string]tls.CurveID{
	"SM2Kyber512Draft00":     tls.SM2Kyber512Draft00,
	"SM2Kyber768Draft00":     tls.SM2Kyber768Draft00,
	"SM2Kyber1024Draft00":    tls.SM2Kyber1024Draft00,
	"X25519Kyber512Draft00":  tls.X25519Kyber512Draft00,
	"X25519Kyber768Draft00":  tls.X25519Kyber768Draft00,
	"X25519Kyber1024Draft00": tls.X25519Kyber1024Draft00,
	"X25519":                 tls.X25519,
	"DummyKex":               tls.DummyKex,
	// HQC（需 -tags pq_hqc 构建）；后两个别名与测试大纲 X25519HQC1/5 的写法对齐
	"X25519HQC-128": tls.X25519HQC128,
	"X25519HQC-256": tls.X25519HQC256,
	"X25519HQC1":    tls.X25519HQC128,
	"X25519HQC5":    tls.X25519HQC256,
	// SM2 + HQC（同样需 -tags pq_hqc 构建）
	"SM2HQC-128": tls.SM2HQC128,
	"SM2HQC-256": tls.SM2HQC256,
	"SM2HQC1":    tls.SM2HQC128,
	"SM2HQC5":    tls.SM2HQC256, "X25519HQC1Draft00": tls.X25519HQC128,
	"X25519HQC5Draft00": tls.X25519HQC256,
	"SM2HQC1Draft00":    tls.SM2HQC128,
	"SM2HQC5Draft00":    tls.SM2HQC256,
}

// kexDisplayName 用于日志展示（别名统一取正式名）。
var kexDisplayName = map[tls.CurveID]string{
	tls.SM2Kyber512Draft00:     "SM2Kyber512Draft00",
	tls.SM2Kyber768Draft00:     "SM2Kyber768Draft00",
	tls.SM2Kyber1024Draft00:    "SM2Kyber1024Draft00",
	tls.X25519Kyber512Draft00:  "X25519Kyber512Draft00",
	tls.X25519Kyber768Draft00:  "X25519Kyber768Draft00",
	tls.X25519Kyber1024Draft00: "X25519Kyber1024Draft00",
	tls.X25519HQC128:           "X25519HQC-128",
	tls.X25519HQC256:           "X25519HQC-256",
	tls.SM2HQC128:              "SM2HQC-128",
	tls.SM2HQC256:              "SM2HQC-256",
	tls.DummyKex:               "DummyKex",
	tls.X25519:                 "X25519",
}

const kexHelp = "SM2Kyber512Draft00、X25519Kyber512Draft00、X25519Kyber768Draft00、" +
	"SM2Kyber768Draft00、X25519Kyber1024Draft00、SM2Kyber1024Draft00、" +
	"X25519HQC-128、X25519HQC-256、SM2HQC-128、SM2HQC-256、DummyKex、X25519（可用逗号分隔多个，顺序即偏好）"

// selectKEX 依据 -kex 参数选择启用哪些密钥交换组（支持逗号分隔的多组）。
func selectKEX() []tls.CurveID {
	if *kexFlag == "" {
		return supportedKEX
	}
	var out []tls.CurveID
	for _, name := range strings.Split(*kexFlag, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		id, ok := kexByName[name]
		if !ok {
			log.Fatalf("未知密钥交换组 %q；可选：%s", name, kexHelp)
		}
		if (id == tls.X25519HQC128 || id == tls.X25519HQC256 || id == tls.SM2HQC128 || id == tls.SM2HQC256) && !tls.HQCEnabled() {
			log.Fatalf("HQC 组需要带 -tags pq_hqc 构建并链接 liboqs；当前构建不含 HQC")
		}
		out = append(out, id)
	}
	if len(out) == 0 {
		log.Fatalf("-kex 未指定有效的密钥交换组")
	}
	return out
}

// kexNames 把 CurveID 列表转成可读名称，用于启动日志。
func kexNames(ids []tls.CurveID) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if n, ok := kexDisplayName[id]; ok {
			out = append(out, n)
		} else {
			out = append(out, fmt.Sprintf("CurveID(%d)", uint16(id)))
		}
	}
	return out
}

// keyLogWriter 在设置了环境变量 SSLKEYLOGFILE 时，把 TLS 会话密钥追加写入该文件，
// 便于用 Wireshark 解密抓包：Wireshark → 首选项 → Protocols → TLS →
// (Pre)-Master-Secret log filename 选择该文件。仅供测试使用。
func keyLogWriter() io.Writer {
	path := os.Getenv("SSLKEYLOGFILE")
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		log.Printf("无法打开 SSLKEYLOGFILE=%s: %v", path, err)
		return nil
	}
	return f
}

func main() {
	flag.Parse()
	log.Printf("启用的密钥交换组: %v", kexNames(selectKEX()))
	config := &tls.Config{
		CurvePreferences: selectKEX(),
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		KeyLogWriter:     keyLogWriter(), // 设置 SSLKEYLOGFILE 时导出密钥供 Wireshark 解密
	}

	http.HandleFunc("/", handler)
	server := &http.Server{
		Addr:      ":8080",
		TLSConfig: config,
	}

	log.Println("Starting HTTPS server on :8080")
	err := server.ListenAndServeTLS(*certFlag, *keyFlag)
	if err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
