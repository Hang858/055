package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
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

// die 打印错误并以非 0 退出：测试脚本按退出码判断握手/校验是否失败。
func die(format string, a ...interface{}) {
	fmt.Printf(format, a...)
	os.Exit(1)
}

// supportedKEX 是源码库支持的混合密钥交换组，按量子安全等级标注。
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

// verifyCert 打开标准证书链校验（InsecureSkipVerify=false）并额外显式检查有效期，
// 用于 TLS-1-9「证书有效性验证」：过期/签名错误的证书应被拒绝。
var verifyCert = flag.Bool("verify", false, "启用证书链校验（默认关闭，便于自测）")

// caFlag 指定信任的 CA 证书文件（默认 server.crt，与历史命令保持一致）。
var caFlag = flag.String("ca", "server.crt", "CA 证书文件（校验服务端证书时使用）")

// addrFlag 指定服务端地址，默认回环地址；跨机测试时传 <服务端IP>:8080。
var addrFlag = flag.String("addr", "localhost:8080", "服务端地址 host:port")

// serverNameFlag 指定 SNI 与证书校验使用的服务端名称。证书 SAN 为 localhost 时，
// 即便通过 IP 连接、打开 -verify，也能按 localhost 校验证书。
var serverNameFlag = flag.String("servername", "localhost", "TLS 校验用服务端名称（SNI）")

// msgFlag / msgHexFlag 指定客户端发送的明文，语义与 e2e 一致。
var msgFlag = flag.String("msg", "Secret client message", "发送的明文（文本）")
var msgHexFlag = flag.String("msg-hex", "", "发送的明文（十六进制，优先于 -msg）")

// kexByName 组名 → CurveID。DummyKex(0xfe33) 是预留给 HelloRetryRequest 测试的
// “服务端不会支持”的组，见 docs/TLS测试-用例执行步骤.md 的 TLS-1-8。
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

const kexHelp = "SM2Kyber512Draft00、X25519Kyber512Draft00、X25519Kyber768Draft00、" +
	"SM2Kyber768Draft00、X25519Kyber1024Draft00、SM2Kyber1024Draft00、" +
	"X25519HQC-128、X25519HQC-256、SM2HQC-128、SM2HQC-256、DummyKex、X25519（可用逗号分隔多个，顺序即偏好）"

// selectKEX 依据 -kex 参数选择启用哪些密钥交换组（支持逗号分隔的多组，顺序即偏好）。
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

	caCert, err := ioutil.ReadFile(*caFlag)
	if err != nil {
		panic(fmt.Sprintf("读取CA证书失败: %v", err))
	}

	// 2. 创建证书池并添加CA证书
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	start := time.Now()
	config := &tls.Config{
		InsecureSkipVerify: !*verifyCert, // -verify 打开标准证书链校验
		RootCAs:            caCertPool,   // 指定信任的CA证书池
		CurvePreferences:   selectKEX(),
		ServerName:         *serverNameFlag,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		KeyLogWriter:       keyLogWriter(), // 设置 SSLKEYLOGFILE 时导出密钥供 Wireshark 解密
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
				case tls.SM2Kyber768Draft00:
					fmt.Println("Used SM2Kyber768Draft00 (192 比特量子安全等级)")
				case tls.X25519Kyber768Draft00:
					fmt.Println("Used X25519Kyber768Draft00")
				case tls.X25519Kyber1024Draft00:
					fmt.Println("Used X25519Kyber1024Draft00 (256 比特量子安全等级)")
				case tls.SM2Kyber1024Draft00:
					fmt.Println("Used SM2Kyber1024Draft00 (256 比特量子安全等级)")
				case tls.X25519HQC128:
					fmt.Println("Used X25519HQC-128 (128 比特量子安全等级)")
				case tls.X25519HQC256:
					fmt.Println("Used X25519HQC-256 (256 比特量子安全等级)")
				case tls.SM2HQC128:
					fmt.Println("Used SM2HQC-128 (128 比特量子安全等级)")
				case tls.SM2HQC256:
					fmt.Println("Used SM2HQC-256 (256 比特量子安全等级)")
				case tls.X25519:
					fmt.Println("Used X25519")
				}
			}
		},
	)

	req, _ := http.NewRequestWithContext(ctx, "GET", "https://"+*addrFlag, nil)
	resp, err := client.Do(req)

	// 处理网络错误
	if err != nil {
		die("请求失败: %v\n", err)
	}
	defer resp.Body.Close()

	if resp.TLS != nil {
		certs := resp.TLS.PeerCertificates // 获取服务器返回的证书链
		if err := validateCertExpiry(certs); err != nil {
			die("[安全] 证书验证失败: %v\n", err)
		}
	} else {
		die("无 TLS 连接信息\n")
	}

	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// 导出密钥材料
	if resp.TLS == nil {
		die("No TLS connection\n")
	}
	keyMaterial, err := resp.TLS.ExportKeyingMaterial("my_app_key", nil, 32)
	if err != nil {
		die("Key export failed: %v\n", err)
	}

	// 加密要发送的数据：-msg-hex 优先（用于二进制数据）
	plaintext := []byte(*msgFlag)
	if *msgHexFlag != "" {
		plaintext, err = hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(*msgHexFlag), " ", ""))
		if err != nil {
			die("-msg-hex 不是合法十六进制: %v\n", err)
		}
	}
	ciphertext, err := encrypt(keyMaterial, plaintext)
	if err != nil {
		die("Encryption failed: %v\n", err)
	}

	// 发送加密后的POST请求
	postReq, _ := http.NewRequestWithContext(ctx, "POST", "https://"+*addrFlag, bytes.NewReader(ciphertext))
	postResp, err := client.Do(postReq)
	if err != nil {
		die("POST request failed: %v\n", err)
	}
	defer postResp.Body.Close()

	// 读取并解密响应
	encryptedResponse, err := io.ReadAll(postResp.Body)
	if err != nil {
		die("Reading response failed: %v\n", err)
	}

	decryptedResponse, err := decrypt(keyMaterial, encryptedResponse)
	if err != nil {
		die("Decryption failed: %v\n", err)
	}

	if *msgHexFlag != "" {
		fmt.Printf("Server response(hex): %x\n", decryptedResponse)
	} else {
		fmt.Printf("Server response: %s\n", decryptedResponse)
	}

	duration := time.Since(start)
	fmt.Printf("代码执行时间: %v\n", duration)
}
