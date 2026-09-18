// server_fixed.go
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
)

// 加载并验证证书
func loadAndVerifyCertificates() error {
	files := []string{
		"pqcerts/root-ca.pem",
		"pqcerts/intermediate1-ca.pem",
		"pqcerts/intermediate2-ca.pem",
		"pqcerts/end-entity.pem",
		"pqcerts/end-entity-key.pem",
	}

	for _, file := range files {
		if _, err := os.Stat(file); err != nil {
			return fmt.Errorf("证书文件不存在: %s", file)
		}

		// 检查文件是否为空
		info, err := os.Stat(file)
		if err != nil {
			return fmt.Errorf("检查文件失败: %s", file)
		}
		if info.Size() == 0 {
			return fmt.Errorf("证书文件为空: %s", file)
		}

		log.Printf("✓ 证书文件正常: %s (%d bytes)", file, info.Size())
	}
	return nil
}

// 创建证书链
func createCertificateChain() ([][]byte, error) {
	// 读取终端实体证书
	endEntityCert, err := os.ReadFile("pqcerts/end-entity.pem")
	if err != nil {
		return nil, fmt.Errorf("读取终端实体证书失败: %v", err)
	}

	// 读取中间证书
	intermediate2Cert, err := os.ReadFile("pqcerts/intermediate2-ca.pem")
	if err != nil {
		return nil, fmt.Errorf("读取中间CA2证书失败: %v", err)
	}

	intermediate1Cert, err := os.ReadFile("pqcerts/intermediate1-ca.pem")
	if err != nil {
		return nil, fmt.Errorf("读取中间CA1证书失败: %v", err)
	}

	// 构建证书链 [终端实体, 中间CA2, 中间CA1]
	var chain [][]byte

	// 解析终端实体证书PEM
	block, _ := pem.Decode(endEntityCert)
	if block == nil {
		return nil, fmt.Errorf("解析终端实体证书PEM失败")
	}
	chain = append(chain, block.Bytes)

	// 解析中间CA2证书PEM
	block, _ = pem.Decode(intermediate2Cert)
	if block == nil {
		return nil, fmt.Errorf("解析中间CA2证书PEM失败")
	}
	chain = append(chain, block.Bytes)

	// 解析中间CA1证书PEM
	block, _ = pem.Decode(intermediate1Cert)
	if block == nil {
		return nil, fmt.Errorf("解析中间CA1证书PEM失败")
	}
	chain = append(chain, block.Bytes)

	return chain, nil
}

// 加载服务器证书
func loadServerCertificate() (tls.Certificate, error) {
	// 直接使用X509KeyPair加载证书和私钥
	cert, err := tls.LoadX509KeyPair("pqcerts/end-entity.pem", "pqcerts/end-entity-key.pem")
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("加载证书对失败: %v", err)
	}

	// 手动构建证书链
	chain, err := createCertificateChain()
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("构建证书链失败: %v", err)
	}

	// 设置证书链
	cert.Certificate = chain

	return cert, nil
}

// 创建TLS配置
func createTLSConfig() (*tls.Config, error) {
	// 首先验证所有证书文件
	if err := loadAndVerifyCertificates(); err != nil {
		return nil, err
	}

	// 加载服务器证书
	cert, err := loadServerCertificate()
	if err != nil {
		return nil, err
	}

	// 创建根证书池
	rootCAPool := x509.NewCertPool()
	rootCABytes, err := os.ReadFile("pqcerts/root-ca.pem")
	if err != nil {
		return nil, fmt.Errorf("读取根CA证书失败: %v", err)
	}

	if !rootCAPool.AppendCertsFromPEM(rootCABytes) {
		return nil, fmt.Errorf("添加根CA到证书池失败")
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.NoClientCert,
		ServerName:   "quantum-secure.example.com",
		RootCAs:      rootCAPool,
		MinVersion:   tls.VersionTLS13,
		ProtocolType: tls.QuantumSupportAKEX,
		//NextProtos:   []string{"pq-HQC-128"},
	}

	return config, nil
}

func startServer() {
	config, err := createTLSConfig()
	if err != nil {
		log.Fatalf("创建TLS配置失败: %v", err)
	}

	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: config,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("收到来自 %s 的请求", r.RemoteAddr)
			w.Write([]byte("Hello from Quantum TLS Server!"))
		}),
	}

	log.Println("服务器启动在 :8443")
	log.Fatal(server.ListenAndServeTLS("", ""))
}

func main() {
	startServer()
}
