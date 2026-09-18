// client_fixed.go
package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

// 验证证书文件
func verifyCertificateFiles() error {
	files := []string{
		"pqcerts/root-ca.pem",
		"pqcerts/intermediate1-ca.pem",
		"pqcerts/intermediate2-ca.pem",
	}

	for _, file := range files {
		if _, err := os.Stat(file); err != nil {
			return fmt.Errorf("证书文件不存在: %s", file)
		}

		info, err := os.Stat(file)
		if err != nil {
			return fmt.Errorf("检查文件失败: %s", file)
		}
		if info.Size() == 0 {
			return fmt.Errorf("证书文件为空: %s", file)
		}

		log.Printf("✓ 证书文件正常: %s", file)
	}
	return nil
}

// 创建客户端TLS配置
func createTLSConfig() (*tls.Config, error) {
	// 验证证书文件
	if err := verifyCertificateFiles(); err != nil {
		return nil, err
	}

	// 创建证书池
	certPool := x509.NewCertPool()

	// 加载根证书
	rootCA, err := os.ReadFile("pqcerts/root-ca.pem")
	if err != nil {
		return nil, fmt.Errorf("读取根CA失败: %v", err)
	}
	if !certPool.AppendCertsFromPEM(rootCA) {
		return nil, fmt.Errorf("添加根CA到证书池失败")
	}

	// 加载中间证书
	intermediate1, err := os.ReadFile("pqcerts/intermediate1-ca.pem")
	if err != nil {
		return nil, fmt.Errorf("读取中间CA1失败: %v", err)
	}
	if !certPool.AppendCertsFromPEM(intermediate1) {
		return nil, fmt.Errorf("添加中间CA1到证书池失败")
	}

	intermediate2, err := os.ReadFile("pqcerts/intermediate2-ca.pem")
	if err != nil {
		return nil, fmt.Errorf("读取中间CA2失败: %v", err)
	}
	if !certPool.AppendCertsFromPEM(intermediate2) {
		return nil, fmt.Errorf("添加中间CA2到证书池失败")
	}

	config := &tls.Config{
		RootCAs:            certPool,
		ServerName:         "quantum-secure.example.com",
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS13,
		ProtocolType:       tls.QuantumSupportAKEX,
		//NextProtos:         []string{"pq-HQC-128"},
	}

	return config, nil
}

// 测试连接
func testConnection() error {
	config, err := createTLSConfig()
	if err != nil {
		return err
	}

	// 测试TLS连接
	conn, err := tls.Dial("tcp", "localhost:8443", config)
	if err != nil {
		return fmt.Errorf("TLS连接失败: %v", err)
	}
	defer conn.Close()

	// 检查连接状态
	state := conn.ConnectionState()
	log.Printf("TLS版本: %x", state.Version)
	log.Printf("密码套件: %x", state.CipherSuite)

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		log.Printf("服务器证书主题: %s", cert.Subject.CommonName)
		log.Printf("服务器证书颁发者: %s", cert.Issuer.CommonName)
	}

	log.Println("✓ TLS握手成功")
	return nil
}

func runClient() {
	log.Println("启动客户端...")

	// 首先测试TLS连接
	log.Println("测试TLS连接...")
	if err := testConnection(); err != nil {
		log.Fatalf("TLS连接测试失败: %v", err)
	}

	// 创建HTTP客户端
	config, err := createTLSConfig()
	if err != nil {
		log.Fatalf("创建TLS配置失败: %v", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
		Timeout: 10 * time.Second,
	}

	// 发送HTTPS请求
	log.Println("发送HTTPS请求...")
	resp, err := client.Get("https://localhost:8443/")
	if err != nil {
		log.Fatalf("HTTP请求失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("读取响应失败: %v", err)
	}

	log.Printf("响应状态: %d", resp.StatusCode)
	log.Printf("响应内容: %s", string(body))
}

func main() {
	runClient()
}
