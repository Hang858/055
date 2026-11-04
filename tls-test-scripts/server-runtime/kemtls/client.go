package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"os"
	"time"
)

func loadRootCA() (*x509.CertPool, error) {
	rootPEM, err := os.ReadFile("pqcerts/root-ca.pem")
	if err != nil {
		return nil, fmt.Errorf("read root-ca.pem: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(rootPEM) {
		return nil, fmt.Errorf("failed to append root CA")
	}

	return pool, nil
}

// 👈 新增用来加载客户端证书
func loadClientCertificate() (tls.Certificate, error) {
	// ✅ 客户端 leaf 证书
	endEntityCertPEM, err := os.ReadFile("pqcerts/end-entity.pem")
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read end-entity.pem: %w", err)
	}

	// ✅ 客户端证书链的中间证书（按你实际链替换/增减）
	inter1PEM, err := os.ReadFile("pqcerts/intermediate1-ca.pem")
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read intermediate1-ca.pem: %w", err)
	}
	inter2PEM, err := os.ReadFile("pqcerts/intermediate2-ca.pem")
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read intermediate2-ca.pem: %w", err)
	}

	fullChainPEM := append(endEntityCertPEM, inter1PEM...)
	fullChainPEM = append(fullChainPEM, inter2PEM...)

	// ✅ 客户端私钥
	keyPEM, err := os.ReadFile("pqcerts/end-entity-key.pem")
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read end-entity-key.pem: %w", err)
	}

	cert, err := tls.X509KeyPair(fullChainPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("X509KeyPair: %w", err)
	}
	return cert, nil
}

func main() {
	rootCAs, err := loadRootCA()
	if err != nil {
		log.Fatalf("loadRootCA failed: %v", err)
	}

	// 新增用来加载证书
	clientCert, err := loadClientCertificate()
	if err != nil {
		log.Fatalf("loadClientCertificate failed: %v", err)
	}

	tlsConfig := &tls.Config{
		RootCAs: rootCAs,
		// 👇 这里一定要写证书里的域名
		ServerName: "quantum-secure.example.com",
		//ProtocolType:       tls.QuantumSupportKemCert_KEX,
		ProtocolType:       tls.QuantumSupportAKEX,
		ProtocolTypeStrict: 0, // 👈 这里表示是不是强制需要执行这个协议版本

		// 👈 新增 ✅ 关键：客户端证书（发给 server）
		Certificates: []tls.Certificate{clientCert},
	}

	//start := time.Now()
	//// 这里仍然可以连 localhost:8443
	//conn, err = tls.Dial("tcp", "localhost:8443", tlsConfig)
	//if err != nil {
	//	log.Fatalf("tls.Dial failed: %v", err)
	//}
	////defer conn.Close()
	//elapsed := time.Since(start)
	//fmt.Println("执行时间:", elapsed)

	//这里来测试执行100次的时间
	var times []time.Duration
	var total time.Duration
	var min time.Duration = time.Hour // 初始设为非常大
	var max time.Duration

	for i := 0; i < 100; i++ {
		start := time.Now()

		conn, err := tls.Dial("tcp", "localhost:8443", tlsConfig)
		if err != nil {
			log.Fatalf("tls.Dial failed: %v", err)
		}
		conn.Close()

		elapsed := time.Since(start)

		// 保存
		times = append(times, elapsed)
		total += elapsed

		// 统计最短
		if elapsed < min {
			min = elapsed
		}
		// 统计最长
		if elapsed > max {
			max = elapsed
		}
	}

	avg := total / time.Duration(len(times))

	fmt.Println("===============================================")
	fmt.Printf("总次数: %d\n", len(times))
	fmt.Printf("平均耗时: %v\n", avg)
	fmt.Printf("最短耗时: %v\n", min)
	fmt.Printf("最长耗时: %v\n", max)
	fmt.Println("===============================================")

	log.Println("TLS handshake OK, server verified")

	// 这里仍然可以连 localhost:8443
	conn, err := tls.Dial("tcp", "localhost:8443", tlsConfig)
	if err != nil {
		log.Fatalf("tls.Dial failed: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	log.Printf("Negotiated protocol: %s, cipher: %s",
		state.NegotiatedProtocol, tls.CipherSuiteName(state.CipherSuite))
	log.Printf("VerifiedChains length: %d", len(state.VerifiedChains))

	msg := "Hello TLS Server\n"
	if _, err := conn.Write([]byte(msg)); err != nil {
		log.Fatalf("Write failed: %v", err)
	}
	log.Printf("Client sent: %s", msg)

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		log.Fatalf("Read failed: %v", err)
	}
	log.Printf("Client received: %s", string(buf[:n]))
}
